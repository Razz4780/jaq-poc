//! A worker: a fork of the dispatcher that evaluates filters for the service, one at a time, over
//! its own socket.
//!
//! All limits are enforced by the kernel on the worker process, so a filter cannot opt out of
//! them, and the way the worker dies tells the service which limit it was:
//!
//! | limit    | mechanism                                         | worker ends with |
//! |----------|---------------------------------------------------|------------------|
//! | CPU time | CPU-time timer armed around each filter           | `SIGXCPU`        |
//! | memory   | `RLIMIT_DATA`; the failed allocation aborts       | `SIGABRT`        |
//! | stack    | `RLIMIT_STACK`; the guard page faults             | `SIGSEGV`        |
//!
//! The wall-clock limit is the service's: it stops waiting and has the dispatcher kill the worker.

use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Write},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    panic,
    rc::Rc,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::{
        prctl,
        resource::{Resource, setrlimit},
        signal::{SigEvent, SigHandler, SigevNotify, Signal, signal},
        socket::{MsgFlags, recv},
        time::TimeSpec,
        timer::{Expiration, Timer, TimerSetTimeFlags},
    },
    time::ClockId,
    unistd::{Pid, close, dup2_stderr, dup2_stdin, dup2_stdout, getppid},
};

use crate::{
    Config,
    dispatcher::exit,
    jq,
    shm::{ArenaView, Mapping, PAGE_LEN, Progress, verdict},
    value::{DocRef, Document, Value},
    wire::{InputAt, Reply, Request, RequestBuffers},
};

/// Signal of the CPU-time timer.
pub const CPU_TIME_SIGNAL: Signal = Signal::SIGXCPU;
/// Signal a worker dies with when an allocation fails: the Rust runtime aborts.
pub const MEMORY_SIGNAL: Signal = Signal::SIGABRT;
/// Signal a worker dies with when it runs off its stack.
pub const STACK_SIGNAL: Signal = Signal::SIGSEGV;

/// Exit code of a worker that could not apply its limits and therefore refused to serve.
const EXIT_SETUP_FAILED: i32 = 70;
/// Exit code of a worker in which jaq panicked.
const EXIT_PANICKED: i32 = 71;
/// Exit code of a worker in which a value of the input outlived its evaluation, which jaq never
/// lets happen. The input's slot in the arena may be reused once the worker replies, so a worker
/// that still holds a view of it must not go on.
const EXIT_INPUT_RETAINED: i32 = 72;

/// The worker's whole life. `control` is the dispatcher's control socket, which this copy of the
/// process must not keep open.
pub struct Setup<'a> {
    pub socket: OwnedFd,
    /// The worker's progress page.
    pub progress: OwnedFd,
    /// The dispatcher's control socket, which this copy of the process must not keep open.
    pub control: &'a OwnedFd,
    pub dispatcher: Pid,
    pub config: &'a Config,
    pub data_limit: u64,
    pub arena: &'a ArenaView,
}

/// The worker's whole life.
pub fn run(setup: Setup<'_>) -> ! {
    let Setup {
        socket,
        progress,
        control,
        dispatcher,
        config,
        data_limit,
        arena,
    } = setup;
    let Ok((timer, progress)) = set_up(progress, control, dispatcher, config, data_limit) else {
        exit(EXIT_SETUP_FAILED);
    };
    // Ends when the service closes its end of the socket.
    let _ = serve(UnixStream::from(socket), timer, config, arena, &progress);
    exit(0)
}

fn set_up(
    progress: OwnedFd,
    control: &OwnedFd,
    dispatcher: Pid,
    config: &Config,
    data_limit: u64,
) -> io::Result<(Timer, Progress)> {
    close(control.as_raw_fd())?;

    // The dispatcher normally kills its workers before it exits. This covers a dispatcher that
    // dies without the chance to.
    prctl::set_pdeathsig(Signal::SIGKILL)?;
    if getppid() != dispatcher {
        exit(0);
    }

    // A worker holds nothing of the service's: not its environment, which jq's `env` would
    // otherwise expose to the filter, and not its output streams.
    //
    // Safety: the worker has a single thread, so nothing reads the environment concurrently.
    unsafe { nix::env::clearenv() }.map_err(io::Error::other)?;
    let null = File::options().read(true).write(true).open("/dev/null")?;
    dup2_stdin(&null)?;
    dup2_stdout(&null)?;
    dup2_stderr(&null)?;
    drop(null);

    // Mapped before the limits below, after which the worker holds no descriptor but its socket.
    let progress = Progress::new(Mapping::new(progress.as_fd(), PAGE_LEN, true)?)?;

    setrlimit(Resource::RLIMIT_DATA, data_limit, data_limit)?;
    // The worker runs on the stack of the dispatcher's only thread, which the kernel grows on
    // demand up to this limit. Stack is not charged to `RLIMIT_DATA`, so without its own limit
    // (it can be "unlimited" in a container) runaway recursion would be bounded by nothing.
    setrlimit(Resource::RLIMIT_STACK, config.stack, config.stack)?;
    // Nothing below opens a file, creates one, starts a process or should leave a core dump.
    setrlimit(Resource::RLIMIT_NOFILE, 0, 0)?;
    setrlimit(Resource::RLIMIT_FSIZE, 0, 0)?;
    setrlimit(Resource::RLIMIT_NPROC, 0, 0)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0)?;

    // The Rust runtime catches the guard-page fault of a stack overflow to print a message, and
    // then aborts. With the default action restored the worker dies of `SIGSEGV` itself, which
    // keeps running off the stack distinguishable from running out of memory.
    //
    // Safety: restoring the default action installs no handler.
    unsafe { signal(STACK_SIGNAL, SigHandler::SigDfl) }?;

    // jaq does not panic on valid use. If it does anyway, die with a code of its own instead of
    // unwinding or aborting, so the death is not mistaken for a limit.
    panic::set_hook(Box::new(|_| exit(EXIT_PANICKED)));

    // Counts CPU time of this process only, and the worker has one thread: the time measured is
    // the time spent on the evaluation.
    let timer = Timer::new(
        ClockId::CLOCK_PROCESS_CPUTIME_ID,
        SigEvent::new(SigevNotify::SigevSignal {
            signal: CPU_TIME_SIGNAL,
            si_value: 0,
        }),
    )?;
    Ok((timer, progress))
}

fn serve(
    stream: UnixStream,
    mut timer: Timer,
    config: &Config,
    arena: &ArenaView,
    progress: &Progress,
) -> io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut buffers = RequestBuffers::default();
    let mut cache = HashMap::new();
    let cpu_time = Expiration::OneShot(TimeSpec::from_duration(config.cpu_time));
    // A zero expiration disarms the timer.
    let disarmed = Expiration::OneShot(TimeSpec::new(0, 0));

    loop {
        if reader.buffer().is_empty() {
            spin_for_request(&stream, config.spin);
        }
        let reply = match buffers.read(&mut reader, config)? {
            Request::Check { id, source } => {
                timer.set(cpu_time, TimerSetTimeFlags::empty())?;
                let compiled = jq::compile(source);
                timer.set(disarmed, TimerSetTimeFlags::empty())?;
                match compiled {
                    Ok(filter) => {
                        if id != 0 {
                            cache.insert(id, filter);
                        }
                        Reply::Valid
                    }
                    Err(message) => Reply::InvalidFilter(message),
                }
            }
            Request::Evaluate {
                input,
                inline,
                forget,
                filters,
            } => {
                for id in forget {
                    cache.remove(id);
                }
                let doc: Document = match input {
                    // Safety: the service keeps the slot alive and unwritten until this request
                    // is answered, and `doc` is dropped before that, which is checked below.
                    InputAt::Arena { offset, len } => match unsafe { arena.input(offset, len) } {
                        Some(input) => Rc::new(input),
                        None => return Err(io::ErrorKind::InvalidData.into()),
                    },
                    InputAt::Inline { .. } => Rc::new(std::mem::take(inline)),
                };

                for (index, (id, source)) in filters.iter().enumerate() {
                    progress.start(index);
                    // Each filter gets the whole budget, compiling it included.
                    timer.set(cpu_time, TimerSetTimeFlags::empty())?;
                    let verdict = evaluate(&mut cache, *id, source, &doc);
                    progress.set_verdict(index, verdict);
                }
                timer.set(disarmed, TimerSetTimeFlags::empty())?;

                if Rc::strong_count(&doc) != 1 {
                    exit(EXIT_INPUT_RETAINED);
                }
                Reply::Evaluated
            }
        };
        (&stream).write_all(&reply.encode())?;
    }
}

/// Polls the socket for up to `spin` before the worker goes to sleep in a blocking read, see
/// [`Config::spin`].
fn spin_for_request(stream: &UnixStream, spin: Duration) {
    if spin.is_zero() {
        return;
    }
    let started = Instant::now();
    let mut byte = [0];
    while started.elapsed() < spin {
        // Anything but "nothing to read yet" ends the wait: a request, the service closing the
        // socket, or an error, which the blocking read then reports.
        match recv(
            stream.as_raw_fd(),
            &mut byte,
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK,
        ) {
            Err(Errno::EAGAIN) => std::hint::spin_loop(),
            _ => return,
        }
    }
}

/// Runs one filter of a batch, compiling it first if it comes with its source.
fn evaluate(cache: &mut HashMap<u64, jq::Filter>, id: u64, source: &str, doc: &Document) -> u8 {
    if !source.is_empty() {
        match jq::compile(source) {
            Ok(filter) => {
                cache.insert(id, filter);
            }
            Err(_) => return verdict::INVALID_FILTER,
        }
    }
    match cache.get(&id) {
        Some(filter) if jq::matches(filter, Value::Doc(DocRef::root(doc.clone()))) => verdict::TRUE,
        Some(_) => verdict::FALSE,
        // The service only sends an id alone to a worker it sent the source to before.
        None => verdict::INVALID_FILTER,
    }
}
