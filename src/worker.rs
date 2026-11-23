//! A worker: a fork of the dispatcher that evaluates filters for the service, one at a time, over
//! its own socket.
//!
//! All limits are enforced by the kernel on the worker process, so a filter cannot opt out of
//! them, and the way the worker dies tells the service which limit it was:
//!
//! | limit    | mechanism                                         | worker ends with |
//! |----------|---------------------------------------------------|------------------|
//! | CPU time | CPU-time timer armed around each evaluation       | `SIGXCPU`        |
//! | memory   | `RLIMIT_DATA`; the failed allocation aborts       | `SIGABRT`        |
//! | stack    | `RLIMIT_STACK`; the guard page faults             | `SIGSEGV`        |
//!
//! The wall-clock limit is the service's: it stops waiting and has the dispatcher kill the worker.

use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    panic,
};

use jaq_json::Val;
use nix::{
    sys::{
        prctl,
        resource::{Resource, setrlimit},
        signal::{SigEvent, SigHandler, SigevNotify, Signal, signal},
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
    wire::{Kind, Reply, Request},
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

/// The worker's whole life. `control` is the dispatcher's control socket, which this copy of the
/// process must not keep open.
pub fn run(
    socket: OwnedFd,
    control: &OwnedFd,
    dispatcher: Pid,
    config: &Config,
    data_limit: u64,
) -> ! {
    let Ok(timer) = set_up(control, dispatcher, config, data_limit) else {
        exit(EXIT_SETUP_FAILED);
    };
    // Ends when the service closes its end of the socket.
    let _ = serve(UnixStream::from(socket), timer, config);
    exit(0)
}

fn set_up(
    control: &OwnedFd,
    dispatcher: Pid,
    config: &Config,
    data_limit: u64,
) -> io::Result<Timer> {
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
    Ok(timer)
}

fn serve(stream: UnixStream, mut timer: Timer, config: &Config) -> io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut cache = FilterCache::default();
    let cpu_time = Expiration::OneShot(TimeSpec::from_duration(config.cpu_time));
    // A zero expiration disarms the timer.
    let disarmed = Expiration::OneShot(TimeSpec::new(0, 0));

    loop {
        let request = Request::read(&mut reader, config)?;
        timer.set(cpu_time, TimerSetTimeFlags::empty())?;
        let reply = handle(&mut cache, request);
        timer.set(disarmed, TimerSetTimeFlags::empty())?;
        (&stream).write_all(&reply.encode())?;
    }
}

fn handle(cache: &mut FilterCache, request: Request) -> Reply {
    let Request {
        kind,
        filter,
        input,
    } = request;
    let result = cache.with(filter, |filter| match kind {
        Kind::Check => Reply::Valid,
        Kind::Evaluate => match serde_json::from_slice::<serde_json::Value>(&input) {
            Ok(input) => Reply::Matched(jq::matches(filter, Val::from(input))),
            Err(error) => Reply::InvalidInput(error.to_string()),
        },
    });
    result.unwrap_or_else(Reply::InvalidFilter)
}

/// Compiled filters this worker has seen, by source.
///
/// Compiling takes around a hundred times longer than running a typical filter, because every
/// compilation processes jq's whole prelude, and the service evaluates the same few filters over
/// and over.
///
/// The cache lives inside the worker's memory limit, so it has to stay small next to it. A
/// compiled filter holds roughly 110 kB plus 140 bytes per byte of source; the two bounds below
/// keep the cache under about 6 MB.
#[derive(Default)]
struct FilterCache {
    filters: HashMap<String, jq::Filter>,
    source_len: usize,
}

impl FilterCache {
    const MAX_FILTERS: usize = 32;
    /// Total source length of the cached filters. A single filter longer than this is compiled
    /// for each evaluation.
    const MAX_SOURCE_LEN: usize = 16 << 10;

    /// Calls `f` with the compiled `code`, compiling it if needed. Fails with the compiler's
    /// message if `code` is not a valid filter.
    fn with<R>(&mut self, code: String, f: impl FnOnce(&jq::Filter) -> R) -> Result<R, String> {
        if let Some(filter) = self.filters.get(&code) {
            return Ok(f(filter));
        }

        let filter = jq::compile(&code)?;
        if code.len() > Self::MAX_SOURCE_LEN {
            return Ok(f(&filter));
        }
        if self.filters.len() >= Self::MAX_FILTERS
            || self.source_len + code.len() > Self::MAX_SOURCE_LEN
        {
            self.filters.clear();
            self.source_len = 0;
        }
        self.source_len += code.len();
        Ok(f(self.filters.entry(code).or_insert(filter)))
    }
}
