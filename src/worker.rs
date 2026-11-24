//! A worker: a child of the trampoline that evaluates filters for the service, one request at a
//! time, over its own socket.
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
//! The wall-clock limit is the service's: it stops waiting and kills the worker.

use std::{
    fs::File,
    io::{self, BufReader, Write},
    os::unix::net::UnixStream,
    panic,
    time::Duration,
};

use nix::sys::{
    prctl,
    resource::{Resource, setrlimit},
    signal::{SigEvent, SigHandler, SigevNotify, Signal, signal},
    time::TimeSpec,
    timer::{Expiration, Timer, TimerSetTimeFlags},
};
use nix::time::ClockId;
use nix::unistd::{dup2_stderr, dup2_stdin, dup2_stdout};

use crate::{
    Config, jq,
    wire::{self, Request, verdict},
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
/// Exit code of a worker that got a request it could not read.
const EXIT_BAD_REQUEST: i32 = 72;

/// The worker's whole life. Returns its exit code.
///
/// `data_limit` is its `RLIMIT_DATA`: the configured budget plus what the trampoline held when it
/// forked the worker, which the worker starts with a copy of.
pub fn run(socket: UnixStream, config: &Config, data_limit: u64) -> i32 {
    let Ok(timer) = set_up(config, data_limit) else {
        return EXIT_SETUP_FAILED;
    };
    match serve(socket, timer, config) {
        Ok(()) => 0,
        Err(_) => EXIT_BAD_REQUEST,
    }
}

fn set_up(config: &Config, data_limit: u64) -> io::Result<Timer> {
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
    // The worker runs on the stack of the trampoline's only thread, which the kernel grows on
    // demand up to this limit. Stack is not charged to `RLIMIT_DATA`, so without its own limit
    // (it can be "unlimited" in a container) runaway recursion would be bounded by nothing.
    setrlimit(Resource::RLIMIT_STACK, config.stack, config.stack)?;
    // Nothing below opens a file, creates one, starts a process or should leave a core dump.
    setrlimit(Resource::RLIMIT_NOFILE, 0, 0)?;
    setrlimit(Resource::RLIMIT_FSIZE, 0, 0)?;
    setrlimit(Resource::RLIMIT_NPROC, 0, 0)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0)?;
    // `RLIMIT_CORE` does not stop a core dump piped to a handler such as apport or
    // systemd-coredump, which can hold a dying worker for a second or more. A process that is
    // not dumpable is never dumped. It cannot be traced by its user either.
    prctl::set_dumpable(false)?;

    // The Rust runtime catches the guard-page fault of a stack overflow to print a message, and
    // then aborts. With the default action restored the worker dies of `SIGSEGV` itself, which
    // keeps running off the stack distinguishable from running out of memory.
    //
    // Safety: restoring the default action installs no handler.
    unsafe { signal(STACK_SIGNAL, SigHandler::SigDfl) }?;

    // jaq does not panic on valid use. If it does anyway, die with a code of its own instead of
    // unwinding or aborting, so the death is not mistaken for a limit.
    panic::set_hook(Box::new(|_| {
        // Safety: `_exit` only terminates the calling process.
        unsafe { libc::_exit(EXIT_PANICKED) }
    }));

    // Counts CPU time of this process only, and the worker has one thread: the time measured is
    // the time spent on the evaluation.
    Ok(Timer::new(
        ClockId::CLOCK_PROCESS_CPUTIME_ID,
        SigEvent::new(SigevNotify::SigevSignal {
            signal: CPU_TIME_SIGNAL,
            si_value: 0,
        }),
    )?)
}

fn serve(stream: UnixStream, mut timer: Timer, config: &Config) -> io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    let cpu_time = config.cpu_time;

    // Ends when the service closes its end of the socket.
    while let Some(request) = wire::read_request(&mut reader, config)? {
        match request {
            Request::Check(source) => match limited(&mut timer, cpu_time, || jq::compile(&source))?
            {
                Ok(_) => writer.write_all(&[wire::VALID])?,
                Err(message) => writer.write_all(&wire::encode_invalid(&message))?,
            },
            Request::Evaluate { input, filters } => {
                let parsed = limited(&mut timer, cpu_time, || {
                    jaq_json::read::parse_single(&input)
                })?;
                drop(input);
                let Ok(input) = parsed else {
                    writer.write_all(&[wire::INPUT_INVALID])?;
                    continue;
                };
                writer.write_all(&[wire::INPUT_OK])?;

                for source in filters {
                    // Each filter gets the whole budget, compiling it included.
                    let result = limited(&mut timer, cpu_time, || match jq::compile(&source) {
                        Ok(filter) if jq::matches(&filter, input.clone()) => verdict::TRUE,
                        Ok(_) => verdict::FALSE,
                        Err(_) => verdict::INVALID_FILTER,
                    })?;
                    // Unbuffered: the verdict must reach the socket before the next filter gets
                    // the chance to kill the worker.
                    writer.write_all(&[result])?;
                }
            }
        }
    }
    Ok(())
}

/// Runs `f` with the CPU-time timer armed for `cpu_time`.
fn limited<T>(timer: &mut Timer, cpu_time: Duration, f: impl FnOnce() -> T) -> io::Result<T> {
    let armed = Expiration::OneShot(TimeSpec::from_duration(cpu_time));
    // A zero expiration disarms the timer.
    let disarmed = Expiration::OneShot(TimeSpec::new(0, 0));
    timer.set(armed, TimerSetTimeFlags::empty())?;
    let result = f();
    timer.set(disarmed, TimerSetTimeFlags::empty())?;
    Ok(result)
}
