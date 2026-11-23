//! The dispatcher: a small, single-threaded child of the service whose only job is to fork
//! workers on request and to reap them.
//!
//! It exists because a worker has to be a `fork` of something. Forking the service itself is not
//! an option once it runs threads, and a worker forked from it would also carry a copy of
//! everything the service holds in memory. The dispatcher is forked before any of that exists and
//! stays as it was at that moment, so every worker starts as a copy of an almost empty process and
//! shares nearly all of its pages with the dispatcher and the other workers.

use std::{
    fs, io,
    os::fd::{AsFd, AsRawFd, OwnedFd, RawFd},
};

use caps::CapSet;
use nix::{
    errno::Errno,
    sys::{
        prctl,
        signal::{Signal, kill},
        socket::{AddressFamily, SockFlag, SockType, socketpair},
        wait::{WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, close, fork, getppid},
};

use crate::{
    Config, Sandbox,
    control::{self, Reply, Request},
    worker,
};

/// A running dispatcher process, not yet usable for evaluations.
///
/// Created with [`Dispatcher::fork`] before the service starts any thread, and turned into a
/// [`Sandbox`] with [`Dispatcher::connect`] once the tokio runtime is up.
///
/// Dropping it, or the last clone of the [`Sandbox`] made from it, stops the dispatcher and all
/// its workers.
#[derive(Debug)]
pub struct Dispatcher {
    // Declared before `reaper`: closing the control socket is what makes the dispatcher exit, and
    // fields drop in declaration order.
    pub(crate) control: OwnedFd,
    pub(crate) reaper: Reaper,
    pub(crate) config: Config,
}

impl Dispatcher {
    /// Forks the dispatcher process.
    ///
    /// Must be called before the process starts its first thread, which in practice means at the
    /// very top of `main`, ahead of building the tokio runtime. A `fork` copies only the calling
    /// thread: locks held by any other thread at that instant, the allocator's included, would
    /// stay locked forever in the child. The call fails if the process already has more than one
    /// thread.
    ///
    /// Calling it this early also keeps the service's secrets out of the workers: whatever the
    /// process has not loaded yet is not in the copy. Descriptors the process has open by then,
    /// other than its standard streams, are closed in the dispatcher.
    pub fn fork(config: Config) -> io::Result<Self> {
        if config.workers == 0 || config.cpu_time.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "`workers` and `cpu_time` must not be zero",
            ));
        }
        if u32::try_from(config.max_filter_len).is_err()
            || u32::try_from(config.max_input_len).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "`max_filter_len` and `max_input_len` must fit in 32 bits",
            ));
        }
        if thread_count()? != 1 {
            return Err(io::Error::other(
                "the jq dispatcher must be forked before the process starts any thread",
            ));
        }

        let (service_end, dispatcher_end) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )?;
        let service = Pid::this();

        // Safety: the process has a single thread (checked above), so the child is a complete,
        // consistent copy of it.
        match unsafe { fork() }? {
            ForkResult::Child => {
                drop(service_end);
                run(dispatcher_end, service, config)
            }
            ForkResult::Parent { child } => {
                drop(dispatcher_end);
                let dispatcher = Self {
                    control: service_end,
                    reaper: Reaper(child),
                    config,
                };
                // The dispatcher reports whether it managed to set itself up, so that a broken
                // sandbox fails the service's startup instead of its first evaluation.
                let (message, _) = control::receive(dispatcher.control.as_fd())?;
                match Reply::decode(message) {
                    Some(Reply::Ready) => Ok(dispatcher),
                    Some(Reply::Failed(errno)) => Err(errno.into()),
                    _ => Err(io::ErrorKind::InvalidData.into()),
                }
            }
        }
    }

    /// Connects the service to the dispatcher. Must be called from within a tokio runtime.
    pub fn connect(self) -> io::Result<Sandbox> {
        Sandbox::new(self)
    }
}

/// Waits for the dispatcher to exit, so that it does not linger as a zombie of the service.
///
/// Dropped after the control socket is closed, at which point the dispatcher kills its workers
/// and exits, so the wait is short.
#[derive(Debug)]
pub(crate) struct Reaper(Pid);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = waitpid(self.0, None);
    }
}

fn thread_count() -> io::Result<usize> {
    status_field("Threads:")
}

/// Size in bytes of the mappings that `RLIMIT_DATA` is charged against.
fn data_size() -> io::Result<u64> {
    let kilobytes: u64 = status_field("VmData:")?;
    Ok(kilobytes * 1024)
}

fn status_field<T: std::str::FromStr>(name: &str) -> io::Result<T> {
    fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other(format!("no `{name}` in /proc/self/status")))
}

/// Exits the calling process at once. Used by the dispatcher and the workers, which are forks of
/// the service and must not run its exit handlers or flush its buffered output a second time.
pub(crate) fn exit(code: i32) -> ! {
    // Safety: `_exit` only terminates the calling process.
    unsafe { libc::_exit(code) }
}

/// What the dispatcher needs to know to fork a worker.
struct Setup {
    config: Config,
    /// `RLIMIT_DATA` for workers: the data the dispatcher itself holds, which every worker starts
    /// with a copy of, plus the configured budget.
    data_limit: u64,
}

/// Closes every descriptor the dispatcher inherited from the service, except the standard streams
/// and `control`.
///
/// Whatever the service had open when it forked, the dispatcher and all its workers would
/// otherwise hold open for as long as they live. For a socket that is more than untidy: its peer
/// never sees it close. A second dispatcher forked by the same service inherits the service's end
/// of the first one's control socket, and the first dispatcher would then outlive its sandbox.
fn close_inherited(control: &OwnedFd) -> io::Result<()> {
    let inherited = fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<RawFd>().ok())
        .collect::<Vec<_>>();
    for fd in inherited {
        if fd > libc::STDERR_FILENO && fd != control.as_raw_fd() {
            // The list includes the descriptor that was used to read the directory, which is
            // closed already.
            let _ = close(fd);
        }
    }
    Ok(())
}

fn set_up(control: &OwnedFd, service: Pid, config: Config) -> io::Result<Setup> {
    // The signal is sent when the thread that forked this process exits. That is the service's
    // main thread, which lives as long as the service does.
    prctl::set_pdeathsig(Signal::SIGKILL)?;
    if getppid() != service {
        // The service died between `fork` and `prctl`, so the signal will never come.
        exit(0);
    }

    close_inherited(control)?;

    // Neither the dispatcher nor its workers need any privilege the service may have. Workers
    // inherit the dropped state.
    prctl::set_no_new_privs()?;
    for set in [
        CapSet::Ambient,
        CapSet::Inheritable,
        CapSet::Effective,
        CapSet::Permitted,
    ] {
        caps::clear(None, set).map_err(io::Error::other)?;
    }

    Ok(Setup {
        data_limit: data_size()? + config.memory,
        config,
    })
}

/// The dispatcher's whole life. It stays single-threaded, which is what keeps `fork` safe here.
fn run(control: OwnedFd, service: Pid, config: Config) -> ! {
    let setup = match set_up(&control, service, config) {
        Ok(setup) => setup,
        Err(error) => {
            let errno = error.raw_os_error().map_or(Errno::EIO, Errno::from_raw);
            let _ = control::send(control.as_fd(), Reply::Failed(errno).encode(), None);
            exit(1);
        }
    };
    if control::send(control.as_fd(), Reply::Ready.encode(), None).is_err() {
        exit(0);
    }

    // Workers that were forked and not yet released.
    let mut workers: Vec<Pid> = Vec::new();

    // Any failure to receive means the service is gone or broken; either way the dispatcher has
    // nothing left to do.
    while let Ok((message, _)) = control::receive(control.as_fd()) {
        let sent = match Request::decode(message) {
            Some(Request::Spawn) => match spawn_worker(&control, &setup) {
                Ok((pid, service_end)) => {
                    workers.push(pid);
                    control::send(
                        control.as_fd(),
                        Reply::Spawned(pid).encode(),
                        Some(service_end.as_fd()),
                    )
                    // `service_end` is closed here. The dispatcher must not keep any end of a
                    // worker's socket: later workers would inherit it, and neither side would
                    // ever see the other one close.
                }
                Err(errno) => control::send(control.as_fd(), Reply::Failed(errno).encode(), None),
            },
            Some(Request::Release(pid)) => {
                let reply = match workers.iter().position(|worker| *worker == pid) {
                    Some(index) => {
                        workers.swap_remove(index);
                        reap(pid)
                    }
                    None => Reply::UnknownWorker,
                };
                control::send(control.as_fd(), reply.encode(), None)
            }
            None => break,
        };
        if sent.is_err() {
            break;
        }
    }

    for pid in workers {
        reap(pid);
    }
    exit(0)
}

fn spawn_worker(control: &OwnedFd, setup: &Setup) -> Result<(Pid, OwnedFd), Errno> {
    let (service_end, worker_end) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
    let dispatcher = Pid::this();

    // Safety: the dispatcher never starts a thread.
    match unsafe { fork() }? {
        ForkResult::Child => {
            // `SOCK_CLOEXEC` does nothing here, as a worker never calls `exec`: what the worker
            // must not hold has to be closed by hand.
            drop(service_end);
            worker::run(
                worker_end,
                control,
                dispatcher,
                &setup.config,
                setup.data_limit,
            )
        }
        ForkResult::Parent { child } => Ok((child, service_end)),
    }
}

/// Kills the worker, which is a no-op if it is already dead, and collects how it ended.
///
/// A worker that had already begun to die keeps its original cause of death: the kill only
/// decides the outcome for a worker that was still running.
fn reap(pid: Pid) -> Reply {
    let _ = kill(pid, Signal::SIGKILL);
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return Reply::Exited(code),
            Ok(WaitStatus::Signaled(_, signal, _)) => return Reply::Signaled(signal as i32),
            // Stop and continue notifications are not requested, and `EINTR` only needs a retry.
            Ok(_) | Err(Errno::EINTR) => continue,
            Err(_) => return Reply::UnknownWorker,
        }
    }
}
