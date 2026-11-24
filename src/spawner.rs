//! Forking processes on demand from a snapshot of the process taken early.
//!
//! `fork` is only safe in a single-threaded process, and a child forked from a running service
//! would carry a copy of everything the service holds. A [`Trampoline`] is forked once, while the
//! process still has one thread. It stays single-threaded, and forks a [`Child`] whenever asked
//! to. **Every child is a copy of the trampoline, not of the service as it is by then.**
//!
//! The trampoline forks with `clone(CLONE_PARENT | CLONE_PIDFD)`: a child's memory is a copy of
//! the trampoline's, but its parent is the process that created the trampoline. The trampoline
//! keeps no record of its children, and the service holds each child through a pidfd. It can
//! signal it without any risk of hitting a reused pid, and as its parent it can wait for it and
//! learn how it ended.
//!
//! This is the legacy `clone` syscall, not `clone3`, on purpose. The default seccomp profiles of
//! Docker and containerd, which is what Kubernetes' `RuntimeDefault` means, fail `clone3` with
//! `ENOSYS`: its flags are behind a pointer, where a seccomp filter cannot inspect them. `clone`
//! is allowed as long as it creates no namespace.
//!
//! The raw syscall skips glibc's `fork` wrapper, and with it the `pthread_atfork` handlers. That
//! is harmless in a single-threaded process that is not inside the allocator at the time.

use std::{
    fs,
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
};

use nix::{
    errno::Errno,
    sys::{
        prctl,
        signal::Signal,
        socket::{
            AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
            recvmsg, sendmsg, socketpair,
        },
        wait::{Id, WaitPidFlag, WaitStatus, waitid},
    },
    unistd::{Pid, close, getppid},
};
use tokio::io::{Interest, unix::AsyncFd};

/// A process forked by this module, controlled through pidfd. It is a child of the calling
/// process.
///
/// Dropping it kills the process and reaps it, blocking until it is gone.
#[derive(Debug)]
pub struct Child {
    pidfd: OwnedFd,
}

impl Child {
    /// Kills the process with `SIGKILL`. A no-op for a process that has already ended.
    pub fn kill(&self) -> io::Result<()> {
        // Safety: a plain syscall on a descriptor owned by this handle.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        match sent {
            0 => Ok(()),
            _ => match Errno::last() {
                // Already reaped.
                Errno::ESRCH => Ok(()),
                errno => Err(errno.into()),
            },
        }
    }

    /// Whether the process has ended. It may still need to be reaped, with [`Child::wait`].
    pub fn has_exited(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Safety: `poll` points to one valid `pollfd`.
        unsafe { libc::poll(&mut poll, 1, 0) > 0 }
    }

    /// Waits for the process to end, without blocking the thread, and reaps it.
    ///
    /// Must be called from within a tokio runtime. Fails if the process has been reaped already.
    pub async fn wait(&self) -> io::Result<WaitStatus> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        // Safety: the descriptor stays open for as long as `self` lives, which outlives the
        // registration.
        let pidfd =
            unsafe { AsyncFd::register_with_interest(self.pidfd.as_fd(), Interest::READABLE) }?;
        // A pidfd becomes readable when the process ends, and stays so.
        let _ = pidfd.readable().await?;
        self.reap()
    }

    /// Reaps the process, blocking until it ends.
    fn reap(&self) -> io::Result<WaitStatus> {
        loop {
            match waitid(Id::PIDFd(self.pidfd.as_fd()), WaitPidFlag::WEXITED) {
                Err(Errno::EINTR) => continue,
                result => return Ok(result?),
            }
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // Both fail harmlessly if the process has already been reaped.
        let _ = self.kill();
        let _ = self.reap();
    }
}

/// A single-threaded copy of a process, responsible for forking children on its behalf.
///
/// This allows for spawning children from a multi-threaded process, and having the
/// children share some memory (e.g. code). Trampoline is created
/// before spawning threads, and the children inherit memory from that moment.
/// See the module documentation.
///
/// Dropping this kills the trampoline process. Children it forked are not affected.
pub struct Trampoline {
    /// `SOCK_SEQPACKET` used to control the trampoline process.
    ///
    /// One byte asks for a new child, and the reply is a status and, attached, the
    /// child's pidfd and the parent's end of its socket.
    ///
    /// Declared before `process`, so that the trampoline sees its end close before it is killed.
    control: OwnedFd,
    process: Child,
}

impl Trampoline {
    /// Creates the trampoline. Fails if the process already has more than one thread.
    ///
    /// The trampoline first closes every descriptor it inherited, except the standard streams,
    /// so that it holds nothing of the process open for as long as it lives. It then runs `init`
    /// once. That is the place to prepare the state every child should start with. `init`
    /// returns the function that each child runs, with its end of a Unix stream socket connected
    /// to the one returned from [`Trampoline::spawn`]. A child exits with the code it returns.
    ///
    /// If `init` fails, so does this call. Its error is reported by its OS error code only.
    ///
    /// The trampoline and every child are killed when the thread calling this exits. That should
    /// be the process's main thread.
    pub fn create<I, G>(init: I) -> io::Result<Self>
    where
        I: FnOnce() -> io::Result<G>,
        G: Fn(UnixStream) -> i32,
    {
        if thread_count()? != 1 {
            return Err(io::Error::other(
                "a trampoline must be created before the process starts any thread",
            ));
        }
        let (parent_end, trampoline_end) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )?;
        let parent = Pid::this();

        // Safety: the process has a single thread, checked above.
        match unsafe { clone_with_pidfd(libc::SIGCHLD) }? {
            None => {
                drop(parent_end);
                trampoline(trampoline_end, parent, init)
            }
            Some(pidfd) => {
                drop(trampoline_end);
                let trampoline = Self {
                    control: parent_end,
                    process: Child { pidfd },
                };
                let (status, _) = receive(trampoline.control.as_fd())?;
                match status {
                    0 => Ok(trampoline),
                    errno => Err(io::Error::from_raw_os_error(errno)),
                }
            }
        }
    }

    /// Forks a child, and returns it with the parent's end of its socket.
    ///
    /// Blocks until the trampoline has forked: a fork of a small single-threaded process, well
    /// under a millisecond.
    pub fn spawn(&mut self) -> io::Result<(Child, UnixStream)> {
        send(self.control.as_fd(), 0, &[])?;
        let (status, attached) = receive(self.control.as_fd())?;
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        let mut attached = attached.into_iter();
        match (attached.next(), attached.next()) {
            (Some(pidfd), Some(socket)) => Ok((Child { pidfd }, UnixStream::from(socket))),
            // A child without its socket is useless: dropping its handle kills it.
            (pidfd, _) => {
                drop(pidfd.map(|pidfd| Child { pidfd }));
                Err(io::ErrorKind::InvalidData.into())
            }
        }
    }
}

impl Drop for Trampoline {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

/// The trampoline's whole life.
fn trampoline<I, G>(control: OwnedFd, parent: Pid, init: I) -> !
where
    I: FnOnce() -> io::Result<G>,
    G: Fn(UnixStream) -> i32,
{
    let child_main = match set_up(&control, parent).and_then(|()| init()) {
        Ok(child_main) => child_main,
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(libc::EIO);
            let _ = send(control.as_fd(), errno, &[]);
            exit(1);
        }
    };
    if send(control.as_fd(), 0, &[]).is_err() {
        exit(0);
    }

    // Any failure to receive means the parent is gone or broken. Either way there is nothing
    // left to do.
    while receive(control.as_fd()).is_ok() {
        let sent = match spawn_child(&control, parent, &child_main) {
            // Both descriptors are closed here, after they are sent. The trampoline must not keep
            // any end of a child's socket: later children would inherit it, and neither side
            // would ever see the other one close.
            Ok((pidfd, socket)) => send(control.as_fd(), 0, &[pidfd.as_fd(), socket.as_fd()]),
            Err(errno) => send(control.as_fd(), errno as i32, &[]),
        };
        if sent.is_err() {
            break;
        }
    }
    exit(0)
}

fn set_up(control: &OwnedFd, parent: Pid) -> io::Result<()> {
    die_with(parent)?;
    close_inherited(control)
}

/// Has the process killed when `parent` dies.
fn die_with(parent: Pid) -> io::Result<()> {
    // The signal comes when the thread that created the trampoline exits.
    prctl::set_pdeathsig(Signal::SIGKILL)?;
    if getppid() != parent {
        // The parent died before the line above, so the signal will never come.
        exit(0);
    }
    Ok(())
}

/// Forks one child and returns its pidfd and the parent's end of its socket.
fn spawn_child<G>(
    control: &OwnedFd,
    parent: Pid,
    child_main: &G,
) -> Result<(OwnedFd, OwnedFd), Errno>
where
    G: Fn(UnixStream) -> i32,
{
    let (parent_end, child_end) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
    // Safety: the trampoline never starts a thread. With `CLONE_PARENT` the exit signal is the
    // trampoline's own, `SIGCHLD`, whatever the flags say.
    match unsafe { clone_with_pidfd(libc::CLONE_PARENT | libc::SIGCHLD) } {
        Ok(None) => {
            // `SOCK_CLOEXEC` does nothing here, as a child never calls `exec`: what it must not
            // hold has to be closed by hand.
            let _ = close(control.as_raw_fd());
            drop(parent_end);
            if die_with(parent).is_err() {
                exit(1);
            }
            exit(child_main(UnixStream::from(child_end)))
        }
        Ok(Some(pidfd)) => Ok((pidfd, parent_end)),
        Err(error) => Err(error.raw_os_error().map_or(Errno::EIO, Errno::from_raw)),
    }
}

/// Forks with `clone`, adding `CLONE_PIDFD` to `flags`, whose lowest byte is the exit signal.
/// Returns `None` in the child, and the child's pidfd in the parent.
///
/// # Safety
///
/// As [`nix::unistd::fork`]: the calling process must have a single thread.
unsafe fn clone_with_pidfd(flags: libc::c_int) -> io::Result<Option<OwnedFd>> {
    let flags = libc::c_ulong::try_from(flags | libc::CLONE_PIDFD).unwrap_or_default();
    let mut pidfd: libc::c_int = -1;
    let pidfd_at: *mut libc::c_int = &mut pidfd;
    let (stack, none): (libc::c_ulong, libc::c_ulong) = (0, 0);
    // With `CLONE_PIDFD` the kernel stores the pidfd where the parent's tid would go, the third
    // argument on every architecture but s390, which swaps the first two.
    #[cfg(not(target_arch = "s390x"))]
    let args = (flags, stack);
    #[cfg(target_arch = "s390x")]
    let args = (stack, flags);
    // Safety: `pidfd_at` points to an `int`. Without `CLONE_VM` and without a stack, the child
    // runs on a copy of the caller's stack, exactly as after `fork`.
    let forked = unsafe { libc::syscall(libc::SYS_clone, args.0, args.1, pidfd_at, none, none) };
    match forked {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(None),
        // Safety: the kernel just stored a new descriptor there, which nothing else owns.
        _ => Ok(Some(unsafe { OwnedFd::from_raw_fd(pidfd) })),
    }
}

/// Exits the calling process at once, without running exit handlers or flushing buffered output
/// a second time: the trampoline and its children are copies of the parent.
fn exit(code: i32) -> ! {
    // Safety: `_exit` only terminates the calling process.
    unsafe { libc::_exit(code) }
}

fn thread_count() -> io::Result<usize> {
    fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|rest| rest.trim().parse().ok())
        .ok_or_else(|| io::Error::other("no thread count in /proc/self/status"))
}

/// Closes every descriptor except the standard streams and `control`.
///
/// Whatever the parent had open when it created the trampoline, the trampoline and all its
/// children would otherwise hold open for as long as they live. For a socket that is more than
/// untidy: its peer never sees it close. A second trampoline would inherit the parent's end of
/// the first one's control socket, and the first one would then outlive its handle.
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

/// Sends one control message, a status, with `attached` passed along as file descriptors.
fn send(socket: BorrowedFd<'_>, status: i32, attached: &[BorrowedFd]) -> io::Result<()> {
    let message = status.to_le_bytes();
    let raw_fds = attached
        .iter()
        .map(|borrowed| borrowed.as_raw_fd())
        .collect::<Vec<_>>();
    let control = [ControlMessage::ScmRights(&raw_fds)];
    let sent = sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(&message)],
        if attached.is_empty() {
            Default::default()
        } else {
            &control
        },
        // A peer that is gone must surface as an error here, whatever the process does with
        // `SIGPIPE`: the trampoline inherits the disposition of whoever created it.
        MsgFlags::MSG_NOSIGNAL,
        None,
    )?;
    if sent == message.len() {
        Ok(())
    } else {
        Err(io::ErrorKind::WriteZero.into())
    }
}

/// Receives one control message and the descriptors attached to it. Fails with
/// [`io::ErrorKind::UnexpectedEof`] when the peer has closed its end.
fn receive(socket: BorrowedFd<'_>) -> io::Result<(i32, Vec<OwnedFd>)> {
    let mut message = [0; 4];
    let mut control_buffer = nix::cmsg_space!([RawFd; 2]);
    let (received, attached) = loop {
        let mut iov = [IoSliceMut::new(&mut message)];
        let received = match recvmsg::<()>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control_buffer),
            MsgFlags::MSG_CMSG_CLOEXEC,
        ) {
            Err(Errno::EINTR) => continue,
            received => received?,
        };
        let attached = received
            .cmsgs()?
            .filter_map(|control_message| match control_message {
                ControlMessageOwned::ScmRights(fds) => Some(fds),
                _ => None,
            })
            .flatten()
            // Safety: the kernel just installed these descriptors in this process for this
            // message, so nothing else owns them.
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
            .collect::<Vec<_>>();
        break (received.bytes, attached);
    };
    match received {
        0 => Err(io::ErrorKind::UnexpectedEof.into()),
        4 => Ok((i32::from_le_bytes(message), attached)),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}
