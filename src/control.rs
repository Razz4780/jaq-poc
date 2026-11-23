//! Messages between the service and the dispatcher.
//!
//! They travel over a `SOCK_SEQPACKET` pair, so every message arrives whole and the peer going
//! away reads as a zero-length message. Every message is [`MESSAGE_LEN`] bytes: a tag and an
//! `i32`. The reply to [`Request::Spawn`] also carries the service's end of the new worker's
//! socket as `SCM_RIGHTS` ancillary data.
//!
//! The service sends one request and waits for its reply before sending the next.

use std::{
    io::{self, IoSlice, IoSliceMut},
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

use nix::{
    errno::Errno,
    sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg},
    unistd::Pid,
};

pub const MESSAGE_LEN: usize = 5;

pub type Message = [u8; MESSAGE_LEN];

fn message(tag: u8, value: i32) -> Message {
    let [a, b, c, d] = value.to_le_bytes();
    [tag, a, b, c, d]
}

fn parts(message: Message) -> (u8, i32) {
    let [tag, a, b, c, d] = message;
    (tag, i32::from_le_bytes([a, b, c, d]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Fork a new worker.
    Spawn,
    /// Kill the worker if it still runs, reap it, and report how it ended.
    ///
    /// This is the only way a worker is ever signalled. The dispatcher is the worker's parent
    /// and only signals pids it has not reaped yet, so the pid cannot have been reused.
    Release(Pid),
}

impl Request {
    pub fn encode(self) -> Message {
        match self {
            Self::Spawn => message(0, 0),
            Self::Release(pid) => message(1, pid.as_raw()),
        }
    }

    pub fn decode(message: Message) -> Option<Self> {
        match parts(message) {
            (0, _) => Some(Self::Spawn),
            (1, pid) => Some(Self::Release(Pid::from_raw(pid))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Sent once, unprompted, when the dispatcher has set itself up.
    Ready,
    /// The dispatcher could not set itself up, or could not fork a worker.
    Failed(Errno),
    /// A worker was forked. The service's end of its socket is attached.
    Spawned(Pid),
    /// The released worker exited with this code.
    Exited(i32),
    /// The released worker was killed by this signal.
    Signaled(i32),
    /// The released pid is not a live worker of this dispatcher.
    UnknownWorker,
}

impl Reply {
    pub fn encode(self) -> Message {
        match self {
            Self::Ready => message(0, 0),
            Self::Failed(errno) => message(1, errno as i32),
            Self::Spawned(pid) => message(2, pid.as_raw()),
            Self::Exited(code) => message(3, code),
            Self::Signaled(signal) => message(4, signal),
            Self::UnknownWorker => message(5, 0),
        }
    }

    pub fn decode(message: Message) -> Option<Self> {
        match parts(message) {
            (0, _) => Some(Self::Ready),
            (1, errno) => Some(Self::Failed(Errno::from_raw(errno))),
            (2, pid) => Some(Self::Spawned(Pid::from_raw(pid))),
            (3, code) => Some(Self::Exited(code)),
            (4, signal) => Some(Self::Signaled(signal)),
            (5, _) => Some(Self::UnknownWorker),
            _ => None,
        }
    }
}

/// Sends one message, with `attached` passed along as a file descriptor.
pub fn send(
    socket: BorrowedFd<'_>,
    message: Message,
    attached: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let attached = attached.map(|fd| [fd.as_raw_fd()]);
    let control_messages = match &attached {
        Some(fds) => vec![ControlMessage::ScmRights(fds)],
        None => Vec::new(),
    };
    // `MSG_NOSIGNAL`: a peer that is gone must surface as an error here, whatever the process
    // does with `SIGPIPE`.
    let sent = sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(&message)],
        &control_messages,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )?;
    if sent == MESSAGE_LEN {
        Ok(())
    } else {
        Err(io::ErrorKind::WriteZero.into())
    }
}

/// Receives one message and the file descriptor attached to it, if any.
///
/// Fails with [`io::ErrorKind::UnexpectedEof`] when the peer has closed its end.
pub fn receive(socket: BorrowedFd<'_>) -> io::Result<(Message, Option<OwnedFd>)> {
    let mut message: Message = [0; MESSAGE_LEN];
    let mut control_buffer = nix::cmsg_space!(RawFd);
    let (received, attached) = {
        let mut iov = [IoSliceMut::new(&mut message)];
        let received = recvmsg::<()>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control_buffer),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )?;
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
        (received.bytes, attached)
    };

    match received {
        0 => Err(io::ErrorKind::UnexpectedEof.into()),
        MESSAGE_LEN => Ok((message, attached.into_iter().next())),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}
