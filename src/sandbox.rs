//! The service's side: a pool of workers and the evaluations handed to them.

use std::{
    fmt, io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream as StdUnixStream,
    },
    sync::{
        Arc, Mutex as StdMutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    sys::signal::Signal,
    unistd::Pid,
};
use tokio::{
    io::{AsyncWriteExt, Interest, unix::AsyncFd},
    net::UnixStream,
    runtime::Handle,
    sync::{Mutex, Semaphore},
    time::timeout,
};

use crate::{
    Config, Dispatcher, Error, Limit,
    control::{self, Reply as ControlReply, Request as ControlRequest},
    dispatcher::Reaper,
    wire::{self, Kind, Reply},
    worker::{CPU_TIME_SIGNAL, MEMORY_SIGNAL, STACK_SIGNAL},
};

/// Evaluates jq filters in sandboxed worker processes.
///
/// Cheap to clone; all clones share one pool of workers. When the last clone is dropped, the
/// dispatcher and its workers are stopped.
#[derive(Clone)]
pub struct Sandbox(Arc<Shared>);

struct Shared {
    config: Config,
    /// Service --spawn and release requests--> dispatcher. Locked for a whole request and its
    /// reply, which is what pairs each reply with its request.
    ///
    /// Declared before `reaper`, see [`Dispatcher`].
    control: Mutex<AsyncFd<OwnedFd>>,
    /// Workers that are alive and not evaluating anything.
    idle: StdMutex<Vec<Worker>>,
    /// One permit per worker that may exist.
    permits: Semaphore,
    workers_spawned: AtomicU64,
    _reaper: Reaper,
}

struct Worker {
    pid: Pid,
    /// Service --filter and input--> worker, and the verdict back.
    stream: UnixStream,
}

/// How an exchange with a worker failed.
enum ExchangeError {
    /// The request could not be written, so the worker was dead before it saw the request.
    NotDelivered,
    /// The worker took the request and closed its socket without answering: it died over it.
    NoReply,
}

impl Worker {
    async fn exchange(&mut self, request: &[u8]) -> Result<Reply, ExchangeError> {
        self.stream
            .write_all(request)
            .await
            .map_err(|_| ExchangeError::NotDelivered)?;
        Reply::read(&mut self.stream)
            .await
            .map_err(|_| ExchangeError::NoReply)
    }
}

impl Sandbox {
    pub(crate) fn new(dispatcher: Dispatcher) -> io::Result<Self> {
        let Dispatcher {
            control,
            reaper,
            config,
        } = dispatcher;
        // `control` moves into the call, so on failure it is closed by the time `reaper` is
        // dropped and waits for the dispatcher to exit.
        let control = register(control)?;

        Ok(Self(Arc::new(Shared {
            permits: Semaphore::new(config.workers),
            config,
            control: Mutex::new(control),
            idle: StdMutex::default(),
            workers_spawned: AtomicU64::new(0),
            _reaper: reaper,
        })))
    }

    /// Runs `filter` on `input` and reports whether it matched: the filter's first boolean output
    /// decides, and a filter that outputs no boolean does not match.
    ///
    /// The evaluation is not cancelled when the returned future is dropped. It runs to its
    /// verdict or to one of its limits either way, and its worker goes back to the pool.
    pub async fn evaluate(&self, filter: &str, input: &serde_json::Value) -> Result<bool, Error> {
        let input =
            serde_json::to_vec(input).map_err(|error| Error::InvalidInput(error.to_string()))?;
        match self.request(Kind::Evaluate, filter, &input).await? {
            Reply::Matched(matched) => Ok(matched),
            reply => Err(unexpected(reply)),
        }
    }

    /// Checks that `filter` compiles, without running it.
    ///
    /// Compiling runs in a worker under the same limits as an evaluation: compiling hostile
    /// source can exhaust the stack just like running it.
    pub async fn check(&self, filter: &str) -> Result<(), Error> {
        match self.request(Kind::Check, filter, &[]).await? {
            Reply::Valid => Ok(()),
            reply => Err(unexpected(reply)),
        }
    }

    /// How many workers have been forked so far. Each one beyond the pool size replaced a worker
    /// that was killed, so a climbing rate means filters are hitting their limits.
    pub fn workers_spawned(&self) -> u64 {
        self.0.workers_spawned.load(Ordering::Relaxed)
    }

    async fn request(&self, kind: Kind, filter: &str, input: &[u8]) -> Result<Reply, Error> {
        let config = &self.0.config;
        if filter.len() > config.max_filter_len {
            return Err(Error::FilterTooLarge {
                len: filter.len(),
                limit: config.max_filter_len,
            });
        }
        if input.len() > config.max_input_len {
            return Err(Error::InputTooLarge {
                len: input.len(),
                limit: config.max_input_len,
            });
        }

        // A task of its own, so that a caller that stops waiting leaves neither a worker with a
        // half-read reply in the pool, nor a conversation with the dispatcher cut off between
        // request and reply.
        let exchange = tokio::spawn(
            self.0
                .clone()
                .exchange(wire::encode_request(kind, filter, input)),
        );
        match exchange.await {
            Ok(Ok(Reply::InvalidFilter(message))) => Err(Error::InvalidFilter(message)),
            Ok(Ok(Reply::InvalidInput(message))) => Err(Error::InvalidInput(message)),
            Ok(result) => result,
            // The task panicked, or the runtime is shutting down.
            Err(error) => Err(Error::Unavailable(io::Error::other(error))),
        }
    }
}

impl fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sandbox")
            .field("config", &self.0.config)
            .finish_non_exhaustive()
    }
}

/// A reply that does not answer the request that was sent, which a worker never produces.
fn unexpected(reply: Reply) -> Error {
    Error::Unavailable(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected reply from a jq worker: {reply:?}"),
    ))
}

/// Makes the control socket usable from async code.
fn register(control: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    Handle::try_current().map_err(io::Error::other)?;
    let flags = OFlag::from_bits_retain(fcntl(&control, FcntlArg::F_GETFL)?);
    fcntl(&control, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    // Safety: `control` is an open socket that the `AsyncFd` owns from here on, so the
    // descriptor stays valid for as long as it is registered.
    Ok(unsafe { AsyncFd::register(control) }?)
}

impl Shared {
    /// Sends `request` to an idle worker, forking one if none is idle, and returns its reply.
    async fn exchange(self: Arc<Self>, request: Vec<u8>) -> Result<Reply, Error> {
        let _permit = self
            .permits
            .acquire()
            .await
            // The semaphore is never closed.
            .expect("the worker semaphore is closed");

        loop {
            let idle = self.idle().pop();
            let (mut worker, pooled) = match idle {
                Some(worker) => (worker, true),
                None => (self.spawn().await?, false),
            };

            // The clock starts here, with a worker in hand: waiting for one is not the filter's
            // time.
            match timeout(self.config.wall_time, worker.exchange(&request)).await {
                Ok(Ok(reply)) => {
                    self.idle().push(worker);
                    return Ok(reply);
                }
                // A worker from the pool that died while idle, killed by something outside the
                // sandbox. That is not this evaluation's doing, so it gets another worker. A
                // worker forked for this very request is not retried, which bounds the loop.
                Ok(Err(ExchangeError::NotDelivered)) if pooled => {
                    if let Error::Unavailable(error) = self.release(worker, false).await {
                        return Err(Error::Unavailable(error));
                    }
                }
                Ok(Err(_)) => return Err(self.release(worker, false).await),
                Err(_) => return Err(self.release(worker, true).await),
            }
        }
    }

    fn idle(&self) -> std::sync::MutexGuard<'_, Vec<Worker>> {
        // Nothing that can panic runs while the lock is held, and a list of workers stays valid
        // regardless.
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One request to the dispatcher and its reply.
    ///
    /// Not cancel safe: a caller that goes away between the two leaves a reply behind for the
    /// next request. It is only called from [`Shared::exchange`], which runs in its own task.
    async fn call(&self, request: ControlRequest) -> io::Result<(ControlReply, Option<OwnedFd>)> {
        let control = self.control.lock().await;
        control
            .async_io(Interest::WRITABLE, |socket| {
                control::send(socket.as_fd(), request.encode(), None)
            })
            .await?;
        let (message, attached) = control
            .async_io(Interest::READABLE, |socket| {
                control::receive(socket.as_fd())
            })
            .await?;
        let reply = ControlReply::decode(message).ok_or(io::ErrorKind::InvalidData)?;
        Ok((reply, attached))
    }

    async fn spawn(&self) -> Result<Worker, Error> {
        let (pid, socket) = match self.call(ControlRequest::Spawn).await {
            Ok((ControlReply::Spawned(pid), Some(socket))) => (pid, socket),
            Ok((ControlReply::Failed(errno), _)) => return Err(Error::Unavailable(errno.into())),
            Ok(_) => return Err(Error::Unavailable(io::ErrorKind::InvalidData.into())),
            Err(error) => return Err(Error::Unavailable(error)),
        };
        self.workers_spawned.fetch_add(1, Ordering::Relaxed);

        let stream = StdUnixStream::from(socket);
        let stream = stream
            .set_nonblocking(true)
            .and_then(|()| UnixStream::from_std(stream));
        match stream {
            Ok(stream) => Ok(Worker { pid, stream }),
            Err(error) => {
                // The worker exists but cannot be talked to; do not leave it behind.
                let _ = self.call(ControlRequest::Release(pid)).await;
                Err(Error::Unavailable(error))
            }
        }
    }

    /// Has the dispatcher kill and reap `worker`, and turns the way the worker ended into the
    /// error of the evaluation that was running on it.
    async fn release(&self, worker: Worker, timed_out: bool) -> Error {
        let Worker { pid, stream } = worker;
        drop(stream);
        let reply = match self.call(ControlRequest::Release(pid)).await {
            Ok((reply, _)) => reply,
            Err(error) => return Error::Unavailable(error),
        };

        match reply {
            ControlReply::Signaled(signal) if signal == CPU_TIME_SIGNAL as i32 => {
                Error::LimitExceeded(Limit::CpuTime)
            }
            ControlReply::Signaled(signal) if signal == MEMORY_SIGNAL as i32 => {
                Error::LimitExceeded(Limit::Memory)
            }
            ControlReply::Signaled(signal) if signal == STACK_SIGNAL as i32 => {
                Error::LimitExceeded(Limit::Stack)
            }
            // The worker was still running when the dispatcher killed it for this release.
            ControlReply::Signaled(signal) if signal == Signal::SIGKILL as i32 && timed_out => {
                Error::LimitExceeded(Limit::WallTime)
            }
            // Includes a `SIGKILL` nobody here sent, such as the kernel's out-of-memory killer.
            ControlReply::Signaled(signal) => Error::WorkerDied(match Signal::try_from(signal) {
                Ok(signal) => format!("killed by {signal}"),
                Err(_) => format!("killed by signal {signal}"),
            }),
            ControlReply::Exited(code) => Error::WorkerDied(format!("exited with code {code}")),
            _ => Error::WorkerDied("the dispatcher has no record of it".to_owned()),
        }
    }
}
