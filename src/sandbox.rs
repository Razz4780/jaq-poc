//! The service's side: a pool of workers, and the evaluations handed to them.

use std::{
    fmt, fs, io,
    num::NonZeroU32,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use caps::CapSet;
use nix::sys::{prctl, signal::Signal, wait::WaitStatus};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    runtime::Handle,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    Config, Error, Limit, jq,
    spawner::{Child, Trampoline},
    wire::{self, verdict},
    worker::{self, CPU_TIME_SIGNAL, MEMORY_SIGNAL, STACK_SIGNAL},
};

/// Most bytes of filter source sent to a worker in one request. A larger batch is split.
const MAX_REQUEST_SOURCES: usize = 1 << 20;

/// Evaluates jq filters in sandboxed worker processes.
///
/// Cheap to clone; all clones share one pool of workers. When the last clone is dropped, the
/// workers are killed.
#[derive(Clone)]
pub struct Sandbox(Arc<Shared>);

/// A filter that compiles, see [`Sandbox::compile`]. Cheap to clone.
#[derive(Clone)]
pub struct Filter(Arc<str>);

/// An input serialized as JSON, see [`Sandbox::input`]. Cheap to clone.
#[derive(Clone)]
pub struct Input(Arc<[u8]>);

struct Shared {
    config: Config,
    /// Workers that are alive and not evaluating anything.
    idle: Mutex<Vec<Worker>>,
    /// One permit per worker that may exist.
    permits: Arc<Semaphore>,
    workers_spawned: AtomicU64,
    trampoline: Mutex<Trampoline>,
}

struct Worker {
    process: Child,
    stream: BufReader<UnixStream>,
}

impl Sandbox {
    /// Creates the sandbox, forking the trampoline that workers will be forked from.
    ///
    /// Must be called before the process starts its first thread, which in practice means at the
    /// very top of `main`, ahead of building the tokio runtime. A `fork` copies only the calling
    /// thread: locks held by any other thread at that instant, the allocator's included, would
    /// stay locked forever in the child. The call fails if the process already has more than one
    /// thread.
    ///
    /// Calling it this early also keeps the service's secrets out of the workers: whatever the
    /// process has not loaded yet is not in the copy.
    ///
    /// Evaluations must run within a tokio runtime.
    pub fn new(config: Config) -> io::Result<Self> {
        if config.cpu_time.is_zero() || config.wall_time.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "`cpu_time` and `wall_time` must not be zero",
            ));
        }

        let worker_config = config.clone();
        let trampoline = Trampoline::create(move || {
            // Neither the trampoline nor its workers need any privilege the service may have.
            // Workers inherit the dropped state.
            prctl::set_no_new_privs()?;
            for set in [
                CapSet::Ambient,
                CapSet::Inheritable,
                CapSet::Effective,
                CapSet::Permitted,
            ] {
                caps::clear(None, set).map_err(io::Error::other)?;
            }
            // Parsing jaq's library here, once, spares every worker doing it.
            jq::init();
            let data_limit = data_size()? + worker_config.memory.get();
            Ok(move |socket| worker::run(socket, &worker_config, data_limit))
        })?;

        Ok(Self(Arc::new(Shared {
            idle: Mutex::default(),
            permits: Arc::new(Semaphore::new(config.workers.get())),
            workers_spawned: AtomicU64::new(0),
            trampoline: Mutex::new(trampoline),
            config,
        })))
    }

    /// Checks that `source` compiles, and returns it as a filter to evaluate.
    ///
    /// Compiling runs in a worker, under the same limits as an evaluation: compiling hostile
    /// source can exhaust the stack just like running it.
    pub async fn compile(&self, source: &str) -> Result<Filter, Error> {
        self.check(source).await?;
        Ok(Filter(source.into()))
    }

    /// Checks that `source` compiles.
    pub async fn check(&self, source: &str) -> Result<(), Error> {
        let limit = self.0.config.max_filter_len;
        if exceeds(source.len(), limit) {
            return Err(Error::FilterTooLarge {
                len: source.len(),
                limit: limit.get(),
            });
        }

        let mut lease = Lease::new(&self.0).await?;
        let request = wire::encode_check(source);
        let stream = &mut lease.worker().stream;
        let exchange = async {
            stream.write_all(&request).await?;
            match stream.read_u8().await? {
                wire::VALID => Ok(Ok(())),
                wire::INVALID => Ok(Err(wire::read_message(stream).await?)),
                _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
            }
        };
        match timeout(self.0.config.wall_time, exchange).await {
            Ok(Ok(result)) => {
                lease.release();
                result.map_err(Error::InvalidFilter)
            }
            Ok(Err(_)) => Err(lease.died(false).await),
            Err(_) => Err(lease.died(true).await),
        }
    }

    /// Serializes `value` for evaluation. An input can be passed to any number of evaluations,
    /// concurrent ones included. It is read by filters as its JSON serialization.
    pub fn input<T: Serialize + ?Sized>(&self, value: &T) -> Result<Input, Error> {
        let limit = self.0.config.max_input_len;
        let json =
            serde_json::to_vec(value).map_err(|error| Error::InvalidInput(error.to_string()))?;
        if exceeds(json.len(), limit) {
            return Err(Error::InputTooLarge { limit: limit.get() });
        }
        Ok(Input(json.into()))
    }

    /// Runs `filter` on `input` and reports whether it matched: the filter's first boolean output
    /// decides, and a filter that outputs no boolean does not match.
    ///
    /// Dropping the returned future kills the worker it runs on.
    pub async fn evaluate(&self, filter: &Filter, input: &Input) -> Result<bool, Error> {
        self.evaluate_many(&[filter], input)
            .await
            .pop()
            .unwrap_or_else(|| {
                Err(Error::Unavailable(Arc::new(
                    io::ErrorKind::InvalidData.into(),
                )))
            })
    }

    /// Runs every filter on `input`, and reports each one's verdict as
    /// [`evaluate`](Self::evaluate) does, in the same order.
    ///
    /// The filters run one after another in one worker, which parses the input once for all of
    /// them. Each has its own CPU-time and wall-clock limits. A filter that kills its worker gets
    /// the error, and the filters after it go on on another worker.
    pub async fn evaluate_many(
        &self,
        filters: &[&Filter],
        input: &Input,
    ) -> Vec<Result<bool, Error>> {
        // An input made by another sandbox, with a larger limit.
        let limit = self.0.config.max_input_len;
        if exceeds(input.0.len(), limit) {
            return filters
                .iter()
                .map(|_| Err(Error::InputTooLarge { limit: limit.get() }))
                .collect();
        }

        let mut results = Vec::with_capacity(filters.len());
        while let Some(rest) = filters.get(results.len()..)
            && !rest.is_empty()
        {
            // As many filters as fit in one request, and at least one.
            let mut bytes = 0;
            let count = rest
                .iter()
                .take(wire::MAX_FILTERS)
                .take_while(|filter| {
                    bytes += filter.0.len();
                    bytes <= MAX_REQUEST_SOURCES
                })
                .count()
                .max(1);
            self.evaluate_some(rest.get(..count).unwrap_or_default(), input, &mut results)
                .await;
        }
        results
    }

    /// Runs `filters` on one worker, and pushes the results of the ones it got to, at least the
    /// first one, to `results`.
    async fn evaluate_some(
        &self,
        filters: &[&Filter],
        input: &Input,
        results: &mut Vec<Result<bool, Error>>,
    ) {
        let all = |results: &mut Vec<_>, error: Error| {
            results.extend(filters.iter().map(|_| Err(error.clone())));
        };
        let mut lease = match Lease::new(&self.0).await {
            Ok(lease) => lease,
            Err(error) => return all(results, error),
        };
        let wall_time = self.0.config.wall_time;
        let request = wire::encode_evaluate(&input.0, filters.iter().map(|filter| &*filter.0));
        let stream = &mut lease.worker().stream;

        // The wall clock restarts with every reply byte: each one means the worker made progress.
        let exchange = async {
            stream.write_all(&request).await?;
            stream.read_u8().await
        };
        match timeout(wall_time, exchange).await {
            Ok(Ok(wire::INPUT_OK)) => {}
            Ok(Ok(wire::INPUT_INVALID)) => {
                lease.release();
                return all(
                    results,
                    Error::InvalidInput("the input is not valid JSON".into()),
                );
            }
            // The input killed the worker, so it would kill it for every filter.
            Ok(_) => return all(results, lease.died(false).await),
            Err(_) => return all(results, lease.died(true).await),
        }

        for _ in filters {
            let stream = &mut lease.worker().stream;
            let result = match timeout(wall_time, stream.read_u8()).await {
                Ok(Ok(verdict::TRUE)) => Ok(true),
                Ok(Ok(verdict::FALSE)) => Ok(false),
                Ok(Ok(verdict::INVALID_FILTER)) => Err(Error::InvalidFilter(
                    "the worker could not compile the filter".to_owned(),
                )),
                Ok(_) => return results.push(Err(lease.died(false).await)),
                Err(_) => return results.push(Err(lease.died(true).await)),
            };
            results.push(result);
        }
        lease.release();
    }

    /// How many workers have been forked so far. Each one beyond the pool size replaced a worker
    /// that was killed, so a climbing rate means filters are hitting their limits.
    pub fn workers_spawned(&self) -> u64 {
        self.0.workers_spawned.load(Ordering::Relaxed)
    }
}

/// A permit, and the worker it lets an operation use.
///
/// An operation either gives the worker back with [`Lease::release`] or reports it dead with
/// [`Lease::died`]. Dropped with the worker still in it, because the caller stopped waiting in
/// the middle of an exchange, it kills the worker.
struct Lease {
    shared: Arc<Shared>,
    worker: Option<Worker>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Lease {
    async fn new(shared: &Arc<Shared>) -> Result<Self, Error> {
        let permit = shared
            .permits
            .clone()
            .acquire_owned()
            .await
            // The semaphore is never closed.
            .expect("the worker semaphore is closed");
        let worker = loop {
            match shared.idle().pop() {
                // Killed while idle, by something outside the sandbox such as the kernel's
                // out-of-memory killer. Dropping it reaps it.
                Some(worker) if worker.process.has_exited() => continue,
                Some(worker) => break worker,
                None => break shared.spawn()?,
            }
        };
        Ok(Self {
            shared: shared.clone(),
            worker: Some(worker),
            permit: Some(permit),
        })
    }

    fn worker(&mut self) -> &mut Worker {
        match &mut self.worker {
            Some(worker) => worker,
            None => unreachable!("a lease holds its worker until it is released"),
        }
    }

    /// Gives the worker back to the pool.
    fn release(mut self) {
        if let Some(worker) = self.worker.take() {
            self.shared.idle().push(worker);
        }
    }

    /// Kills the worker, which a dead worker does not notice, and turns the way it ended into
    /// the error of the operation that was running on it.
    async fn died(mut self, timed_out: bool) -> Error {
        let Some(worker) = self.worker.take() else {
            unreachable!("a lease holds its worker until it is released");
        };
        if let Err(error) = worker.process.kill() {
            return Error::Unavailable(error.into());
        }
        match worker.process.wait().await {
            Ok(status) => error_for(status, timed_out),
            Err(error) => Error::Unavailable(error.into()),
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let _ = worker.process.kill();
        let permit = self.permit.take();
        match Handle::try_current() {
            // Reaped without blocking. The permit is held until then, so that the pool never has
            // more processes than its size.
            Ok(runtime) => {
                runtime.spawn(async move {
                    let _ = worker.process.wait().await;
                    drop(permit);
                });
            }
            // Dropping the worker reaps it.
            Err(_) => drop(worker),
        }
    }
}

/// What a worker's end says about the operation that was running on it.
fn error_for(status: WaitStatus, timed_out: bool) -> Error {
    match status {
        WaitStatus::Signaled(_, CPU_TIME_SIGNAL, _) => Error::LimitExceeded(Limit::CpuTime),
        WaitStatus::Signaled(_, MEMORY_SIGNAL, _) => Error::LimitExceeded(Limit::Memory),
        WaitStatus::Signaled(_, STACK_SIGNAL, _) => Error::LimitExceeded(Limit::Stack),
        // The worker was still running when it was killed for taking too long.
        WaitStatus::Signaled(_, Signal::SIGKILL, _) if timed_out => {
            Error::LimitExceeded(Limit::WallTime)
        }
        // Includes a `SIGKILL` nobody here sent, such as the kernel's out-of-memory killer.
        WaitStatus::Signaled(_, signal, _) => Error::WorkerDied(format!("killed by {signal}")),
        WaitStatus::Exited(_, code) => Error::WorkerDied(format!("exited with code {code}")),
        other => Error::WorkerDied(format!("ended with {other:?}")),
    }
}

impl Shared {
    fn idle(&self) -> MutexGuard<'_, Vec<Worker>> {
        // Nothing that can panic runs while these locks are held, and what they guard stays
        // valid regardless.
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forks a worker. Blocks the thread for the fork, which is short.
    fn spawn(&self) -> Result<Worker, Error> {
        let (process, stream) = self
            .trampoline
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spawn()
            .map_err(Arc::new)
            .map_err(Error::Unavailable)?;
        self.workers_spawned.fetch_add(1, Ordering::Relaxed);
        // On failure, dropping `process` kills the worker.
        let stream = stream
            .set_nonblocking(true)
            .and_then(|()| UnixStream::from_std(stream))
            .map_err(Arc::new)
            .map_err(Error::Unavailable)?;
        Ok(Worker {
            process,
            stream: BufReader::new(stream),
        })
    }
}

/// Whether `len` is over `limit`.
fn exceeds(len: usize, limit: NonZeroU32) -> bool {
    usize::try_from(limit.get()).is_ok_and(|limit| len > limit)
}

/// Size in bytes of the mappings that `RLIMIT_DATA` is charged against.
fn data_size() -> io::Result<u64> {
    fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| line.strip_prefix("VmData:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kilobytes| kilobytes.parse::<u64>().ok())
        .map(|kilobytes| kilobytes * 1024)
        .ok_or_else(|| io::Error::other("no `VmData:` in /proc/self/status"))
}

impl fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sandbox")
            .field("config", &self.0.config)
            .finish_non_exhaustive()
    }
}

impl Filter {
    /// The filter's source.
    pub fn source(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Filter").field(&self.0).finish()
    }
}

impl Input {
    /// The input as JSON text.
    pub fn json(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Input")
            .field(&String::from_utf8_lossy(&self.0))
            .finish()
    }
}
