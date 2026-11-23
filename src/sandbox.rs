//! The service's side: a pool of workers, the filters compiled on them, and the evaluations
//! handed to them.
//!
//! # Filters
//!
//! A [`Filter`] is compiled once, by [`Sandbox::compile`], and then lives for as long as the
//! service keeps the handle. Each worker compiles it the first time it runs it and keeps it until
//! told otherwise, so the source crosses to a worker once, and later evaluations only name it by
//! id. The service keeps a mirror of every worker's cache, so it always knows which filters to
//! send in full. When the last handle to a filter is dropped, each worker that has it is told to
//! forget it with its next request.
//!
//! A worker's cache is bounded by an estimate of its size, at a quarter of the worker's memory
//! limit: past that, the filters it ran least recently are forgotten. A filter compiles in
//! microseconds, so that costs little.
//!
//! # Inputs
//!
//! An [`Input`] is encoded once, by [`Sandbox::input`], into memory every worker can read, and any
//! number of evaluations on any workers can then use it without copying it.
//!
//! # Batches
//!
//! [`Sandbox::evaluate_many`] runs several filters on one input in a single round trip to one
//! worker, and the worker reads the input once for all of them. Each filter still gets its own
//! CPU-time budget. If one of them kills the worker, the verdicts reached before it stand, it
//! gets the error, and the filters after it go on on another worker.

use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt, io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream as StdUnixStream,
    },
    sync::{
        Arc, Mutex as StdMutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    sys::signal::Signal,
    unistd::Pid,
};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest, unix::AsyncFd},
    net::UnixStream,
    runtime::Handle,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot},
    time::timeout,
};

use crate::{
    Config, Dispatcher, Error, Limit,
    control::{self, Reply as ControlReply, Request as ControlRequest},
    dispatcher::Reaper,
    doc::{self, EncodeError},
    shm::{Arena, MAX_BATCH, Mapping, PAGE_LEN, Progress, Slot, verdict},
    wire::{self, FilterRef, InputAt, Reply},
    worker::{CPU_TIME_SIGNAL, MEMORY_SIGNAL, STACK_SIGNAL},
};

/// Evaluates jq filters in sandboxed worker processes.
///
/// Cheap to clone; all clones share one pool of workers. When the last clone is dropped, the
/// dispatcher and its workers are stopped.
#[derive(Clone)]
pub struct Sandbox(Arc<Shared>);

/// A compiled filter, see [`Sandbox::compile`]. Cheap to clone.
#[derive(Clone)]
pub struct Filter(Arc<FilterInner>);

struct FilterInner {
    /// Unique in the process, so that a filter compiled by one sandbox can be run by another.
    id: u64,
    source: Box<str>,
    sandbox: Weak<Shared>,
}

/// An encoded input, see [`Sandbox::input`]. Cheap to clone.
#[derive(Clone)]
pub struct Input(Arc<InputInner>);

enum InputInner {
    /// In the arena of the sandbox that encoded it.
    Arena(Slot),
    /// The arena had no room. Sent along with every evaluation.
    Inline(Box<[u8]>),
}

impl InputInner {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Arena(slot) => slot.bytes(),
            Self::Inline(bytes) => bytes,
        }
    }
}

static NEXT_FILTER_ID: AtomicU64 = AtomicU64::new(1);

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
    permits: Arc<Semaphore>,
    workers_spawned: AtomicU64,
    /// Which filters the workers hold, and which of those are no longer wanted.
    registry: StdMutex<Registry>,
    /// Bumped whenever a filter is retired, so that a worker only looks for filters to forget
    /// when there may be some.
    retired_generation: AtomicU64,
    /// Workers forked for a caller that went away before it could take them. Released with the
    /// next request to the dispatcher.
    orphans: StdMutex<Vec<Pid>>,
    arena: Arc<Arena>,
    _reaper: Reaper,
}

#[derive(Default)]
struct Registry {
    /// How many workers hold each filter.
    known_by: HashMap<u64, usize>,
    /// Filters whose last handle is gone and that some worker still holds.
    retired: HashSet<u64>,
}

impl Registry {
    fn learned(&mut self, id: u64) {
        *self.known_by.entry(id).or_default() += 1;
    }

    fn forgot(&mut self, id: u64) {
        if let Entry::Occupied(mut entry) = self.known_by.entry(id) {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove();
                self.retired.remove(&id);
            }
        }
    }
}

/// What the service knows about one filter a worker holds.
struct Known {
    cost: usize,
    last_used: u64,
}

struct Worker {
    pid: Pid,
    /// Service --requests--> worker, and the replies back.
    stream: UnixStream,
    progress: Progress,
    /// The part of a reply read so far.
    replies: Vec<u8>,
    /// Mirror of the worker's filter cache.
    known: HashMap<u64, Known>,
    known_cost: usize,
    /// Counts requests, to find the filters used least recently.
    clock: u64,
    retired_seen: u64,
}

/// How an exchange with a worker failed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The request could not be written, so the worker was dead before it saw the request.
    NotDelivered,
    /// The worker took the request and closed its socket without answering: it died over it.
    NoReply,
    /// The worker made no progress for the whole wall-clock limit.
    TimedOut,
}

/// A worker died over a request.
struct Death {
    error: Error,
    failure: Failure,
    /// How many filters of the request had started, the last of them the one it died over.
    started: usize,
    /// Verdicts of the filters that finished.
    verdicts: Vec<u8>,
}

/// How much of a worker's memory its cache of compiled filters may take, by [`filter_cost`].
fn cache_budget(config: &Config) -> usize {
    usize::try_from(config.memory / 4).unwrap_or(usize::MAX)
}

/// Estimated memory of a compiled filter in a worker. Compiled with the parts of jaq's library
/// it uses, a filter typically holds a few kilobytes, growing with its source.
fn filter_cost(source: &str) -> usize {
    8192 + 128 * source.len()
}

impl Worker {
    fn new(pid: Pid, socket: OwnedFd, progress: OwnedFd) -> io::Result<Self> {
        let progress = Progress::new(Mapping::new(progress.as_fd(), PAGE_LEN, true)?)?;
        let stream = StdUnixStream::from(socket);
        stream.set_nonblocking(true)?;
        Ok(Self {
            pid,
            stream: UnixStream::from_std(stream)?,
            progress,
            replies: Vec::new(),
            known: HashMap::new(),
            known_cost: 0,
            clock: 0,
            retired_seen: 0,
        })
    }

    /// Records that the worker holds `id`. Reports whether that is new.
    fn learn(&mut self, registry: &mut Registry, id: u64, cost: usize) -> bool {
        match self.known.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(Known {
                    cost,
                    last_used: self.clock,
                });
                self.known_cost += cost;
                registry.learned(id);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    fn forget(&mut self, registry: &mut Registry, id: u64) -> bool {
        match self.known.remove(&id) {
            Some(known) => {
                self.known_cost -= known.cost;
                registry.forgot(id);
                true
            }
            None => false,
        }
    }

    /// Updates the cache mirror for a request with `filters`, collects the ids the worker is to
    /// forget into `forget`, and returns, for each filter, whether its source must be sent.
    fn prepare(
        &mut self,
        shared: &Shared,
        filters: &[&FilterInner],
        forget: &mut Vec<u64>,
    ) -> Vec<bool> {
        forget.clear();
        self.clock += 1;
        let clock = self.clock;
        // Marked first, so that nothing this request uses is evicted below.
        let mut send = Vec::with_capacity(filters.len());
        for filter in filters {
            match self.known.get_mut(&filter.id) {
                Some(known) => {
                    known.last_used = clock;
                    send.push(false);
                }
                None => send.push(true),
            }
        }

        let generation = shared.retired_generation.load(Ordering::Acquire);
        if !send.contains(&true) && generation == self.retired_seen {
            return send;
        }
        let mut registry = shared.registry();
        if generation != self.retired_seen {
            let retired: Vec<u64> = self
                .known
                .keys()
                .filter(|id| registry.retired.contains(id))
                .take(wire::MAX_FORGET)
                .copied()
                .collect();
            // With more to forget than one request carries, the rest go with the next one.
            if retired.len() < wire::MAX_FORGET {
                self.retired_seen = generation;
            }
            for id in retired {
                self.forget(&mut registry, id);
                forget.push(id);
            }
        }
        for (filter, send) in filters.iter().zip(&mut send) {
            // A filter listed twice is sent in full only the first time.
            if *send && !self.learn(&mut registry, filter.id, filter_cost(&filter.source)) {
                *send = false;
            }
        }
        let budget = cache_budget(&shared.config);
        while self.known_cost > budget && forget.len() < wire::MAX_FORGET {
            let oldest = self
                .known
                .iter()
                .filter(|(_, known)| known.last_used < clock)
                .min_by_key(|(_, known)| known.last_used)
                .map(|(id, _)| *id);
            let Some(oldest) = oldest else { break };
            self.forget(&mut registry, oldest);
            forget.push(oldest);
        }
        send
    }

    async fn send(&mut self, request: &[u8]) -> io::Result<()> {
        self.stream.write_all(request).await
    }

    /// Reads the next reply. Cancel safe: what was read so far is kept for the next call.
    async fn receive(&mut self) -> io::Result<Reply> {
        loop {
            if let Some(reply) = Reply::take(&mut self.replies)? {
                return Ok(reply);
            }
            if self.stream.read_buf(&mut self.replies).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Waits for the reply for as long as the worker keeps making progress: the wall clock is
    /// the limit of each filter in the request, not of the whole request.
    async fn receive_within(&mut self, wall_time: Duration) -> Result<Reply, Failure> {
        // The service resets the page before each request, and the first filter starting is
        // not progress yet.
        let mut seen = 1;
        loop {
            match timeout(wall_time, self.receive()).await {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(_)) => return Err(Failure::NoReply),
                Err(_) => {
                    let started = self.progress.started();
                    if started <= seen {
                        return Err(Failure::TimedOut);
                    }
                    seen = started;
                }
            }
        }
    }
}

/// State of a worker that an operation has taken from the pool.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Between requests: the worker can go back to the pool as it is.
    Idle,
    /// A request is being written. If that is cut short, the worker's stream is unusable.
    Sending,
    /// The request is written and the reply is not read yet.
    Waiting,
}

/// A permit, and the worker it lets an operation use.
///
/// Dropped in the middle of an exchange, because the caller stopped waiting, it finishes the
/// exchange in a task of its own: the worker either answers and goes back to the pool, or dies
/// and is released. Nothing is spawned on the normal path.
struct Busy {
    shared: Arc<Shared>,
    worker: Option<Worker>,
    state: State,
    permit: Option<OwnedSemaphorePermit>,
    /// Keeps the input's slot from being reused while a worker may be reading it.
    input: Option<Input>,
}

impl Busy {
    async fn new(shared: &Arc<Shared>, input: Option<Input>) -> Self {
        let permit = shared
            .permits
            .clone()
            .acquire_owned()
            .await
            // The semaphore is never closed.
            .expect("the worker semaphore is closed");
        Self {
            shared: shared.clone(),
            worker: None,
            state: State::Idle,
            permit: Some(permit),
            input,
        }
    }

    /// The worker to use next, from the pool if one is idle. Reports whether it came from the
    /// pool, and could have died there unnoticed.
    async fn worker(&mut self) -> Result<(&mut Worker, bool), Error> {
        let pooled = match self.worker {
            Some(_) => true,
            None => {
                let idle = self.shared.idle().pop();
                let pooled = idle.is_some();
                let worker = match idle {
                    Some(worker) => worker,
                    None => self.shared.spawn().await?,
                };
                self.worker = Some(worker);
                pooled
            }
        };
        match &mut self.worker {
            Some(worker) => Ok((worker, pooled)),
            None => unreachable!("a worker was just put in place"),
        }
    }

    async fn exchange(&mut self, request: &[u8]) -> Result<Reply, Death> {
        let wall_time = self.shared.config.wall_time;
        let Some(worker) = &mut self.worker else {
            unreachable!("`exchange` is called with a worker in place");
        };
        worker.progress.reset();

        self.state = State::Sending;
        if worker.send(request).await.is_err() {
            return Err(self.died(Failure::NotDelivered).await);
        }
        self.state = State::Waiting;
        match worker.receive_within(wall_time).await {
            Ok(reply) => {
                self.state = State::Idle;
                Ok(reply)
            }
            Err(failure) => Err(self.died(failure).await),
        }
    }

    async fn died(&mut self, failure: Failure) -> Death {
        self.state = State::Idle;
        let Some(worker) = self.worker.take() else {
            unreachable!("only a worker in place can die");
        };
        let started = worker.progress.started().min(MAX_BATCH);
        let verdicts = (0..started.saturating_sub(1))
            .map(|index| {
                worker
                    .progress
                    .verdict(index)
                    .unwrap_or(verdict::INVALID_FILTER)
            })
            .collect();
        let error = self
            .shared
            .release(worker, failure == Failure::TimedOut)
            .await;
        Death {
            error,
            failure,
            started,
            verdicts,
        }
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let Some(mut worker) = self.worker.take() else {
            return;
        };
        if self.state == State::Idle {
            self.shared.idle().push(worker);
            return;
        }

        let Ok(runtime) = Handle::try_current() else {
            // Nothing can wait for the worker here. The dispatcher kills it with the next
            // request it gets.
            self.shared.discard_known(&mut worker);
            self.shared.orphans().push(worker.pid);
            return;
        };
        let shared = self.shared.clone();
        let state = self.state;
        let permit = self.permit.take();
        let input = self.input.take();
        runtime.spawn(async move {
            let _held_until_done = (permit, input);
            if state == State::Waiting
                && worker.receive_within(shared.config.wall_time).await.is_ok()
            {
                shared.idle().push(worker);
            } else {
                let _ = shared.release(worker, false).await;
            }
        });
    }
}

impl Sandbox {
    pub(crate) fn new(dispatcher: Dispatcher) -> io::Result<Self> {
        let Dispatcher {
            control,
            reaper,
            config,
            arena,
        } = dispatcher;
        // `control` moves into the call, so on failure it is closed by the time `reaper` is
        // dropped and waits for the dispatcher to exit.
        let control = register(control)?;

        Ok(Self(Arc::new(Shared {
            permits: Arc::new(Semaphore::new(config.workers)),
            config,
            control: Mutex::new(control),
            idle: StdMutex::default(),
            workers_spawned: AtomicU64::new(0),
            registry: StdMutex::default(),
            retired_generation: AtomicU64::new(0),
            orphans: StdMutex::default(),
            arena: Arc::new(Arena::new(arena)),
            _reaper: reaper,
        })))
    }

    /// Compiles `source` into a filter that can be evaluated any number of times.
    ///
    /// Compiling runs in a worker, under the same limits as an evaluation: compiling hostile
    /// source can exhaust the stack just like running it. The worker keeps the result, and the
    /// other workers compile the filter the first time they run it.
    pub async fn compile(&self, source: &str) -> Result<Filter, Error> {
        self.check_len(source)?;
        // Made first, so that if the caller stops waiting, dropping it retires the filter on the
        // worker that compiled it.
        let filter = Filter(Arc::new(FilterInner {
            id: NEXT_FILTER_ID.fetch_add(1, Ordering::Relaxed),
            source: source.into(),
            sandbox: Arc::downgrade(&self.0),
        }));
        self.check_as(Some(&filter.0), source).await?;
        Ok(filter)
    }

    /// Checks that `source` compiles, without keeping the result.
    pub async fn check(&self, source: &str) -> Result<(), Error> {
        self.check_len(source)?;
        self.check_as(None, source).await
    }

    /// Encodes `value` for evaluation. Encoded once, an input can be passed to any number of
    /// evaluations, concurrent ones included.
    ///
    /// `value` is serialized directly, without building a `serde_json::Value` first. It is read
    /// by filters as its JSON serialization would be: structs and maps are objects, sequences
    /// are arrays, enums follow serde's externally tagged representation.
    pub fn input<T: Serialize + ?Sized>(&self, value: &T) -> Result<Input, Error> {
        thread_local! {
            static SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
        }
        let limit = self.0.config.max_input_len;
        SCRATCH.with_borrow_mut(|scratch| {
            let encoded = doc::encode(value, limit, scratch);
            let input = encoded.map(|()| match self.0.arena.alloc(scratch) {
                Some(slot) => InputInner::Arena(slot),
                None => InputInner::Inline(scratch.as_slice().into()),
            });
            // Not kept around at the size of the largest input this thread ever encoded.
            if scratch.capacity() > 1 << 20 {
                *scratch = Vec::new();
            }
            match input {
                Ok(input) => Ok(Input(Arc::new(input))),
                Err(EncodeError::TooLarge) => Err(Error::InputTooLarge { limit }),
                Err(EncodeError::Invalid(message)) => Err(Error::InvalidInput(message)),
            }
        })
    }

    /// Runs `filter` on `input` and reports whether it matched: the filter's first boolean output
    /// decides, and a filter that outputs no boolean does not match.
    ///
    /// The evaluation is not cancelled when the returned future is dropped. It runs to its
    /// verdict or to one of its limits either way, and its worker goes back to the pool.
    pub async fn evaluate(&self, filter: &Filter, input: &Input) -> Result<bool, Error> {
        self.evaluate_many(&[filter], input)
            .await
            .pop()
            .unwrap_or_else(|| Err(Error::Unavailable(io::ErrorKind::InvalidData.into())))
    }

    /// Runs every filter on `input`, and reports each one's verdict as
    /// [`evaluate`](Self::evaluate) does, in the same order.
    ///
    /// The filters run one after another in one worker, which reads the input once for all of
    /// them, in a single round trip. Each has its own CPU-time and wall-clock limits. A filter
    /// that kills its worker gets the error, and does not affect the others.
    pub async fn evaluate_many(
        &self,
        filters: &[&Filter],
        input: &Input,
    ) -> Vec<Result<bool, Error>> {
        let shared = &self.0;
        let mut results: Vec<Option<Result<bool, Error>>> = std::iter::repeat_with(|| None)
            .take(filters.len())
            .collect();
        if filters.is_empty() {
            return Vec::new();
        }

        let (input_at, inline) = match &*input.0 {
            InputInner::Arena(slot) if slot.is_in(&shared.arena) => (
                InputAt::Arena {
                    offset: slot.offset(),
                    len: slot.len(),
                },
                &[][..],
            ),
            other => {
                let bytes = other.bytes();
                (InputAt::Inline { len: bytes.len() }, bytes)
            }
        };

        // An input encoded by another sandbox, with a larger limit.
        let limit = shared.config.max_input_len;
        if inline.len() > limit {
            return std::iter::repeat_with(|| Err(Error::InputTooLarge { limit }))
                .take(filters.len())
                .collect();
        }

        let mut busy = Busy::new(shared, Some(input.clone())).await;
        // Indices of the filters without a verdict yet, in order.
        let mut pending: Vec<usize> = (0..filters.len()).collect();
        let (mut request, mut forget) = (Vec::new(), Vec::new());

        while !pending.is_empty() {
            let (worker, pooled) = match busy.worker().await {
                Ok(worker) => worker,
                Err(error) => {
                    for &index in &pending {
                        set(&mut results, index, Err(error.duplicate()));
                    }
                    break;
                }
            };
            // As many filters as one request carries, and no more distinct ones than the worker
            // can keep compiled at once.
            let budget = cache_budget(&shared.config);
            let (mut chunk, mut distinct, mut cost) = (Vec::new(), HashSet::new(), 0);
            for filter in pending.iter().filter_map(|&index| filters.get(index)) {
                let filter = &*filter.0;
                if distinct.insert(filter.id) {
                    cost += filter_cost(&filter.source);
                }
                if chunk.len() == MAX_BATCH || (cost > budget && !chunk.is_empty()) {
                    break;
                }
                chunk.push(filter);
            }
            let send = worker.prepare(shared, &chunk, &mut forget);
            let refs = chunk.iter().zip(&send).map(|(filter, send)| FilterRef {
                id: filter.id,
                source: send.then_some(&*filter.source),
            });
            wire::encode_evaluate(&mut request, input_at, inline, &forget, refs);

            match busy.exchange(&request).await {
                Ok(reply) => {
                    let progress = match (&reply, &busy.worker) {
                        (Reply::Evaluated, Some(worker)) => Some(&worker.progress),
                        _ => None,
                    };
                    for (position, &index) in pending.iter().take(chunk.len()).enumerate() {
                        set(
                            &mut results,
                            index,
                            match progress.map(|p| p.verdict(position)) {
                                Some(Some(verdict::TRUE)) => Ok(true),
                                Some(Some(verdict::FALSE)) => Ok(false),
                                Some(_) => Err(Error::InvalidFilter(
                                    "the worker could not compile the filter".to_owned(),
                                )),
                                None => Err(unexpected(&reply)),
                            },
                        );
                    }
                    pending.drain(..chunk.len());
                }
                // A worker from the pool that died while idle, killed by something outside the
                // sandbox. That is not this evaluation's doing, so it gets another worker. A
                // worker forked for this very request is not retried, which bounds the loop.
                Err(death) if death.failure == Failure::NotDelivered && pooled => {
                    if let Error::Unavailable(error) = death.error {
                        for &index in &pending {
                            set(
                                &mut results,
                                index,
                                Err(Error::Unavailable(error.duplicate_io())),
                            );
                        }
                        break;
                    }
                }
                Err(death) => {
                    let resolved = match death.started.min(chunk.len()) {
                        // Died before it started any filter: every one of them gets the error.
                        0 => chunk.len(),
                        started => started,
                    };
                    for (position, &index) in pending.iter().take(resolved).enumerate() {
                        let verdict = death.verdicts.get(position).copied();
                        set(
                            &mut results,
                            index,
                            match verdict {
                                Some(verdict::TRUE) => Ok(true),
                                Some(verdict::FALSE) => Ok(false),
                                _ => Err(death.error.duplicate()),
                            },
                        );
                    }
                    pending.drain(..resolved);
                }
            }
        }

        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| Err(Error::Unavailable(io::ErrorKind::Interrupted.into())))
            })
            .collect()
    }

    /// How many workers have been forked so far. Each one beyond the pool size replaced a worker
    /// that was killed, so a climbing rate means filters are hitting their limits.
    pub fn workers_spawned(&self) -> u64 {
        self.0.workers_spawned.load(Ordering::Relaxed)
    }

    fn check_len(&self, source: &str) -> Result<(), Error> {
        let limit = self.0.config.max_filter_len;
        if source.len() > limit {
            return Err(Error::FilterTooLarge {
                len: source.len(),
                limit,
            });
        }
        Ok(())
    }

    /// Compiles `source` on a worker, which keeps it as `filter` if there is one.
    async fn check_as(&self, filter: Option<&FilterInner>, source: &str) -> Result<(), Error> {
        let shared = &self.0;
        let mut request = Vec::new();
        wire::encode_check(&mut request, filter.map_or(0, |filter| filter.id), source);
        let mut busy = Busy::new(shared, None).await;
        loop {
            let (worker, pooled) = busy.worker().await?;
            // Recorded before sending: if the caller stops waiting, the dropped handle retires
            // the filter, and the worker is told to forget it.
            if let Some(filter) = filter {
                worker.learn(&mut shared.registry(), filter.id, filter_cost(source));
            }
            match busy.exchange(&request).await {
                Ok(Reply::Valid) => return Ok(()),
                Ok(Reply::InvalidFilter(message)) => {
                    if let (Some(filter), Some(worker)) = (filter, &mut busy.worker) {
                        worker.forget(&mut shared.registry(), filter.id);
                    }
                    return Err(Error::InvalidFilter(message));
                }
                Ok(reply) => return Err(unexpected(&reply)),
                Err(death) if death.failure == Failure::NotDelivered && pooled => {
                    if let Error::Unavailable(error) = death.error {
                        return Err(Error::Unavailable(error));
                    }
                }
                Err(death) => return Err(death.error),
            }
        }
    }
}

fn set<T>(slots: &mut [Option<T>], index: usize, value: T) {
    if let Some(slot) = slots.get_mut(index) {
        *slot = Some(value);
    }
}

trait DuplicateIo {
    fn duplicate_io(&self) -> io::Error;
}

impl DuplicateIo for io::Error {
    fn duplicate_io(&self) -> io::Error {
        io::Error::new(self.kind(), self.to_string())
    }
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
        &self.0.source
    }
}

impl fmt::Debug for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Filter").field(&self.0.source).finish()
    }
}

impl Drop for FilterInner {
    fn drop(&mut self) {
        if let Some(shared) = self.sandbox.upgrade() {
            let mut registry = shared.registry();
            if registry.known_by.contains_key(&self.id) {
                registry.retired.insert(self.id);
                shared.retired_generation.fetch_add(1, Ordering::Release);
            }
        }
    }
}

impl Input {
    /// Length of the encoded input in bytes.
    pub fn len(&self) -> usize {
        self.0.bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Input")
            .field("len", &self.len())
            .field("shared", &matches!(&*self.0, InputInner::Arena(_)))
            .finish()
    }
}

/// A reply that does not answer the request that was sent, which a worker never produces.
fn unexpected(reply: &Reply) -> Error {
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
    fn idle(&self) -> MutexGuard<'_, Vec<Worker>> {
        // Nothing that can panic runs while these locks are held, and what they guard stays
        // valid regardless.
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn orphans(&self) -> MutexGuard<'_, Vec<Pid>> {
        self.orphans.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One request to the dispatcher and its reply, in a task of its own: a caller that stops
    /// waiting cannot cut the conversation short between the two.
    async fn control(
        self: &Arc<Self>,
        request: ControlRequest,
    ) -> io::Result<(ControlReply, Vec<OwnedFd>)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let shared = self.clone();
        tokio::spawn(async move {
            let reply = shared.call(request).await;
            if let Err(Ok((ControlReply::Spawned(pid), _))) = reply_tx.send(reply) {
                // Forked for a caller that is gone.
                shared.orphans().push(pid);
            }
        });
        reply_rx
            .await
            .unwrap_or_else(|_| Err(io::Error::other("the jq sandbox is shutting down")))
    }

    async fn call(&self, request: ControlRequest) -> io::Result<(ControlReply, Vec<OwnedFd>)> {
        let control = self.control.lock().await;
        let orphans = std::mem::take(&mut *self.orphans());
        for pid in orphans {
            Self::round_trip(&control, ControlRequest::Release(pid)).await?;
        }
        Self::round_trip(&control, request).await
    }

    async fn round_trip(
        control: &AsyncFd<OwnedFd>,
        request: ControlRequest,
    ) -> io::Result<(ControlReply, Vec<OwnedFd>)> {
        control
            .async_io(Interest::WRITABLE, |socket| {
                control::send(socket.as_fd(), request.encode(), &[])
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

    async fn spawn(self: &Arc<Self>) -> Result<Worker, Error> {
        let (pid, socket, progress) = match self.control(ControlRequest::Spawn).await {
            Ok((ControlReply::Spawned(pid), attached)) => {
                let mut attached = attached.into_iter();
                match (attached.next(), attached.next()) {
                    (Some(socket), Some(progress)) => (pid, socket, progress),
                    _ => {
                        self.orphans().push(pid);
                        return Err(Error::Unavailable(io::ErrorKind::InvalidData.into()));
                    }
                }
            }
            Ok((ControlReply::Failed(errno), _)) => return Err(Error::Unavailable(errno.into())),
            Ok(_) => return Err(Error::Unavailable(io::ErrorKind::InvalidData.into())),
            Err(error) => return Err(Error::Unavailable(error)),
        };
        self.workers_spawned.fetch_add(1, Ordering::Relaxed);

        match Worker::new(pid, socket, progress) {
            Ok(worker) => Ok(worker),
            Err(error) => {
                // The worker exists but cannot be talked to; do not leave it behind.
                let _ = self.control(ControlRequest::Release(pid)).await;
                Err(Error::Unavailable(error))
            }
        }
    }

    /// Has the dispatcher kill and reap `worker`, and turns the way the worker ended into the
    /// error of the evaluation that was running on it.
    /// Takes the filters a worker holds off the registry, as the worker is going away.
    fn discard_known(&self, worker: &mut Worker) {
        let mut registry = self.registry();
        let known: Vec<u64> = worker.known.keys().copied().collect();
        for id in known {
            worker.forget(&mut registry, id);
        }
    }

    async fn release(self: &Arc<Self>, mut worker: Worker, timed_out: bool) -> Error {
        self.discard_known(&mut worker);
        let Worker { pid, stream, .. } = worker;
        drop(stream);
        let reply = match self.control(ControlRequest::Release(pid)).await {
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
