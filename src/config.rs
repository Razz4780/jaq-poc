use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};

/// Limits applied to every evaluation, and the size of the worker pool.
///
/// The configuration is fixed when the sandbox is created: every worker is a copy of the process
/// as it was at that moment, so nothing set later reaches them.
#[derive(Debug, Clone)]
pub struct Config {
    /// How many worker processes may exist at once, which is also how many evaluations run
    /// concurrently. Further evaluations wait for a free worker.
    ///
    /// The container must have room for `workers * (memory + stack)` on top of the service
    /// itself: when a container's cgroup runs out of memory, the kubelet's default on cgroup v2
    /// is to kill every process in it, not only the worker that grew.
    ///
    /// Defaults to 2.
    pub workers: NonZeroUsize,

    /// CPU time one evaluation may consume, compiling the filter included.
    ///
    /// This is the worker's own CPU time, so an evaluation that is slow only because the host is
    /// busy does not hit it.
    ///
    /// Defaults to 250ms.
    pub cpu_time: Duration,

    /// Wall-clock time the service waits for a worker's answer before killing the worker.
    ///
    /// A backstop for a worker that is not burning CPU and still not answering, for example
    /// because it is stopped or the host is badly starved. The clock starts when the request is
    /// handed to a worker, so time spent waiting for a free worker does not count.
    ///
    /// Defaults to 2s.
    pub wall_time: Duration,

    /// Heap memory in bytes a worker may allocate, the parsed input included.
    ///
    /// Defaults to 32MiB.
    pub memory: NonZeroU64,

    /// Stack size in bytes of a worker. Bounds recursion in the filter, in the compiler (deeply
    /// nested filter source), and in handling deeply nested values.
    ///
    /// Defaults to 2MiB.
    pub stack: NonZeroU64,

    /// Longest accepted filter source, in bytes.
    ///
    /// Defaults to 4KiB.
    pub max_filter_len: NonZeroU32,

    /// Longest accepted input, in bytes of its JSON serialization.
    ///
    /// Defaults to 1MiB.
    pub max_input_len: NonZeroU32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            workers: NonZeroUsize::new(2).unwrap(),
            cpu_time: Duration::from_millis(250),
            wall_time: Duration::from_secs(2),
            memory: NonZeroU64::new(32 << 20).unwrap(),
            stack: NonZeroU64::new(2 << 20).unwrap(),
            max_filter_len: NonZeroU32::new(4 << 10).unwrap(),
            max_input_len: NonZeroU32::new(1 << 20).unwrap(),
        }
    }
}
