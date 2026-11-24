use std::time::Duration;

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
    pub workers: usize,

    /// CPU time one evaluation may consume, compiling the filter included.
    ///
    /// This is the worker's own CPU time, so an evaluation that is slow only because the host is
    /// busy does not hit it.
    pub cpu_time: Duration,

    /// Wall-clock time the service waits for a worker's answer before killing the worker.
    ///
    /// A backstop for a worker that is not burning CPU and still not answering, for example
    /// because it is stopped or the host is badly starved. The clock starts when the request is
    /// handed to a worker, so time spent waiting for a free worker does not count.
    pub wall_time: Duration,

    /// Heap memory in bytes a worker may allocate, the parsed input included.
    pub memory: u64,

    /// Stack size in bytes of a worker. Bounds recursion in the filter, in the compiler (deeply
    /// nested filter source), and in handling deeply nested values.
    pub stack: u64,

    /// Longest accepted filter source, in bytes.
    pub max_filter_len: usize,

    /// Longest accepted input, in bytes of its JSON serialization.
    pub max_input_len: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            workers: 4,
            cpu_time: Duration::from_millis(500),
            wall_time: Duration::from_secs(5),
            memory: 64 << 20,
            stack: 8 << 20,
            max_filter_len: 16 << 10,
            max_input_len: 4 << 20,
        }
    }
}
