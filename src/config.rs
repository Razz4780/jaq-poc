use std::time::Duration;

/// Limits applied to every evaluation, and the size of the worker pool.
///
/// The configuration is fixed when the dispatcher is forked: the dispatcher and every worker are
/// copies of the process as it was at that moment, so nothing set later reaches them.
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

    /// Heap memory in bytes a worker may allocate, cached compiled filters included. The input
    /// arena is not part of it.
    pub memory: u64,

    /// Stack size in bytes of a worker. Bounds recursion in the filter, in the compiler (deeply
    /// nested filter source), and in handling deeply nested values.
    pub stack: u64,

    /// Longest accepted filter source, in bytes.
    pub max_filter_len: usize,

    /// Longest accepted input, in bytes of its encoding, which is about as long as its JSON.
    pub max_input_len: usize,

    /// Size in bytes of the memory shared with the workers that inputs are encoded into. Inputs
    /// that do not fit, because the arena is full of other live inputs, are copied to the worker
    /// with each evaluation instead.
    ///
    /// Pages are only allocated as inputs are written to them. The first 4 MiB stay resident once
    /// touched; pages beyond that are given back to the kernel when the input on them is freed.
    pub input_arena: usize,

    /// How long an idle worker polls its socket before it goes to sleep waiting for the next
    /// request. Zero by default.
    ///
    /// Waking a sleeping process is most of what an evaluation costs: on a 4-core VM, 50 µs of
    /// spinning cuts the latency of a small evaluation from about 55 to 42 µs, and nearly doubles
    /// throughput under load, because a busy worker then never sleeps between requests. The price
    /// is up to this much CPU time burned after every request when requests are sparse. The
    /// spinning is not counted against `cpu_time`.
    pub spin: Duration,
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
            input_arena: 32 << 20,
            spin: Duration::ZERO,
        }
    }
}
