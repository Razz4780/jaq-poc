# jq-sandbox

A proof of concept: evaluating untrusted [jq](https://jqlang.org/) filters on untrusted input inside a long-running
Linux service, with every evaluation bounded in CPU time, memory and stack, and unable to take the service down.

Filters are evaluated with [jaq](https://github.com/01mf02/jaq), in forked worker processes.

## Why

jaq states that it "does not take countermeasures against any kind of resource exhaustion", and it has no way to
interrupt a running filter. Evaluated in-process, a filter or the data it runs on can:

| Input | Effect on the process that evaluates it |
|---|---|
| `def f: f; f` | A thread spins forever. A timeout around it only stops waiting. |
| `[range(1e12)]` | Allocates until the process aborts or is OOM-killed. |
| `def f: 1 + f; f` | Overflows the stack, which aborts the whole process. |
| A few thousand nested parentheses | Overflows the stack in the compiler, so validating the filter is enough. |
| `fromjson` on a deeply nested string | Overflows the stack with a harmless filter and hostile data. |
| `halt` | Calls `std::process::exit` (jaq-std 2.x). |
| `env` | Returns the process's environment. |

None of this can be fixed from inside the process: a thread cannot be killed, a failed allocation aborts, and a stack
overflow cannot be caught. A process boundary handles all of it with one mechanism.

## Design

```text
                  control socket
  service  ---------------------------  dispatcher      forked first thing in `main`
     |      "spawn" / "release(pid)"         |
     |                                       | fork
     |           worker socket               v
     +--------------------------------   worker(s)      one evaluation at a time each
          filter + input / verdict
```

- **Dispatcher.** Forked at the very top of `main`, before the service starts any thread or loads anything. It stays
  single-threaded and does two things: fork a worker, and kill and reap one.
- **Workers.** Forks of the dispatcher, never `exec`ed. Each compiles and runs filters for the service over its own
  socket, one request at a time, and caches the filters it has compiled.
- **Service.** Keeps a pool of workers. A worker's socket is created by the dispatcher and the service's end is passed
  over the control socket with `SCM_RIGHTS`, so evaluations go from the service straight to the worker.

Why this shape:

- **Fork instead of exec** keeps workers cheap. A forked worker shares every page with the dispatcher until it writes
  to it, and costs about 0.45 MB of private memory. Re-executing a large service binary costs megabytes per worker
  before `main` runs, for the pages the dynamic loader relocates.
- **A dispatcher instead of forking the service** because `fork` is only safe in a single-threaded process, and
  because a worker forked from the running service would hold a copy of everything the service has in memory. The
  dispatcher is a snapshot of the process from before it had threads or secrets.
- **Only the dispatcher signals workers.** It is their parent and signals only pids it has not reaped, so a pid can
  never have been reused. `release(pid)` kills, reaps, and returns the wait status, which is also how the service
  learns why a worker died.

### Limits

All limits are enforced by the kernel on the worker process. The way a worker dies identifies the limit:

| Limit | Mechanism | Worker ends with | Reported as |
|---|---|---|---|
| CPU time | CPU-time timer armed around each evaluation | `SIGXCPU` | `Limit::CpuTime` |
| Memory | `RLIMIT_DATA`; the failed allocation aborts | `SIGABRT` | `Limit::Memory` |
| Stack | `RLIMIT_STACK`; the guard page faults | `SIGSEGV` | `Limit::Stack` |
| Wall clock | the service stops waiting and releases the worker | `SIGKILL` | `Limit::WallTime` |

The time limit that matters is **CPU time**, measured on the worker alone. A wall-clock timeout fires on a small filter
whenever the host is busy enough; a CPU-time limit does not, because it only counts time the filter actually ran. The
wall clock is kept as a loose backstop for a worker that neither answers nor burns CPU.

A worker also runs with an empty environment, `/dev/null` for its standard streams, no capabilities,
`PR_SET_NO_NEW_PRIVS`, and resource limits that stop it from opening files or starting processes. `halt` and
`halt_error` are replaced with builtins that raise a jq error, so that they do not cost a worker each time.

Compiling a filter is sandboxed exactly like running it: `Sandbox::check` exists so that validation does not happen
in the service.

## Usage

```rust
use jq_sandbox::{Config, Dispatcher};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before anything else: no thread may exist yet.
    let dispatcher = Dispatcher::fork(Config::default())?;

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let sandbox = dispatcher.connect()?;
        let message = serde_json::json!({"priority": "high"});

        sandbox.check(r#".priority == "high""#).await?;
        assert!(sandbox.evaluate(r#".priority == "high""#, &message).await?);
        Ok(())
    })
}
```

`evaluate` reports the filter's first boolean output; a filter that outputs no boolean does not match.
`Sandbox` is cheap to clone, and dropping the last clone stops the dispatcher and its workers.

To try a filter from the shell:

```sh
echo '{"priority": "high"}' | cargo run --example eval -- '.priority == "high"'   # true
echo '{}' | cargo run --example eval -- 'def f: f; f'       # jq evaluation exceeded its CPU time limit
echo '{}' | cargo run --example eval -- '[range(1e12)]'     # jq evaluation exceeded its memory limit
```

What the caller has to get right:

- **Fork first.** `Dispatcher::fork` refuses to run once the process has a second thread. `#[tokio::main]` builds the
  runtime before the function body, so `main` has to be a plain function that forks and then builds the runtime.
- **Leave room for the pool.** A container needs `workers * (memory + stack)` on top of the service. On cgroup v2 the
  kubelet kills every process in a container whose cgroup runs out of memory, so the per-worker limits must trip
  first.
- **Linux only.**

## Measurements

`cargo run --release --example bench`, on a 4-core x86_64 VM, 4 workers, with 256 MiB allocated on the service's heap
after the fork:

| | |
|---|---|
| Evaluation, filter already compiled in the worker | 82–98 µs p50, 145–185 µs p99 |
| Throughput with 4 workers | 38–43 k evaluations/s |
| First evaluation of a filter on a worker (compiles it) | 0.56 ms |
| First evaluation on a newly forked worker | 1.0 ms |
| Private memory per worker | 0.45 MB |
| Private memory of the dispatcher | 0.05 MB |

For scale, compiling a filter in-process takes about 0.4 ms and running a compiled one 3–9 µs. The round trip costs
more than the evaluation itself, and much less than compiling the filter for every evaluation.

## Tests

```sh
cargo test
```

`tests/sandbox.rs` is a plain `main` rather than a libtest harness, because the harness runs tests on threads and the
dispatcher must be forked before any exist. It covers:

- verdicts, invalid filters, size limits;
- every hostile filter above, each followed by an ordinary evaluation that must succeed;
- hostile input with a harmless filter;
- 200 concurrent evaluations, hostile ones mixed in, with the pool never exceeding its size;
- callers that give up mid-evaluation;
- a stopped worker (wall clock), and workers killed from outside while idle;
- a host with every core oversubscribed four times over: ordinary filters pass, a runaway one still hits its CPU limit;
- a service that dies abruptly: dispatcher and workers die with it;
- a service that forks too late: refused;
- shutdown leaving no process behind.

## Known gaps

- **Memory is limited through `RLIMIT_DATA`**, which counts address space the worker maps writable, not resident
  pages. It is a close proxy for the heap and needs no cooperation from the allocator, but it is not byte-exact.
- **`SIGABRT` is read as "memory limit"**, because a failed allocation is the only thing that aborts a worker: panics
  exit with their own code and a stack overflow is left to `SIGSEGV`.
- **No seccomp filter.** jaq's core forbids `unsafe` code, so the threat here is resource exhaustion rather than code
  execution, and the limits above cover that. A syscall allowlist would be cheap defence in depth.
- **Workers see UTC.** With an empty environment and no way to open files, `localtime` cannot read a time zone.
- **A lost dispatcher is not replaced.** It cannot be forked again once the service has threads; every evaluation
  then fails with `Error::Unavailable`.
- **The pool is a fixed size and never shrinks.** Workers are forked on demand and kept.
