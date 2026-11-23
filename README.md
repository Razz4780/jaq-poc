# jq-sandbox

A proof of concept: evaluating untrusted [jq](https://jqlang.org/) filters on untrusted input inside a long-running
Linux service, with every evaluation bounded in CPU time, memory and stack, and unable to take the service down.

Filters are evaluated with [jaq](https://github.com/01mf02/jaq) 3, in forked worker processes. Filters are
long-lived: compiled once and evaluated as often as needed. Inputs are encoded once into memory every worker can
read, and can go to any number of filters, in one round trip.

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
     +--------------------------------   worker(s)      one request at a time each
     |      filter ids / "done"              ^
     |                                       | read-only
     +-------- input arena (shared memory) --+
```

- **Dispatcher.** Forked at the very top of `main`, before the service starts any thread or loads anything. It
  stays single-threaded and does two things: fork a worker, and kill and reap one.
- **Workers.** Forks of the dispatcher, never `exec`ed. Each compiles and runs filters for the service over its own
  socket, one request at a time, and keeps every filter it compiles until the service tells it to forget it.
- **Service.** Keeps a pool of workers. A worker's socket is created by the dispatcher and the service's end is passed
  over the control socket with `SCM_RIGHTS`, so evaluations go from the service straight to the worker.
- **Input arena.** A `memfd` created before the dispatcher is forked. The service maps it read-write and encodes
  inputs into it; the dispatcher maps it read-only, through a read-only descriptor, so every worker inherits a view
  it cannot make writable.

Why this shape:

- **Fork instead of exec** keeps workers cheap. A forked worker shares every page with the dispatcher until it writes
  to it, and costs about 0.2 MB of private memory. Re-executing a large service binary costs megabytes per worker
  before `main` runs, for the pages the dynamic loader relocates.
- **A dispatcher instead of forking the service** because `fork` is only safe in a single-threaded process, and
  because a worker forked from the running service would hold a copy of everything the service has in memory. The
  dispatcher is a snapshot of the process from before it had threads or secrets.
- **Only the dispatcher signals workers.** It is their parent and signals only pids it has not reaped, so a pid can
  never have been reused. `release(pid)` kills, reaps, and returns the wait status, which is also how the service
  learns why a worker died.

### Filters

`Sandbox::compile` returns a `Filter`, a handle with a process-wide id. Every worker can run every filter: it compiles
a filter the first time it is asked to run it, and keeps it. The service mirrors each worker's cache, so the source
crosses to a worker once, and every later request names the filter by id. When the last handle to a filter is
dropped, each worker holding it is told to forget it with its next request.

Caching every filter in every worker is affordable because a filter is compiled with only the part of jaq's library
it can reach. jaq compiles its whole library, some 200 definitions and as many natives, into every filter: 0.4 ms and
110 kB for `.a == 1`. The worker over-approximates what a filter can reach by name (every word in its source, then
everything those definitions call, any arity) and compiles only that: a few microseconds and about 10 kB. Everything
sharing a name with something reachable is kept, in order, so calls resolve exactly as with the whole library; a name
the approximation missed cannot resolve to something else, it fails to compile, and the filter is then compiled
against the whole library. A worker's cache is bounded by an estimate of its size, a quarter of its memory limit,
past which the filters it ran least recently are forgotten.

The dispatcher parses jaq's library once before forking any worker, so workers start with it.

### Inputs

`Sandbox::input` serializes any `serde::Serialize` value, with no `serde_json::Value` in between, into a compact
binary encoding written to the arena. A worker reads it where it lies: every container records its size, so a reader
steps over what it does not need, and `.headers["x-user"]` on a megabyte of message touches a few cache lines.

Filters run on a value type of their own. It is either a position in the encoded input or a value jaq built
(jaq-json's `Val`). Reading the input stays on the first kind: indexing, iterating, comparing strings and numbers,
`length`, `has`. Every other operation builds the part of the input it needs as a `Val` and calls jaq-json's
implementation, so semantics are jaq's. A differential test runs about 150 filters on several inputs through both
this and plain jaq on parsed JSON and requires identical outputs, errors included.

An input lives in the arena for as long as a handle to it exists, and any number of evaluations on any workers read
it without a copy. An input that does not fit, because the arena is full of live inputs, is sent along with each
evaluation instead.

Why not rkyv: an archived value would still need a jaq value type around it, which is the bulk of the work. rkyv's
validation is a pass over the whole buffer, or `unsafe` access without it, where here every read is bounds-checked
and malformed data reads as `null`. And it has no serializer from arbitrary `serde` types, so inputs would be built
twice.

### Batches

`Sandbox::evaluate_many` sends several filters with one input to one worker, which reads the input once and runs
the filters one after another. Each filter gets its own CPU-time budget and wall-clock limit. The worker records in
a page of memory shared with the service which filter it is running and the verdicts so far. When it dies, the
verdicts before the culprit stand, the culprit gets the error, and the filters after it go on on another worker.

### Limits

All limits are enforced by the kernel on the worker process. The way a worker dies identifies the limit:

| Limit | Mechanism | Worker ends with | Reported as |
|---|---|---|---|
| CPU time | CPU-time timer armed around each filter | `SIGXCPU` | `Limit::CpuTime` |
| Memory | `RLIMIT_DATA`; the failed allocation aborts | `SIGABRT` | `Limit::Memory` |
| Stack | `RLIMIT_STACK`; the guard page faults | `SIGSEGV` | `Limit::Stack` |
| Wall clock | the service stops waiting and releases the worker | `SIGKILL` | `Limit::WallTime` |

In a batch, the wall clock restarts whenever the worker moves on to the next filter.

The time limit that matters is **CPU time**, measured on the worker alone. A wall-clock timeout fires on a small filter
whenever the host is busy enough; a CPU-time limit does not, because it only counts time the filter actually ran. The
wall clock is kept as a loose backstop for a worker that neither answers nor burns CPU.

A worker also runs with an empty environment, `/dev/null` for its standard streams, no capabilities,
`PR_SET_NO_NEW_PRIVS`, and resource limits that stop it from opening files or starting processes. In jaq 3 `halt` no
longer exits the process; it ends the filter's output like an error. `input` and `inputs` produce nothing.

Compiling a filter is sandboxed exactly like running it: `Sandbox::compile` and `Sandbox::check` run in a worker, so
that validation does not happen in the service.

## Usage

```rust
use jq_sandbox::{Config, Dispatcher};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before anything else: no thread may exist yet.
    let dispatcher = Dispatcher::fork(Config::default())?;

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let sandbox = dispatcher.connect()?;
        // Once per session.
        let high = sandbox.compile(r#".priority == "high""#).await?;
        let acme = sandbox.compile(r#".tenant | startswith("ac")"#).await?;

        // Once per message, from any `Serialize` type.
        let message = sandbox.input(&serde_json::json!({"priority": "high", "tenant": "acme"}))?;
        assert!(sandbox.evaluate(&high, &message).await?);
        let verdicts = sandbox.evaluate_many(&[&high, &acme], &message).await;
        assert!(verdicts.into_iter().all(|verdict| matches!(verdict, Ok(true))));
        Ok(())
    })
}
```

`evaluate` reports the filter's first boolean output; a filter that outputs no boolean does not match.
`Sandbox`, `Filter` and `Input` are cheap to clone, and dropping the last `Sandbox` clone stops the dispatcher and its
workers. A `Filter` or `Input` from one sandbox works with another; the input is then copied with each evaluation.

To try a filter from the shell:

```sh
echo '{"priority": "high"}' | cargo run --example eval -- '.priority == "high"'   # true
echo '{}' | cargo run --example eval -- 'def f: f; f'       # jq evaluation exceeded its CPU time limit
echo '{}' | cargo run --example eval -- '[range(1e12)]'     # jq evaluation exceeded its memory limit
```

What the caller has to get right:

- **Fork first.** `Dispatcher::fork` refuses to run once the process has a second thread. `#[tokio::main]` builds the
  runtime before the function body, so `main` has to be a plain function that forks and then builds the runtime.
- **Leave room for the pool.** A container needs `workers * (memory + stack)` on top of the service, plus the pages of
  the input arena in use (at most `input_arena`; the first 4 MiB stay resident once touched). On cgroup v2 the
  kubelet kills every process in a container whose cgroup runs out of memory, so the per-worker limits must trip
  first.
- **Linux only.**

## Measurements

`cargo run --release --example bench`, on a 4-core x86_64 VM, 4 workers, with 256 MiB allocated on the service's heap
after the fork. "Before" is the previous version of this crate (jaq 2, filter source and JSON text sent with every
evaluation, each evaluation in a task of its own), measured on the same scenarios.

| | before | now |
|---|---|---|
| One small evaluation, filter compiled, p50 / p99 | 92 µs / 162 µs | 55 µs / 103 µs |
| Same, with `Config::spin` = 50 µs | | 44 µs / 95 µs |
| One small message, 10 filters, p50 | 1.0 ms (one by one) | 83 µs (one batch) |
| Throughput, one filter per message | 41 k/s | 42 k/s (79 k/s with spin) |
| Throughput, 10 filters per message | 4.5 k messages/s | 31 k messages/s (37 k with spin) |
| 5.7 kB input (100 objects), `.headers["x-user"] == "michal"` | 331 µs | 10 µs encode + 69 µs |
| 630 kB input (10 k objects), same filter | 20.8 ms | 1.1 ms encode + 0.19 ms |
| 900 kB input (one long string), same filter | 1.6 ms | 0.11 ms encode + 0.11 ms |
| 630 kB input, `.items \| map(.price) \| add > 0` | 27.9 ms | 8.8 ms |
| New filter, compiled and evaluated once | 0.62 ms | 0.14 ms |
| First evaluation on a newly forked worker | 1.07 ms | 0.38 ms |
| Private memory per idle worker | 0.45 MB | 0.18 MB |
| Private memory per cached filter | ~110 kB | ~10 kB |

Where the time goes now: running a compiled filter on a small input takes 1–2 µs, and a raw round trip between two
processes blocking on a Unix socket takes 23 µs on this VM. The rest of the 55 µs is waking tokio tasks across
threads. `Config::spin` trades CPU for some of that: an idle worker polls its socket for that long before it sleeps,
so a busy worker never sleeps between requests. It costs up to that much CPU per request when requests are sparse,
which is why it is off by default.

## Tests

```sh
cargo test
```

The unit tests cover the input encoding, the wire format, the arena, and the differential test of the value type
against plain jaq. `tests/sandbox.rs` is a plain `main` rather than a libtest harness, because the harness runs tests
on threads and the dispatcher must be forked before any exist. It covers:

- verdicts, invalid filters, size limits;
- batches with a runaway filter in the middle, large batches, typed (`serde`) inputs shared by concurrent
  evaluations, filter turnover, batches larger than a worker's cache, handles used across sandboxes, a full arena;
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
- **One request per worker at a time.** A worker sleeps between replying and its next request unless `spin` is set.
  Pipelining a second request behind the first would keep workers busy without spinning, at the cost of a reply
  demultiplexer per worker.
- **An input is copied once into the arena** after it is encoded, rather than encoded straight into it, because its
  size is not known in advance.
- **Lookups in large objects and arrays are linear.** Containers record their size, not an index, so `.[5000]` steps
  over 5000 elements. An offset table for large containers would make it constant.
- **jaq 3.** mirrord's `mirrord-jaq` crate, which validates filters in the CLI, is on jaq 2.2. The two should move
  together, so that a filter the CLI accepts compiles in the sandbox.
