# jq-sandbox

A proof of concept: evaluating untrusted [jq](https://jqlang.org/) filters on untrusted input inside a long-running
Linux service, with every evaluation bounded in CPU time, memory and stack, and unable to take the service down.

Filters are evaluated with [jaq](https://github.com/01mf02/jaq) 3, in forked worker processes. An input is
serialized to JSON once, and can go to any number of filters in one round trip.

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
  service ---- "spawn" ---->  trampoline      forked first thing in `main`
     |   <--- pidfd, socket ---   |
     |                            | clone(CLONE_PARENT)
     |       worker socket        v
     +------------------------> worker(s)     children of the service, one request at a time
```

- **Trampoline** (`src/spawner.rs`, independent of jq). Forked by `Sandbox::new` at the very top of `main`, before
  the service starts any thread or loads anything. It stays single-threaded and does one thing: fork a child when
  asked, and hand back the child's pidfd and one end of a socket connected to it.
- **Workers.** Copies of the trampoline, never `exec`ed. The trampoline forks them with `CLONE_PARENT`, so their
  parent is the service. Each compiles and runs filters for the service over its own socket, one request at a time.
- **Service.** Keeps a pool of workers. It holds each worker through its pidfd: it kills a worker with
  `pidfd_send_signal`, which cannot hit a reused pid, and, as the worker's parent, reaps it with `waitid(P_PIDFD)`
  to learn how it ended. The trampoline keeps no record of its children.

Why this shape:

- **Fork instead of exec** keeps workers cheap. A forked worker shares every page with the trampoline until it
  writes to it. Re-executing a large service binary costs megabytes per worker before `main` runs, for the pages
  the dynamic loader relocates.
- **A trampoline instead of forking the service** because `fork` is only safe in a single-threaded process, and
  because a worker forked from the running service would hold a copy of everything the service has in memory. The
  trampoline is a snapshot of the process from before it had threads or secrets.
- **`CLONE_PARENT`** because only a parent can learn a process's wait status, and the status is what tells the
  limits apart. With the service as the parent, killing and reaping a worker needs no message to the trampoline.
- **Forking is synchronous.** `Trampoline::spawn` blocks for the fork, well under a millisecond. A blocking call
  cannot be cancelled halfway through, so no request to the trampoline is ever left without its reply.

### Filters and inputs

`Sandbox::compile` checks in a worker that a filter compiles, and returns a `Filter` handle holding its source.
`Sandbox::input` serializes any `serde::Serialize` value to JSON. Every evaluation sends the sources and the JSON to
the worker, which parses the input once and compiles each filter.

Compiling on every evaluation is affordable because a filter is compiled with only the part of jaq's library it can
reach. jaq compiles its whole library, some 200 definitions and as many natives, into every filter: 0.4 ms for
`.a == 1`. The worker over-approximates what a filter can reach by name (every word in its source, then everything
those definitions call, any arity) and compiles only that, in a few microseconds. Everything sharing a name with
something reachable is kept, in order, so calls resolve exactly as with the whole library; a name the
approximation missed cannot resolve to something else, it fails to compile, and the filter is then compiled
against the whole library. A test runs about 150 filters through both and requires identical outputs.

The trampoline parses jaq's library once before forking any worker, so workers start with it.

### Batches

`Sandbox::evaluate_many` sends several filters with one input to one worker, which parses the input once and runs
the filters one after another. Each filter gets its own CPU-time budget and wall-clock limit. The worker writes each
verdict to its socket as soon as the filter is done, before it starts the next one. When it dies, the verdicts it
wrote are still there to read: they stand, the next filter is the culprit and gets the error, and the filters after
it go on on another worker. A worker that dies before it has parsed the input fails every filter of the batch.

### Limits

All limits are enforced by the kernel on the worker process. The way a worker dies identifies the limit:

| Limit | Mechanism | Worker ends with | Reported as |
|---|---|---|---|
| CPU time | CPU-time timer armed around each filter, and around parsing the input | `SIGXCPU` | `Limit::CpuTime` |
| Memory | `RLIMIT_DATA`; the failed allocation aborts | `SIGABRT` | `Limit::Memory` |
| Stack | `RLIMIT_STACK`; the guard page faults | `SIGSEGV` | `Limit::Stack` |
| Wall clock | the service stops waiting and kills the worker | `SIGKILL` | `Limit::WallTime` |

The wall clock restarts with every byte the worker sends: after the input is parsed, and after each verdict.

The time limit that matters is **CPU time**, measured on the worker alone. A wall-clock timeout fires on a small filter
whenever the host is busy enough; a CPU-time limit does not, because it only counts time the filter actually ran. The
wall clock is kept as a loose backstop for a worker that neither answers nor burns CPU.

A worker also runs with an empty environment, `/dev/null` for its standard streams, no capabilities,
`PR_SET_NO_NEW_PRIVS`, and resource limits that stop it from opening files or starting processes. It is not
dumpable: a core dump piped to apport or systemd-coredump ignores `RLIMIT_CORE` and holds a dying worker for a
second or more. In jaq 3 `halt` no longer exits the process; it ends the filter's output like an error. `input` and
`inputs` produce nothing.

Compiling a filter is sandboxed exactly like running it: `Sandbox::compile` and `Sandbox::check` run in a worker, so
that validation does not happen in the service.

## Usage

```rust
use jq_sandbox::{Config, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before anything else: no thread may exist yet.
    let sandbox = Sandbox::new(Config::default())?;

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
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
`Sandbox`, `Filter` and `Input` are cheap to clone, and dropping the last `Sandbox` clone kills the trampoline and
the workers. Dropping an evaluation's future kills the worker it runs on. A `Filter` or `Input` from one sandbox
works with another.

To try a filter from the shell:

```sh
echo '{"priority": "high"}' | cargo run --example eval -- '.priority == "high"'   # true
echo '{}' | cargo run --example eval -- 'def f: f; f'       # jq evaluation exceeded its CPU time limit
echo '{}' | cargo run --example eval -- '[range(1e12)]'     # jq evaluation exceeded its memory limit
```

What the caller has to get right:

- **Create it first.** `Sandbox::new` refuses to run once the process has a second thread. `#[tokio::main]` builds
  the runtime before the function body, so `main` has to be a plain function that creates the sandbox and then
  builds the runtime.
- **Leave room for the pool.** A container needs `workers * (memory + stack)` on top of the service. On cgroup v2 the
  kubelet kills every process in a container whose cgroup runs out of memory, so the per-worker limits must trip
  first.
- **Reap only your own children.** Workers are children of the service. Code that calls `waitpid(-1)` would take
  their exit statuses. Tokio's `process` module does not.
- **Linux 5.4 or later** (`clone` with `CLONE_PIDFD`, `pidfd_send_signal`, `waitid(P_PIDFD)`).
- **A seccomp profile that allows those.** Docker's and containerd's default profiles do; the tests run under
  Docker's in CI. Forking uses `clone` rather than `clone3` because those profiles fail `clone3` with `ENOSYS`.

## Measurements

`cargo run --release --example bench`, 4 workers, with 256 MiB allocated on the service's heap after the fork, on a
32-core x86_64 machine. "Before" is the previous version of this crate (shared input arena with lazy reads of a
binary encoding, filter caches in the workers, mirrored in the service), measured on the same machine.

| | before | now |
|---|---|---|
| One small evaluation, p50 | 6.3 µs | 12.8 µs |
| Same, `.payload \| fromjson \| …` | 11 µs | 29 µs |
| One small message, 10 filters, one batch, p50 | 18 µs | 85 µs |
| Throughput, one filter per message | 195 k/s | 150 k/s |
| Throughput, 10 filters per message | 140 k messages/s | 37 k messages/s |
| 5.7 kB input (100 objects), `.headers["x-user"] == "michal"` | 5 µs serialize + 8 µs | 7 µs + 83 µs |
| 630 kB input (10 k objects), same filter | 0.47 ms + 0.03 ms | 0.87 ms + 7.1 ms |
| 900 kB input (one long string), same filter | 0.04 ms + 0.01 ms | 0.26 ms + 0.55 ms |
| 630 kB input, `.items \| map(.price) \| add > 0` | 4.8 ms | 13.5 ms |
| New filter, compiled and evaluated once | 18 µs | 25 µs |
| First evaluation on a newly forked worker | | 0.28 ms |

The cost is all in work that is now repeated: every filter is compiled with every evaluation, and every input is
sent and parsed in full, whatever part of it the filter reads. Small messages stay in the tens of microseconds.
Large inputs pay for parsing.

## Tests

```sh
cargo test
```

The unit tests cover the wire format and compare jaq with the pruned library against jaq with the whole library.
`tests/sandbox.rs` is a plain `main` rather than a libtest harness, because the harness runs tests on threads and the
sandbox must be created before any exist. It covers:

- verdicts, invalid filters, size limits, inputs that have no JSON form;
- batches with a runaway filter in the middle, large batches, batches split across requests, typed (`serde`) inputs
  shared by concurrent evaluations, handles used across sandboxes;
- every hostile filter above, each followed by an ordinary evaluation that must succeed;
- hostile input with a harmless filter, through `fromjson` and as the input itself;
- 200 concurrent evaluations, hostile ones mixed in, with the pool never exceeding its size;
- callers that give up mid-evaluation;
- a stopped worker (wall clock), and workers killed from outside while idle;
- a host with every core oversubscribed four times over: ordinary filters pass, a runaway one still hits its CPU limit;
- a service that dies abruptly: trampoline and workers die with it;
- a service that creates its sandbox too late: refused;
- shutdown leaving no process behind.

## Known gaps

- **Memory is limited through `RLIMIT_DATA`**, which counts address space the worker maps writable, not resident
  pages. It is a close proxy for the heap and needs no cooperation from the allocator, but it is not byte-exact.
- **`SIGABRT` is read as "memory limit"**, because a failed allocation is the only thing that aborts a worker: panics
  exit with their own code and a stack overflow is left to `SIGSEGV`.
- **No seccomp filter.** jaq's core forbids `unsafe` code, so the threat here is resource exhaustion rather than code
  execution, and the limits above cover that. A syscall allowlist would be cheap defence in depth.
- **Inputs are serialized in the service.** `serde_json` has no depth limit when serializing, so a value nested
  deeply enough to overflow the service's stack in serialization would do so in the service. Values deserialized
  by `serde_json` are limited to a depth of 128.
- **Workers see UTC.** With an empty environment and no way to open files, `localtime` cannot read a time zone.
- **A lost trampoline is not replaced.** It cannot be forked again once the service has threads; every evaluation
  then fails with `Error::Unavailable`.
- **The pool is a fixed size and never shrinks.** Workers are forked on demand and kept.
- **The raw `clone` bypasses glibc's `fork`.** No `pthread_atfork` handler runs in the trampoline's children, which is
  harmless in a single-threaded process outside the allocator. Tested with glibc only.
- **jaq 3.** mirrord's `mirrord-jaq` crate, which validates filters in the CLI, is on jaq 2.2. The two should move
  together, so that a filter the CLI accepts compiles in the sandbox.
