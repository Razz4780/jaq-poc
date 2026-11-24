//! End-to-end tests of the sandbox against hostile filters, hostile input and process failures.
//!
//! This is a plain `main` (`harness = false`): the dispatcher has to be forked before the process
//! has a second thread, and the standard test harness runs every test on a thread of its own.
//!
//! The binary also re-runs itself with an argument to play a service that dies, or one that
//! forks its dispatcher too late.

use std::{
    fs,
    future::Future,
    process::{Command, ExitCode},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use jq_sandbox::{Config, Dispatcher, Error, Filter, Limit, Sandbox};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::{Value, json};

const WORKERS: usize = 3;
const SECRET_VARIABLE: &str = "JQ_SANDBOX_TEST_SECRET";
const BENIGN: &str = r#".priority == "high""#;
const RUNAWAY: &str = "def f: f; f";

fn config() -> Config {
    Config {
        workers: WORKERS,
        cpu_time: Duration::from_millis(300),
        wall_time: Duration::from_secs(2),
        ..Config::default()
    }
}

fn message() -> Value {
    json!({"priority": "high", "tenant": "acme"})
}

/// Compiles, encodes and evaluates in one go, as the tests mostly need.
trait EvaluateOnce {
    fn eval(&self, filter: &str, input: &Value)
    -> impl Future<Output = Result<bool, Error>> + Send;
}

impl EvaluateOnce for Sandbox {
    fn eval(
        &self,
        filter: &str,
        input: &Value,
    ) -> impl Future<Output = Result<bool, Error>> + Send {
        let input = self.input(input);
        async move {
            let filter = self.compile(filter).await?;
            self.evaluate(&filter, &input?).await
        }
    }
}

/// `(pid, state)` of every process whose parent is `parent`, from `/proc`.
fn children_of(parent: Pid) -> Vec<(Pid, char)> {
    let mut children = Vec::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        // `pid (command) state ppid ...`, where the command may itself contain parentheses.
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let state = fields.next().and_then(|state| state.chars().next());
        let ppid = fields.next().and_then(|ppid| ppid.parse::<i32>().ok());
        if let (Some(state), Some(ppid)) = (state, ppid)
            && ppid == parent.as_raw()
        {
            children.push((Pid::from_raw(pid), state));
        }
    }
    children
}

/// The dispatcher, right after the process forked its first one.
fn first_child() -> Pid {
    let children = children_of(Pid::this());
    children.first().expect("the dispatcher was just forked").0
}

/// Whether the process is gone, or dead and only waiting to be reaped.
fn is_dead(pid: Pid) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
        Err(_) => true,
    }
}

async fn assert_healthy(sandbox: &Sandbox) {
    let verdict = sandbox.eval(BENIGN, &message()).await;
    assert!(
        matches!(verdict, Ok(true)),
        "the sandbox must keep answering, got {verdict:?}"
    );
}

async fn verdicts(sandbox: &Sandbox) {
    let input = message();
    for (filter, expected) in [
        (BENIGN, true),
        (r#".priority == "low""#, false),
        (r#".priority == "high" and (.tenant | test("^ac"))"#, true),
        // No boolean output at all.
        (".tenant", false),
        ("empty", false),
        // The first boolean decides, whatever comes before or after it.
        (r#"1, "x", true, false"#, true),
        // An error raised by the filter is skipped like any other non-boolean output.
        (r#"(.tenant | .[0]), true"#, true),
        (r#".tenant | .[0]"#, false),
    ] {
        let verdict = sandbox.eval(filter, &input).await;
        assert!(
            matches!(verdict, Ok(v) if v == expected),
            "`{filter}` should give {expected}, got {verdict:?}"
        );
    }
}

async fn invalid_filters(sandbox: &Sandbox) {
    sandbox.check(BENIGN).await.unwrap();
    sandbox.check(".[] | select(.snow > 25)").await.unwrap();

    for filter in ["", "snow", ".a |", "idk | whatever"] {
        let checked = sandbox.check(filter).await;
        assert!(
            matches!(&checked, Err(Error::InvalidFilter(message)) if !message.is_empty()),
            "`{filter}` should not compile, got {checked:?}"
        );
        let evaluated = sandbox.eval(filter, &message()).await;
        assert!(
            matches!(evaluated, Err(Error::InvalidFilter(_))),
            "`{filter}` should not evaluate, got {evaluated:?}"
        );
    }

    let undefined = sandbox.check("no_such_filter").await;
    assert!(
        matches!(&undefined, Err(Error::InvalidFilter(message)) if message.contains("no_such_filter")),
        "the error should name the undefined filter, got {undefined:?}"
    );
}

async fn size_limits(sandbox: &Sandbox) {
    let limits = Config::default();

    let filter = format!(r#". == "{}""#, "a".repeat(limits.max_filter_len));
    let result = sandbox.eval(&filter, &message()).await;
    assert!(
        matches!(result, Err(Error::FilterTooLarge { .. })),
        "{result:?}"
    );
    let result = sandbox.check(&filter).await;
    assert!(
        matches!(result, Err(Error::FilterTooLarge { .. })),
        "{result:?}"
    );

    let input = json!("a".repeat(limits.max_input_len));
    let result = sandbox.input(&input);
    assert!(
        matches!(result, Err(Error::InputTooLarge { .. })),
        "{result:?}"
    );

    let mut deep = json!(1);
    for _ in 0..1000 {
        deep = json!([deep]);
    }
    let result = sandbox.input(&deep);
    assert!(matches!(result, Err(Error::InvalidInput(_))), "{result:?}");
}

/// Several filters on one input, in one round trip, with a runaway one in the middle: the
/// verdicts on both sides of it stand, and only it gets the error.
async fn batches(sandbox: &Sandbox) {
    let input = sandbox.input(&message()).unwrap();
    let mut filters = Vec::new();
    for source in [
        BENIGN,
        r#".priority == "low""#,
        RUNAWAY,
        r#".tenant | startswith("ac")"#,
        "[range(1e12)] | length > 0",
        ".tenant",
    ] {
        filters.push(sandbox.compile(source).await.unwrap());
    }
    let refs: Vec<&Filter> = filters.iter().collect();

    let spawned = sandbox.workers_spawned();
    let results = sandbox.evaluate_many(&refs, &input).await;
    let shown = format!("{results:?}");
    let Ok([low_true, low_false, runaway, prefix, memory, no_bool]) = <[_; 6]>::try_from(results)
    else {
        panic!("one result per filter: {shown}");
    };
    assert!(matches!(low_true, Ok(true)), "{shown}");
    assert!(matches!(low_false, Ok(false)), "{shown}");
    assert!(
        matches!(runaway, Err(Error::LimitExceeded(Limit::CpuTime))),
        "{shown}"
    );
    assert!(matches!(prefix, Ok(true)), "{shown}");
    assert!(
        matches!(
            memory,
            Err(Error::LimitExceeded(Limit::Memory | Limit::CpuTime))
        ),
        "{shown}"
    );
    assert!(matches!(no_bool, Ok(false)), "{shown}");
    assert!(sandbox.workers_spawned() <= spawned + 2);

    // A large batch, the same filter many times over, and an empty one.
    let benign = sandbox.compile(BENIGN).await.unwrap();
    let many = vec![&benign; 10_000];
    let results = sandbox.evaluate_many(&many, &input).await;
    assert_eq!(results.len(), many.len());
    assert!(results.iter().all(|result| matches!(result, Ok(true))));
    assert!(sandbox.evaluate_many(&[], &input).await.is_empty());
}

/// Inputs straight from Rust types, reused across evaluations and filters.
async fn typed_inputs(sandbox: &Sandbox) {
    #[derive(serde::Serialize)]
    struct Message<'a> {
        priority: &'a str,
        attempts: u32,
        headers: std::collections::BTreeMap<&'a str, &'a str>,
        kind: Kind,
    }
    #[derive(serde::Serialize)]
    enum Kind {
        Order { id: u64 },
    }

    let message = Message {
        priority: "high",
        attempts: 3,
        headers: [("x-user", "michal")].into(),
        kind: Kind::Order { id: 7 },
    };
    let input = sandbox.input(&message).unwrap();
    for (source, expected) in [
        (BENIGN, true),
        (".attempts > 2", true),
        (r#".headers["x-user"] == "michal""#, true),
        (".kind.Order.id == 7", true),
        (".kind | keys == [\"Order\"]", true),
        (".missing == null", true),
    ] {
        let filter = sandbox.compile(source).await.unwrap();
        let verdict = sandbox.evaluate(&filter, &input).await;
        assert!(
            matches!(verdict, Ok(v) if v == expected),
            "`{source}` gave {verdict:?}"
        );
    }

    // One input, many concurrent evaluations of one filter.
    let filter = sandbox.compile(".attempts == 3").await.unwrap();
    let evaluations = (0..100).map(|_| {
        let (sandbox, filter, input) = (sandbox.clone(), filter.clone(), input.clone());
        tokio::spawn(async move { sandbox.evaluate(&filter, &input).await })
    });
    for evaluation in evaluations.collect::<Vec<_>>() {
        assert!(matches!(evaluation.await.unwrap(), Ok(true)));
    }
}

/// Filters dropped and compiled again, many more than any worker keeps.
async fn filter_turnover(sandbox: &Sandbox) {
    let input = sandbox.input(&message()).unwrap();
    for round in 0..20 {
        let filters = futures_join((0..100).map(|i| {
            let sandbox = sandbox.clone();
            async move {
                let filter = sandbox
                    .compile(&format!(r#".priority == "high" and {round} + {i} >= 0"#))
                    .await
                    .unwrap();
                sandbox
                    .evaluate(&filter, &sandbox.input(&message()).unwrap())
                    .await
                    .map(|v| (v, filter))
            }
        }))
        .await;
        let filters: Vec<Filter> = filters
            .into_iter()
            .map(|result| {
                let (verdict, filter) = result.unwrap();
                assert!(verdict);
                filter
            })
            .collect();
        let refs: Vec<&Filter> = filters.iter().collect();
        assert!(
            sandbox
                .evaluate_many(&refs, &input)
                .await
                .iter()
                .all(|result| matches!(result, Ok(true)))
        );
    }
}

/// A batch of more distinct filters than a worker keeps compiled at once, run twice: it is split
/// into requests the worker can hold, and the cache turns over in between.
async fn more_filters_than_a_worker_keeps(sandbox: &Sandbox) {
    let input = sandbox.input(&message()).unwrap();
    let filters = futures_join((0..1500).map(|i| {
        let sandbox = sandbox.clone();
        async move {
            let padding = "x".repeat(100);
            sandbox
                .compile(&format!(r#".priority == "high" and "{padding}" != "{i}""#))
                .await
                .unwrap()
        }
    }))
    .await;
    let refs: Vec<&Filter> = filters.iter().collect();
    for _ in 0..2 {
        let results = sandbox.evaluate_many(&refs, &input).await;
        let wrong: Vec<_> = results
            .iter()
            .enumerate()
            .filter(|(_, result)| !matches!(result, Ok(true)))
            .collect();
        assert!(wrong.is_empty(), "{wrong:?}");
    }
}

/// Runs the futures concurrently, each in a task of its own.
async fn futures_join<T: Send + 'static>(
    futures: impl Iterator<Item = impl Future<Output = T> + Send + 'static>,
) -> Vec<T> {
    let tasks: Vec<_> = futures.map(tokio::spawn).collect();
    let mut outputs = Vec::new();
    for task in tasks {
        outputs.push(task.await.unwrap());
    }
    outputs
}

/// Handles from one sandbox used with another, and inputs that do not fit in the arena.
async fn foreign_handles_and_full_arena(sandbox: &Sandbox, small: &Sandbox) {
    let filter = sandbox.compile(BENIGN).await.unwrap();
    let input = sandbox.input(&message()).unwrap();
    assert!(matches!(small.evaluate(&filter, &input).await, Ok(true)));

    // The small sandbox's arena holds one of these at a time.
    let big = json!({"priority": "high", "padding": "x".repeat(40 << 10)});
    let inputs: Vec<_> = (0..4).map(|_| small.input(&big).unwrap()).collect();
    for input in &inputs {
        assert!(matches!(small.evaluate(&filter, input).await, Ok(true)));
        assert!(matches!(sandbox.evaluate(&filter, input).await, Ok(true)));
    }
    let shared = inputs
        .iter()
        .filter(|input| format!("{input:?}").contains("shared: true"));
    assert_eq!(shared.count(), 1, "{inputs:?}");
}

/// Filters that, evaluated in-process, would hang a thread forever, exhaust the process's memory,
/// or abort the process.
async fn hostile_filters(sandbox: &Sandbox) {
    use Limit::{CpuTime, Memory, Stack};

    // 7,000 nested parentheses: overflows the stack in the compiler, before anything runs.
    let nested = format!("{}1{}", "(".repeat(7000), ")".repeat(7000));
    let cases: &[(&str, &[Limit])] = &[
        (RUNAWAY, &[CpuTime]),
        ("last(range(1e18))", &[CpuTime]),
        ("def f: 1 + f; f", &[Stack]),
        (
            r#"reduce range(60) as $i ("aaaaaaaa"; . + .) | length > 0"#,
            &[Memory],
        ),
        (r#""a" * 1000000000 | length > 0"#, &[Memory]),
        // These grow slowly enough that an unoptimized build can run out of CPU time first.
        ("[range(1e12)] | length > 0", &[Memory, CpuTime]),
        (
            r#"[repeat("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] | length > 0"#,
            &[Memory, CpuTime],
        ),
        // Builds a value nested deeper than the stack can handle. Building it may already run
        // out of something else.
        (
            "reduce range(3000000) as $i (0; [.]) | false",
            &[Memory, Stack, CpuTime],
        ),
        (
            "reduce range(200000) as $i (0; [.]) | tojson | length > 0",
            &[Memory, Stack, CpuTime],
        ),
        (&nested, &[Stack]),
    ];

    for (filter, expected) in cases {
        let shown: String = filter.chars().take(60).collect();
        let started = Instant::now();
        let result = sandbox.eval(filter, &message()).await;
        assert!(
            matches!(&result, Err(Error::LimitExceeded(limit)) if expected.contains(limit)),
            "`{shown}` should exceed one of {expected:?}, got {result:?}"
        );
        println!("    {:>6.0?}  {result:?}  {shown}", started.elapsed());
        assert_healthy(sandbox).await;
    }

    let checked = sandbox.check(&nested).await;
    assert!(
        matches!(checked, Err(Error::LimitExceeded(Stack))),
        "checking a filter is sandboxed like running it, got {checked:?}"
    );
}

/// Builtins that reach outside the evaluation: they must find nothing there.
async fn ambient_builtins(sandbox: &Sandbox) {
    assert_healthy(sandbox).await;
    let spawned = sandbox.workers_spawned();

    // In-process, both of these end the calling process.
    for filter in ["halt", r#""bye" | halt_error(3)"#, "halt, true"] {
        let verdict = sandbox.eval(filter, &message()).await;
        let expected = filter.ends_with("true");
        assert!(
            matches!(verdict, Ok(v) if v == expected),
            "`{filter}` should behave like a failed output, got {verdict:?}"
        );
    }

    assert!(
        std::env::var(SECRET_VARIABLE).is_ok(),
        "the service itself has the variable"
    );
    let verdict = sandbox.eval("env | length == 0", &message()).await;
    assert!(
        matches!(verdict, Ok(true)),
        "a worker must see an empty environment, got {verdict:?}"
    );
    let verdict = sandbox
        .eval(&format!("env.{SECRET_VARIABLE} != null"), &message())
        .await;
    assert!(matches!(verdict, Ok(false)), "{verdict:?}");

    // Time and output builtins keep working as jq defines them.
    for filter in [
        "now > 0",
        "(now | localtime | mktime) > 0",
        r#"("to stderr" | stderr | debug) == "to stderr""#,
        "[inputs] == []",
    ] {
        let verdict = sandbox.eval(filter, &message()).await;
        assert!(matches!(verdict, Ok(true)), "`{filter}` gave {verdict:?}");
    }

    assert_eq!(
        sandbox.workers_spawned(),
        spawned,
        "none of these may cost a worker"
    );
}

/// A harmless filter and a message built to overflow the stack of whoever parses it.
async fn hostile_input(sandbox: &Sandbox) {
    let payload = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let input = json!({ "payload": payload });
    let filter = r#".payload | fromjson | .priority == "high""#;

    let result = sandbox.eval(filter, &input).await;
    assert!(
        matches!(result, Err(Error::LimitExceeded(Limit::Stack))),
        "{result:?}"
    );

    let input = json!({ "payload": r#"{"priority": "high"}"# });
    let verdict = sandbox.eval(filter, &input).await;
    assert!(matches!(verdict, Ok(true)), "{verdict:?}");
}

/// Hostile and ordinary evaluations side by side: the ordinary ones must all get their verdict,
/// and the pool must never grow past its size.
async fn concurrency(sandbox: &Sandbox, dispatcher: Pid) {
    let evaluations = (0..200).map(|i| {
        let sandbox = sandbox.clone();
        tokio::spawn(async move {
            if i % 20 == 0 {
                let result = sandbox.eval(RUNAWAY, &message()).await;
                assert!(
                    matches!(result, Err(Error::LimitExceeded(Limit::CpuTime))),
                    "{result:?}"
                );
            } else {
                let expected = i % 2 == 0;
                let input = json!({"priority": if expected { "high" } else { "low" }});
                let verdict = sandbox.eval(BENIGN, &input).await;
                assert!(matches!(verdict, Ok(v) if v == expected), "{verdict:?}");
            }
            let workers = children_of(dispatcher).len();
            assert!(workers <= WORKERS, "{workers} workers exist at once");
        })
    });
    for evaluation in evaluations.collect::<Vec<_>>() {
        evaluation.await.unwrap();
    }
}

/// A caller that gives up must not cost the pool a worker or leave one in a broken state.
async fn cancellation(sandbox: &Sandbox, dispatcher: Pid) {
    let input = message();
    for _ in 0..WORKERS * 2 {
        let abandoned =
            tokio::time::timeout(Duration::from_millis(20), sandbox.eval(RUNAWAY, &input));
        assert!(abandoned.await.is_err(), "the caller gives up first");
    }

    // More evaluations than workers, started while abandoned ones may still be running.
    let evaluations = (0..WORKERS * 3).map(|_| {
        let sandbox = sandbox.clone();
        tokio::spawn(async move { assert_healthy(&sandbox).await })
    });
    for evaluation in evaluations.collect::<Vec<_>>() {
        evaluation.await.unwrap();
    }
    let workers = children_of(dispatcher).len();
    assert!(workers <= WORKERS, "{workers} workers exist at once");
}

/// A worker that does not answer and does not burn CPU either is caught by the wall clock.
async fn wall_clock(sandbox: &Sandbox, dispatcher: Pid) {
    assert_healthy(sandbox).await;
    let workers = children_of(dispatcher);
    assert!(!workers.is_empty());
    for (pid, _) in &workers {
        kill(*pid, Signal::SIGSTOP).unwrap();
    }

    let started = Instant::now();
    let result = sandbox.eval(BENIGN, &message()).await;
    assert!(
        matches!(result, Err(Error::LimitExceeded(Limit::WallTime))),
        "{result:?}"
    );
    assert!(started.elapsed() >= config().wall_time);

    for (pid, _) in &workers {
        // One of them has been killed and reaped by now.
        let _ = kill(*pid, Signal::SIGCONT);
    }
    assert_healthy(sandbox).await;
}

/// Workers killed from outside while idle, as the kernel's out-of-memory killer could do, are
/// replaced without failing the evaluation that finds them dead.
async fn idle_workers_killed(sandbox: &Sandbox, dispatcher: Pid) {
    let evaluations = (0..WORKERS).map(|_| {
        let sandbox = sandbox.clone();
        tokio::spawn(async move { assert_healthy(&sandbox).await })
    });
    for evaluation in evaluations.collect::<Vec<_>>() {
        evaluation.await.unwrap();
    }

    let workers = children_of(dispatcher);
    assert!(!workers.is_empty());
    for (pid, _) in &workers {
        kill(*pid, Signal::SIGKILL).unwrap();
    }
    while !workers.iter().all(|(pid, _)| is_dead(*pid)) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    for _ in 0..WORKERS * 2 {
        assert_healthy(sandbox).await;
    }
}

/// The CPU-time limit measures the filter, not the host: with every core oversubscribed, ordinary
/// filters still pass (each one compiled from scratch), and a runaway one is still stopped by
/// its CPU time rather than by the wall clock.
async fn starved_host(sandbox: &Sandbox) {
    let stop = Arc::new(AtomicBool::new(false));
    let cores = thread::available_parallelism().map_or(4, usize::from);
    let spinners = (0..cores * 4)
        .map(|_| {
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            })
        })
        .collect::<Vec<_>>();

    let input = message();
    for i in 0..150 {
        let filter = format!(r#".priority == "high" and {i} == {i}"#);
        let verdict = sandbox.eval(&filter, &input).await;
        assert!(
            matches!(verdict, Ok(true)),
            "evaluation {i} on a starved host gave {verdict:?}"
        );
    }
    let result = sandbox.eval(RUNAWAY, &input).await;
    assert!(
        matches!(result, Err(Error::LimitExceeded(Limit::CpuTime))),
        "{result:?}"
    );

    stop.store(true, Ordering::Relaxed);
    for spinner in spinners {
        spinner.join().unwrap();
    }
}

/// Runs this binary again in one of its service roles.
fn rerun(role: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .arg(role)
        .output()
        .unwrap()
}

/// Role: a service that dies abruptly while one of its workers is deep in a runaway filter.
/// Prints the pids of its dispatcher and workers first.
fn service_that_dies() -> ExitCode {
    let dispatcher = Dispatcher::fork(Config {
        cpu_time: Duration::from_secs(60),
        wall_time: Duration::from_secs(60),
        ..config()
    })
    .unwrap();
    let dispatcher_pid = first_child();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let sandbox = dispatcher.connect().unwrap();
        assert_healthy(&sandbox).await;
        tokio::spawn(async move { sandbox.eval(RUNAWAY, &message()).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let workers = children_of(dispatcher_pid);
    assert!(workers.iter().any(|(_, state)| *state == 'R'));
    print!("{dispatcher_pid}");
    for (pid, _) in workers {
        print!(" {pid}");
    }
    println!();
    // No destructors, no goodbye to the dispatcher.
    std::process::abort()
}

fn orphans_die_with_the_service() {
    let output = rerun("service-that-dies");
    let pids = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|pid| Pid::from_raw(pid.parse().unwrap()))
        .collect::<Vec<_>>();
    assert!(
        pids.len() >= 2,
        "expected a dispatcher and a worker, got {pids:?}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !pids.iter().all(|pid| is_dead(*pid)) {
        assert!(
            Instant::now() < deadline,
            "dispatcher and workers must not outlive the service: {pids:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Role: a service that starts a thread before forking its dispatcher.
fn service_that_forks_late() -> ExitCode {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let thread = thread::spawn(move || stop_rx.recv());
    let result = Dispatcher::fork(config());
    drop(stop_tx);
    let _ = thread.join();
    match result {
        Err(error) => {
            println!("{error}");
            ExitCode::SUCCESS
        }
        Ok(_) => ExitCode::FAILURE,
    }
}

fn forking_late_is_refused() {
    let output = rerun("service-that-forks-late");
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("before the process starts any thread")
    );
}

async fn run<F: Future<Output = ()>>(name: &str, test: F) {
    println!("test {name} ...");
    let started = Instant::now();
    test.await;
    println!("test {name} ... ok ({:.1?})", started.elapsed());
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("service-that-dies") => return service_that_dies(),
        Some("service-that-forks-late") => return service_that_forks_late(),
        _ => {}
    }

    // Something for jq's `env` to find, set while the process still has one thread.
    //
    // Safety: no other thread exists yet.
    unsafe { std::env::set_var(SECRET_VARIABLE, "s3cr3t") };

    let dispatcher = Dispatcher::fork(config()).expect("failed to fork the dispatcher");
    let dispatcher_pid = first_child();
    // A second, independent sandbox whose wall clock never gets in the way.
    let patient = Dispatcher::fork(Config {
        cpu_time: Duration::from_millis(200),
        wall_time: Duration::from_secs(120),
        ..config()
    })
    .expect("failed to fork the second dispatcher");
    // A third one with an arena that holds a single large input.
    let small = Dispatcher::fork(Config {
        workers: 1,
        input_arena: 64 << 10,
        ..config()
    })
    .expect("failed to fork the third dispatcher");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let sandbox = dispatcher.connect().unwrap();
        let patient = patient.connect().unwrap();
        let small = small.connect().unwrap();

        run("verdicts", verdicts(&sandbox)).await;
        run("invalid_filters", invalid_filters(&sandbox)).await;
        run("size_limits", size_limits(&sandbox)).await;
        run("batches", batches(&sandbox)).await;
        run("typed_inputs", typed_inputs(&sandbox)).await;
        run("filter_turnover", filter_turnover(&sandbox)).await;
        run(
            "more_filters_than_a_worker_keeps",
            more_filters_than_a_worker_keeps(&sandbox),
        )
        .await;
        run(
            "foreign_handles_and_full_arena",
            foreign_handles_and_full_arena(&sandbox, &small),
        )
        .await;
        run("hostile_filters", hostile_filters(&sandbox)).await;
        run("ambient_builtins", ambient_builtins(&sandbox)).await;
        run("hostile_input", hostile_input(&sandbox)).await;
        run("concurrency", concurrency(&sandbox, dispatcher_pid)).await;
        run("cancellation", cancellation(&sandbox, dispatcher_pid)).await;
        run("wall_clock", wall_clock(&sandbox, dispatcher_pid)).await;
        run(
            "idle_workers_killed",
            idle_workers_killed(&sandbox, dispatcher_pid),
        )
        .await;
        run("starved_host", starved_host(&patient)).await;

        // In the order they were forked. The second dispatcher was forked while the service
        // already held the first one's control socket, and must not be keeping it open.
        drop(sandbox);
        drop(patient);
        drop(small);
    });

    println!("test orphans_die_with_the_service ...");
    orphans_die_with_the_service();
    println!("test forking_late_is_refused ...");
    forking_late_is_refused();

    // Both sandboxes were dropped inside `block_on`, which stops and reaps everything.
    let left = children_of(Pid::this());
    assert!(left.is_empty(), "processes left behind: {left:?}");
    println!("test shutdown_leaves_no_process ... ok");

    println!("all tests passed");
    ExitCode::SUCCESS
}
