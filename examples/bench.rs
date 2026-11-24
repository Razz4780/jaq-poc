//! Measures what the sandbox costs: latency and throughput of evaluations, batches and large
//! inputs, the price of a new filter and of replacing a worker, and the memory a worker holds.
//!
//! ```sh
//! cargo run --release --example bench
//! ```

use std::{
    fs,
    time::{Duration, Instant},
};

use jq_sandbox::{Config, Dispatcher, Error, Filter, Sandbox};
use serde_json::{Value, json};

const WORKERS: usize = 4;

/// Private memory of this process's dispatcher and of its workers, in kB, from `/proc`.
fn private_memory() -> (u64, Vec<u64>) {
    let private_dirty = |pid: u32| {
        fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
            .ok()
            .and_then(|rollup| {
                rollup
                    .lines()
                    .find_map(|line| line.strip_prefix("Private_Dirty:"))
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|kilobytes| kilobytes.parse().ok())
            })
            .unwrap_or(0)
    };
    let children = |parent: u32| {
        fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|pid| pid.parse().ok())
            .collect::<Vec<u32>>()
    };

    let dispatcher = children(std::process::id()).first().copied().unwrap_or(0);
    let workers = children(dispatcher)
        .into_iter()
        .map(private_dirty)
        .collect();
    (private_dirty(dispatcher), workers)
}

fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    sorted
        .get(sorted.len() * percent / 100)
        .copied()
        .unwrap_or_default()
}

fn message() -> Value {
    json!({
        "topic": "orders",
        "partition": 3,
        "offset": 12345,
        "key": "user-42",
        "payload": r#"{"priority":"high","tenant":"acme","items":[1,2,3]}"#,
        "headers": {"x-user": "michal", "traceparent": "00-abc-def-01"},
    })
}

fn items(count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| json!({"id": i, "name": format!("item-{i}"), "price": i as f64 * 1.5, "tags": ["a", "b"]}))
        .collect()
}

async fn latency(
    sandbox: &Sandbox,
    filter: &Filter,
    input: &Value,
    encode_each_time: bool,
) -> String {
    let encoded = sandbox.input(input).unwrap();
    let mut latencies = Vec::with_capacity(50_000);
    for _ in 0..50_000 {
        let started = Instant::now();
        if encode_each_time {
            let encoded = sandbox.input(input).unwrap();
            sandbox.evaluate(filter, &encoded).await.unwrap();
        } else {
            sandbox.evaluate(filter, &encoded).await.unwrap();
        }
        latencies.push(started.elapsed());
    }
    latencies.sort();
    format!(
        "p50 {:?}, p99 {:?}",
        percentile(&latencies, 50),
        percentile(&latencies, 99)
    )
}

async fn throughput(sandbox: &Sandbox, filters: &[Filter], input: &Value, count: usize) -> f64 {
    let started = Instant::now();
    let evaluations = (0..count)
        .map(|_| {
            let (sandbox, filters, input) = (sandbox.clone(), filters.to_vec(), input.clone());
            tokio::spawn(async move {
                let input = sandbox.input(&input).unwrap();
                let refs: Vec<&Filter> = filters.iter().collect();
                for result in sandbox.evaluate_many(&refs, &input).await {
                    result.unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    for evaluation in evaluations {
        evaluation.await.unwrap();
    }
    count as f64 / started.elapsed().as_secs_f64()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `JQ_BENCH_SPIN_US=50` measures with `Config::spin`.
    let spin = std::env::var("JQ_BENCH_SPIN_US")
        .ok()
        .and_then(|us| us.parse().ok())
        .map_or(Duration::ZERO, Duration::from_micros);
    let dispatcher = Dispatcher::fork(Config {
        workers: WORKERS,
        spin,
        ..Config::default()
    })?;
    // Stands in for everything a real service allocates after startup. The workers never see it.
    let service_heap = vec![7u8; 256 << 20];

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let sandbox = dispatcher.connect()?;
        let input = message();

        println!("## one filter, one small message ({} bytes encoded)", sandbox.input(&input)?.len());
        for source in [
            r#".headers["x-user"] == "michal""#,
            r#".payload | fromjson | .priority == "high" and (.tenant | test("^ac"))"#,
        ] {
            let filter = sandbox.compile(source).await?;
            assert!(sandbox.evaluate(&filter, &sandbox.input(&input)?).await?);
            println!("{source}");
            println!("  input encoded once:      {}", latency(&sandbox, &filter, &input, false).await);
            println!("  input encoded each time: {}", latency(&sandbox, &filter, &input, true).await);
            let rate = throughput(&sandbox, std::slice::from_ref(&filter), &input, 200_000).await;
            println!("  {WORKERS} workers, 200k queued: {rate:.0} evaluations/s");
        }

        println!("\n## one message, many filters");
        let mut filters = Vec::new();
        for i in 0..10 {
            filters.push(sandbox.compile(&format!(r#".headers["x-user"] == "user-{i}" or .partition == {i}"#)).await?);
        }
        let encoded = sandbox.input(&input)?;
        let refs: Vec<&Filter> = filters.iter().collect();
        let mut one_by_one = Vec::new();
        let mut batched = Vec::new();
        for _ in 0..20_000 {
            let started = Instant::now();
            for filter in &filters {
                sandbox.evaluate(filter, &encoded).await?;
            }
            one_by_one.push(started.elapsed());
            let started = Instant::now();
            for result in sandbox.evaluate_many(&refs, &encoded).await {
                result?;
            }
            batched.push(started.elapsed());
        }
        one_by_one.sort();
        batched.sort();
        println!(
            "10 filters one by one: p50 {:?}; as one batch: p50 {:?}, p99 {:?}",
            percentile(&one_by_one, 50),
            percentile(&batched, 50),
            percentile(&batched, 99),
        );
        let rate = throughput(&sandbox, &filters, &input, 100_000).await;
        println!("{WORKERS} workers, 100k messages queued, 10 filters each: {rate:.0} messages/s, {:.0} filters/s", rate * 10.0);

        println!("\n## large inputs, `.headers[\"x-user\"] == \"michal\"`");
        let filter = sandbox.compile(r#".headers["x-user"] == "michal""#).await?;
        let body = serde_json::to_string(&json!({"user": "michal", "data": "x".repeat(900_000)}))?;
        for (name, value) in [
            ("100 objects", json!({"headers": {"x-user": "michal"}, "items": items(100)})),
            ("10k objects", json!({"headers": {"x-user": "michal"}, "items": items(10_000)})),
            ("900 kB string", json!({"headers": {"x-user": "michal"}, "body": body})),
        ] {
            let json_len = serde_json::to_vec(&value)?.len();
            let runs = if json_len > 100_000 { 200 } else { 5_000 };
            let mut encode = Duration::ZERO;
            let mut evaluate = Duration::ZERO;
            for _ in 0..runs {
                let started = Instant::now();
                let encoded = sandbox.input(&value)?;
                let encoded_at = Instant::now();
                assert!(sandbox.evaluate(&filter, &encoded).await?);
                encode += encoded_at - started;
                evaluate += encoded_at.elapsed();
            }
            println!(
                "{name:>14} ({json_len} bytes of JSON): encode {:?}, evaluate {:?}",
                encode / runs,
                evaluate / runs
            );
        }
        let value = json!({"headers": {"x-user": "michal"}, "items": items(10_000)});
        let deep = sandbox.compile(".items | map(.price) | add > 0").await?;
        let encoded = sandbox.input(&value)?;
        let started = Instant::now();
        for _ in 0..100 {
            assert!(sandbox.evaluate(&deep, &encoded).await?);
        }
        println!("   10k objects, `.items | map(.price) | add > 0`: {:?}", started.elapsed() / 100);

        // Each of these compiles on a worker that has never seen the filter.
        let started = Instant::now();
        for i in 0..2_000 {
            let filter = sandbox.compile(&format!(r#".headers["x-user"] == "user-{i}""#)).await?;
            sandbox.evaluate(&filter, &encoded).await?;
        }
        println!("\nnew filter, compiled and evaluated once: {:?}", started.elapsed() / 2_000);

        let mut kept = Vec::new();
        for i in 0..1_000 {
            kept.push(sandbox.compile(&format!(r#".headers["x-user"] == "user-{i}" and (.partition | tostring | test("^[0-9]+$"))"#)).await?);
        }
        let small = sandbox.input(&message())?;
        for _ in 0..WORKERS * 4 {
            let refs: Vec<&Filter> = kept.iter().collect();
            sandbox.evaluate_many(&refs, &small).await;
        }
        let (dispatcher, workers) = private_memory();
        println!(
            "private memory with 1000 filters cached: dispatcher {dispatcher} kB, workers {workers:?} kB, with {} MiB on the service's heap",
            service_heap.len() >> 20
        );
        drop(kept);

        // Empty the pool, so that every evaluation below runs on a worker forked for it.
        let bomb = sandbox.compile(r#""a" * 1000000000"#).await?;
        let ordinary = sandbox.compile(".offset > 0").await?;
        let mut killed = Duration::ZERO;
        let mut replaced = Duration::ZERO;
        for i in 0..200 + WORKERS {
            let started = Instant::now();
            let result = sandbox.evaluate(&bomb, &small).await;
            assert!(matches!(result, Err(Error::LimitExceeded(_))));
            if i >= WORKERS {
                killed += started.elapsed();
            }
        }
        for _ in 0..200 {
            let result = sandbox.evaluate(&bomb, &small).await;
            assert!(matches!(result, Err(Error::LimitExceeded(_))));
            let started = Instant::now();
            sandbox.evaluate(&ordinary, &small).await?;
            replaced += started.elapsed();
        }
        println!(
            "evaluation that hits the memory limit, on a new worker: {:?}; first evaluation on a new worker: {:?}",
            killed / 200,
            replaced / 200
        );
        Ok(())
    })
}
