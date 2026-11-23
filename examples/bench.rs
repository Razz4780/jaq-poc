//! Measures what the sandbox costs: latency of an evaluation, the price of replacing a worker,
//! and the memory a worker holds.
//!
//! ```sh
//! cargo run --release --example bench
//! ```

use std::{
    fs,
    time::{Duration, Instant},
};

use jq_sandbox::{Config, Dispatcher, Error};
use serde_json::json;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dispatcher = Dispatcher::fork(Config {
        workers: WORKERS,
        ..Config::default()
    })?;
    // Stands in for everything a real service allocates after startup. The workers never see it.
    let service_heap = vec![7u8; 256 << 20];

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let sandbox = dispatcher.connect()?;
        let input = json!({
            "topic": "orders",
            "partition": 3,
            "offset": 12345,
            "key": "user-42",
            "payload": r#"{"priority":"high","tenant":"acme","items":[1,2,3]}"#,
            "headers": {"x-user": "michal", "traceparent": "00-abc-def-01"},
        });

        for filter in [
            r#".headers["x-user"] == "michal""#,
            r#".payload | fromjson | .priority == "high" and (.tenant | test("^ac"))"#,
        ] {
            assert!(sandbox.evaluate(filter, &input).await?);
            let mut latencies = Vec::with_capacity(50_000);
            for _ in 0..50_000 {
                let started = Instant::now();
                sandbox.evaluate(filter, &input).await?;
                latencies.push(started.elapsed());
            }
            latencies.sort();
            println!(
                "{filter}\n  one at a time: p50 {:?}, p99 {:?}",
                percentile(&latencies, 50),
                percentile(&latencies, 99)
            );

            let started = Instant::now();
            let evaluations = (0..200_000)
                .map(|_| {
                    let (sandbox, input) = (sandbox.clone(), input.clone());
                    tokio::spawn(async move { sandbox.evaluate(filter, &input).await })
                })
                .collect::<Vec<_>>();
            for evaluation in evaluations {
                evaluation.await??;
            }
            println!(
                "  {WORKERS} workers, 200k queued: {:.0} evaluations/s",
                200_000.0 / started.elapsed().as_secs_f64()
            );
        }

        let (dispatcher, workers) = private_memory();
        println!(
            "private memory: dispatcher {dispatcher} kB, workers {workers:?} kB, with {} MiB on the service's heap",
            service_heap.len() >> 20
        );

        // Each of these compiles on a worker that has never seen the filter.
        let started = Instant::now();
        for i in 0..2_000 {
            let filter = format!(r#".headers["x-user"] == "user-{i}""#);
            sandbox.evaluate(&filter, &input).await?;
        }
        println!(
            "new filter, first evaluation: {:?}",
            started.elapsed() / 2_000
        );

        // Empty the pool, so that every evaluation below runs on a worker forked for it.
        let mut killed = Duration::ZERO;
        let mut replaced = Duration::ZERO;
        for i in 0..200 + WORKERS {
            let started = Instant::now();
            let result = sandbox.evaluate(r#""a" * 1000000000"#, &input).await;
            assert!(matches!(result, Err(Error::LimitExceeded(_))));
            let died = Instant::now();
            if i >= WORKERS {
                killed += died - started;
            }
        }
        for _ in 0..200 {
            let result = sandbox.evaluate(r#""a" * 1000000000"#, &input).await;
            assert!(matches!(result, Err(Error::LimitExceeded(_))));
            let started = Instant::now();
            sandbox.evaluate(".offset > 0", &input).await?;
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
