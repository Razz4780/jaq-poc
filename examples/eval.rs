//! Evaluates one filter on JSON read from standard input, inside the sandbox.
//!
//! ```sh
//! echo '{"priority": "high"}' | cargo run --example eval -- '.priority == "high"'
//! echo '{}' | cargo run --example eval -- 'def f: f; f'
//! ```

use std::process::ExitCode;

use jq_sandbox::{Config, Dispatcher};

fn main() -> ExitCode {
    // Before reading input, parsing arguments or anything else that could start a thread.
    let dispatcher = match Dispatcher::fork(Config::default()) {
        Ok(dispatcher) => dispatcher,
        Err(error) => {
            eprintln!("failed to fork the dispatcher: {error}");
            return ExitCode::FAILURE;
        }
    };

    let Some(filter) = std::env::args().nth(1) else {
        eprintln!("usage: eval <jq filter> < input.json");
        return ExitCode::FAILURE;
    };
    let input: serde_json::Value = match serde_json::from_reader(std::io::stdin()) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("standard input is not JSON: {error}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to build the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let verdict = runtime.block_on(async {
        let sandbox = dispatcher
            .connect()
            .map_err(jq_sandbox::Error::Unavailable)?;
        let filter = sandbox.compile(&filter).await?;
        let input = sandbox.input(&input)?;
        sandbox.evaluate(&filter, &input).await
    });

    match verdict {
        Ok(matched) => {
            println!("{matched}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
