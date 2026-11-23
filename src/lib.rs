//! Evaluates untrusted jq filters on untrusted input, with every evaluation bounded in CPU time,
//! memory and stack, and unable to take the calling service down.
//!
//! The evaluator, [jaq](https://github.com/01mf02/jaq), takes no measures against resource
//! exhaustion: a filter, or the data it is run on, can loop forever, allocate without bound or
//! overflow the stack, and in-process each of those ends with the service stuck or dead. Here
//! filters run in separate worker processes instead, where the kernel enforces the limits and a
//! worker that breaks one is simply killed and replaced.
//!
//! ```text
//!                   control socket
//!   service  ---------------------------  dispatcher      forked first thing in `main`
//!      |      "spawn" / "release(pid)"         |
//!      |                                       | fork
//!      |           worker socket               v
//!      +--------------------------------   worker(s)      one request at a time each
//!      |     filter ids / "done"               ^
//!      |                                       | read-only
//!      +-------- input arena (shared memory) --+
//! ```
//!
//! - The **dispatcher** ([`Dispatcher::fork`]) is forked before the service starts any thread. It
//!   stays single-threaded and tiny, and does nothing but fork and reap workers.
//! - A **worker** is a fork of the dispatcher. Its socket is created by the dispatcher and the
//!   service's end is passed over the control socket (`SCM_RIGHTS`), so requests go from the
//!   service to the worker directly. It keeps every filter it compiles until told to forget it.
//! - The **service** side ([`Sandbox`]) keeps a pool of workers and hands each request to an idle
//!   one.
//! - Inputs are encoded once into an **arena** of memory that every worker can read, and read in
//!   place: a filter pays only for the parts of the input it looks at.
//!
//! Filters are long-lived: [`Sandbox::compile`] returns a [`Filter`] to evaluate as often as
//! needed. Inputs are encoded once with [`Sandbox::input`], straight from any
//! [`serde::Serialize`] type, and can go to any number of filters, in one round trip with
//! [`Sandbox::evaluate_many`].
//!
//! ```no_run
//! use jq_sandbox::{Config, Dispatcher};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Before anything else: no thread may exist yet.
//!     let dispatcher = Dispatcher::fork(Config::default())?;
//!
//!     let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
//!     runtime.block_on(async {
//!         let sandbox = dispatcher.connect()?;
//!         let high = sandbox.compile(r#".priority == "high""#).await?;
//!         let acme = sandbox.compile(r#".tenant | startswith("ac")"#).await?;
//!
//!         let message = sandbox.input(&serde_json::json!({"priority": "high", "tenant": "acme"}))?;
//!         assert!(sandbox.evaluate(&high, &message).await?);
//!         let verdicts = sandbox.evaluate_many(&[&high, &acme], &message).await;
//!         assert!(verdicts.into_iter().all(|verdict| matches!(verdict, Ok(true))));
//!         Ok(())
//!     })
//! }
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("jq-sandbox relies on Linux process primitives and only builds for Linux");

mod config;
mod control;
mod dispatcher;
mod doc;
mod error;
mod jq;
mod sandbox;
mod shm;
mod value;
mod wire;
mod worker;

pub use config::Config;
pub use dispatcher::Dispatcher;
pub use error::{Error, Limit};
pub use sandbox::{Filter, Input, Sandbox};
