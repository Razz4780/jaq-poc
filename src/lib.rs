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
//!      +--------------------------------   worker(s)      one evaluation at a time each
//!           filter + input / verdict
//! ```
//!
//! - The **dispatcher** ([`Dispatcher::fork`]) is forked before the service starts any thread. It
//!   stays single-threaded and tiny, and does nothing but fork and reap workers.
//! - A **worker** is a fork of the dispatcher. Its socket is created by the dispatcher and the
//!   service's end is passed over the control socket (`SCM_RIGHTS`), so requests go from the
//!   service to the worker directly.
//! - The **service** side ([`Sandbox`]) keeps a pool of workers and hands each evaluation to an
//!   idle one.
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
//!         let message = serde_json::json!({"priority": "high"});
//!         assert!(sandbox.evaluate(r#".priority == "high""#, &message).await?);
//!         Ok(())
//!     })
//! }
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("jq-sandbox relies on Linux process primitives and only builds for Linux");

mod config;
mod control;
mod dispatcher;
mod error;
mod jq;
mod sandbox;
mod wire;
mod worker;

pub use config::Config;
pub use dispatcher::Dispatcher;
pub use error::{Error, Limit};
pub use sandbox::Sandbox;
