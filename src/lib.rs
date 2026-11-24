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
//!   service ---- "spawn" ---->  trampoline      forked first thing in `main`
//!      |   <--- pidfd, socket ---   |
//!      |                            | clone(CLONE_PARENT)
//!      |       worker socket        v
//!      +------------------------> worker(s)     children of the service, one request at a time
//! ```
//!
//! - The **trampoline** is forked by [`Sandbox::new`] before the service starts any thread. It
//!   stays single-threaded and does nothing but fork workers on request.
//! - A **worker** is a copy of the trampoline, but a child of the service. The service holds it
//!   through a pidfd, talks to it over a socket of its own, and reaps it to learn which limit, if
//!   any, killed it.
//! - The **service** side ([`Sandbox`]) keeps a pool of workers and hands each request to an idle
//!   one.
//!
//! ```no_run
//! use jq_sandbox::{Config, Sandbox};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Before anything else: no thread may exist yet.
//!     let sandbox = Sandbox::new(Config::default())?;
//!
//!     let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
//!     runtime.block_on(async {
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
mod error;
mod jq;
mod sandbox;
mod spawner;
mod wire;
mod worker;

pub use config::Config;
pub use error::{Error, Limit};
pub use sandbox::{Filter, Input, Sandbox};
