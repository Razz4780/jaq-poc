//! Compiling and running jq filters with [jaq](https://github.com/01mf02/jaq).
//!
//! Nothing in this module limits anything: jaq may take unbounded time, memory and stack, and it
//! is only ever called inside a worker process.

use jaq_core::{
    Compiler, Ctx, Error, Exn, Native, RcIter,
    box_iter::box_once,
    load::{Arena, File, Loader},
};
use jaq_json::Val;

pub type Filter = jaq_core::Filter<Native<Val>>;

/// Builtins that end the process they run in. In a worker that is harmless, but it costs a new
/// worker each time, so they raise an ordinary jq error instead.
///
/// They are replaced rather than left out of the function table: jaq's jq-defined prelude refers
/// to them (`halt_error/0` is defined through `halt_error/1`), and with a name missing no filter
/// compiles at all.
const DISABLED: &[&str] = &["halt", "halt_error"];

pub fn compile(code: &str) -> Result<Filter, String> {
    let loader = Loader::new(jaq_std::defs().chain(jaq_json::defs()));
    let arena = Arena::default();
    let modules = loader
        .load(&arena, File { code, path: () })
        .map_err(|errors| {
            // Only one file is loaded, so there is one entry.
            match errors.first() {
                Some((_, error)) => format!("{error:?}"),
                None => "the filter could not be parsed".to_owned(),
            }
        })?;

    let funs = jaq_std::funs()
        .chain(jaq_json::funs())
        .map(|(name, arity, native)| {
            if DISABLED.contains(&name) {
                let disabled =
                    Native::new(|_, _| box_once(Err(Exn::from(Error::str("not available")))));
                (name, arity, disabled)
            } else {
                (name, arity, native)
            }
        });

    Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errors| {
            errors
                .into_iter()
                .flat_map(|(_, undefined)| undefined)
                .map(|(name, kind)| format!("undefined {}: {name}", kind.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        })
}

/// Runs `filter` on `input` and reports its first boolean output.
///
/// Outputs that are not booleans, and errors the filter raises, are skipped. A filter that
/// produces no boolean at all does not match.
pub fn matches(filter: &Filter, input: Val) -> bool {
    let inputs = RcIter::new(core::iter::empty());
    filter
        .run((Ctx::new([], &inputs), input))
        .find_map(|output| match output {
            Ok(Val::Bool(value)) => Some(value),
            _ => None,
        })
        .unwrap_or(false)
}
