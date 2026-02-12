use jaq_core::{
    Ctx, RcIter,
    load::{Arena, File, Loader},
};
use jaq_json::Val;
use nix::{libc::rlim_t, sys::resource::Resource};
use safejaq_types::EvaluationRequest;
use std::io::Read;

fn main() {
    set_limits();

    let mut buf = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .expect("failed to read stdin");
    let request = serde_json::from_slice::<EvaluationRequest>(&buf)
        .expect("failed to parse EvaluationRequest");
    let result = evaluate(request);
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &result).expect("failed to write EvaluationResult");
}

fn set_limits() {
    // Set the total virtual memory limit
    let requested = std::env::var(safejaq_types::MEMORY_LIMIT_ENV)
        .unwrap_or_else(|error| {
            panic!(
                "{} env not set or malformed: {error}",
                safejaq_types::MEMORY_LIMIT_ENV
            )
        })
        .parse::<rlim_t>()
        .unwrap_or_else(|error| {
            panic!("{} env malformed: {error}", safejaq_types::MEMORY_LIMIT_ENV)
        });
    let (soft_limit, _) =
        nix::sys::resource::getrlimit(Resource::RLIMIT_AS).expect("failed to get RLIMIT_AS");
    if requested < soft_limit {
        nix::sys::resource::setrlimit(Resource::RLIMIT_AS, requested, requested)
            .expect("failed to set RLIMIT_AS");
    }

    // Set the CPU time limit
    let requested = std::env::var(safejaq_types::TIME_LIMIT_ENV)
        .unwrap_or_else(|error| {
            panic!(
                "{} env not set or malformed: {error}",
                safejaq_types::TIME_LIMIT_ENV
            )
        })
        .parse::<rlim_t>()
        .unwrap_or_else(|error| panic!("{} env malformed: {error}", safejaq_types::TIME_LIMIT_ENV));
    let (soft_limit, _) =
        nix::sys::resource::getrlimit(Resource::RLIMIT_CPU).expect("failed to get RLIMIT_CPU");
    if requested < soft_limit {
        nix::sys::resource::setrlimit(Resource::RLIMIT_CPU, requested, requested)
            .expect("failed to set RLIMIT_CPU");
    }

    // Disable core dumps
    nix::sys::resource::setrlimit(Resource::RLIMIT_CORE, 0, 0).expect("failed to set RLIMIT_CORE");
}

fn evaluate(request: EvaluationRequest) -> Result<bool, String> {
    let program = File {
        code: request.filter.as_str(),
        path: (),
    };
    let loader = Loader::new(jaq_std::defs().chain(jaq_json::defs()));
    let arena = Arena::default();
    let modules = loader
        .load(&arena, program)
        .map_err(|errors| format!("failed to parse the filter: {errors:?}"))?;

    let filter = jaq_core::Compiler::default()
        .with_funs(jaq_std::funs().chain(jaq_json::funs()))
        .compile(modules)
        .map_err(|errors| format!("failed to compile the filter: {errors:?}"))?;

    let inputs = RcIter::new(core::iter::empty());
    let mut out = filter.run((Ctx::new([], &inputs), Val::from(request.payload)));

    let found_match = out
        .find_map(|item| {
            if let Ok(Val::Bool(value)) = &item {
                Some(*value)
            } else {
                None
            }
        })
        .unwrap_or(false);
    Ok(found_match)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use safejaq_types::EvaluationRequest;

    #[rstest]
    #[case(
        "(.user_id // \"\") | test(\"^(liron|\\\\d+)$\")",
        serde_json::json!({
            "user_id": "liron",
        }),
        Some(true)
    )]
    #[case(
        "(.user_id // \"\") | test(\"^(liron|\\\\d+)$\")",
        serde_json::json!({
            "user_id": "definitely not liron",
        }),
        Some(false)
    )]
    #[case(
        "i am really not a valid filter",
        serde_json::json!({}),
        None,
    )]
    #[test]
    fn test_evaluate(
        #[case] filter: &str,
        #[case] payload: serde_json::Value,
        #[case] expected: Option<bool>,
    ) {
        let result = super::evaluate(EvaluationRequest {
            filter: filter.into(),
            payload,
        });

        match (result, expected) {
            (Ok(true), Some(true)) => {}
            (Ok(false), Some(false)) => {}
            (Err(..), None) => {}
            (result, Some(value)) => panic!("unexpected result: {result:?}, expected {value}"),
            (result, None) => panic!("unexpected result: {result:?}, expected an error"),
        }
    }
}
