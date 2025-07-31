use std::{io::Read, process::ExitCode};

use jaq_core::{
    Ctx, RcIter,
    load::{Arena, File, Loader},
};
use jaq_json::Val;
use serde_json::Value;

fn main() -> ExitCode {
    let args = std::env::args().collect::<Vec<_>>();

    let code = match args.as_slice() {
        [binary, arg] if arg == "--help" => {
            eprintln!("USAGE: {binary} <query in JAQ format>");
            eprintln!(
                "The program will read JSON input from stdin, and print debug of returned values to stdout."
            );
            return ExitCode::SUCCESS;
        }
        [_, code] => code.as_str(),
        _ => {
            eprintln!(
                "USAGE: {} <query in JAQ format>",
                args.first().map(String::as_str).unwrap_or("<binary>")
            );
            eprintln!(
                "The program will read JSON input from stdin, and print debug of returned values to stdout."
            );
            return ExitCode::FAILURE;
        }
    };

    let mut json = Vec::new();
    std::io::stdin()
        .read_to_end(&mut json)
        .expect("failed to read input from stdin");
    let input: Value = serde_json::from_slice(&json).expect("failed to parse input as JSON");

    let program = File { code, path: () };
    let loader = Loader::new(jaq_std::defs().chain(jaq_json::defs()));
    let arena = Arena::default();

    let modules = loader
        .load(&arena, program)
        .expect("failed to parse the filter");
    let filter = jaq_core::Compiler::default()
        .with_funs(jaq_std::funs().chain(jaq_json::funs()))
        .compile(modules)
        .expect("failed to compile the filter");
    let inputs = RcIter::new(core::iter::empty());
    let out = filter.run((Ctx::new([], &inputs), Val::from(input)));

    for item in out {
        match item {
            Ok(item) => println!("{item:?}"),
            Err(error) => {
                // This can happen if the input JSON does not match the query's expectations,
                // e.g. at some point we try to index a string. This is not a fatal error.
                eprintln!("query error: {error:?}");
            }
        }
    }

    ExitCode::SUCCESS
}
