//! Compiling and running jq filters with [jaq](https://github.com/01mf02/jaq).
//!
//! Nothing in this module limits anything: jaq may take unbounded time, memory and stack, and it
//! is only ever called inside a worker process.
//!
//! # Compiling only what a filter uses
//!
//! jaq compiles its whole standard library, about 200 definitions and as many native functions,
//! into every filter: compiling `.a == 1` takes 0.4 ms and the result holds 110 kB. Here a filter
//! is compiled with only the definitions and natives its source can reach, which takes a few
//! microseconds and holds about ten kilobytes.
//!
//! What a filter can reach is over-approximated by name: every word in its source, and then
//! every name called from a definition already included, whatever the arity. Everything that
//! shares a name with something reachable is kept, in its original order, so a call resolves to
//! the same definition as with the whole library. A name the approximation missed cannot resolve
//! to anything else; it fails to compile, and the filter is then compiled again with the whole
//! library, so the result is the same either way.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use jaq_core::{
    Compiler, Ctx, Vars,
    load::{
        self, Arena, File, Loader,
        lex::{Lexer, StrPart, Tok, Token},
        parse::{BinaryOp, Def, Pattern, Term},
    },
    path::Part,
};

use crate::value::{self, Data, Value};

pub type Filter = jaq_core::Filter<Data>;

/// Definitions added to jaq's library.
///
/// `input` and `inputs` read further inputs, and a worker has none: they produce nothing, as they
/// do in jq at the end of its input.
const EXTRA_DEFS: &str = "def inputs: empty; def input: empty;";

/// jaq's library, parsed, and what each definition calls.
struct Prelude {
    defs: Vec<Def>,
    /// Indices into `defs`, by name.
    by_name: HashMap<&'static str, Vec<usize>>,
    /// The names each definition calls.
    calls: Vec<Vec<&'static str>>,
}

static PRELUDE: OnceLock<Prelude> = OnceLock::new();

/// How many valid filters had to be compiled with the whole library. Only for tests: it stays at
/// zero unless the over-approximation above misses a name. (Invalid filters always end up there,
/// so that their error is the one the whole library gives.)
pub static FULL_COMPILES: AtomicUsize = AtomicUsize::new(0);

/// Parses jaq's library. Called in the dispatcher before it forks any worker, so that every
/// worker starts with it.
pub fn init() {
    prelude();
}

fn prelude() -> &'static Prelude {
    PRELUDE.get_or_init(|| {
        let extra = load::parse(EXTRA_DEFS, |p| p.defs()).unwrap_or_default();
        let defs: Vec<Def> = jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs())
            .chain(extra)
            .collect();
        let mut by_name: HashMap<_, Vec<_>> = HashMap::new();
        let mut calls = Vec::with_capacity(defs.len());
        for (index, def) in defs.iter().enumerate() {
            by_name.entry(def.name).or_default().push(index);
            let mut names = HashSet::new();
            term_names(&def.body, &mut names);
            calls.push(names.into_iter().collect());
        }
        Prelude {
            defs,
            by_name,
            calls,
        }
    })
}

/// Names that `term` calls, including format strings such as `@base64`.
fn term_names<S: Copy + Eq + std::hash::Hash>(term: &Term<S>, names: &mut HashSet<S>) {
    match term {
        Term::Id | Term::Recurse | Term::Num(_) | Term::Break(_) | Term::Var(_) => {}
        Term::Str(format, parts) => {
            names.extend(*format);
            for part in parts {
                if let StrPart::Term(term) = part {
                    term_names(term, names);
                }
            }
        }
        Term::Arr(term) => {
            if let Some(term) = term {
                term_names(term, names);
            }
        }
        Term::Obj(entries) => {
            for (key, value) in entries {
                term_names(key, names);
                if let Some(value) = value {
                    term_names(value, names);
                }
            }
        }
        Term::Neg(term) | Term::Label(_, term) => term_names(term, names),
        Term::BinOp(l, op, r) => {
            if let BinaryOp::Pipe(Some(pattern)) = op {
                pattern_names(pattern, names);
            }
            term_names(l, names);
            term_names(r, names);
        }
        Term::Fold(_, term, pattern, args) => {
            term_names(term, names);
            pattern_names(pattern, names);
            args.iter().for_each(|arg| term_names(arg, names));
        }
        Term::TryCatch(term, catch) => {
            term_names(term, names);
            if let Some(catch) = catch {
                term_names(catch, names);
            }
        }
        Term::IfThenElse(branches, otherwise) => {
            for (condition, then) in branches {
                term_names(condition, names);
                term_names(then, names);
            }
            if let Some(otherwise) = otherwise {
                term_names(otherwise, names);
            }
        }
        Term::Def(defs, term) => {
            for def in defs {
                term_names(&def.body, names);
            }
            term_names(term, names);
        }
        Term::Call(name, args) => {
            names.insert(*name);
            args.iter().for_each(|arg| term_names(arg, names));
        }
        Term::Path(term, path) => {
            term_names(term, names);
            for (part, _) in &path.0 {
                match part {
                    Part::Index(index) => term_names(index, names),
                    Part::Range(from, upto) => {
                        from.iter().chain(upto).for_each(|t| term_names(t, names));
                    }
                }
            }
        }
    }
}

fn pattern_names<S: Copy + Eq + std::hash::Hash>(pattern: &Pattern<S>, names: &mut HashSet<S>) {
    match pattern {
        Pattern::Var(_) => {}
        Pattern::Arr(patterns) => patterns.iter().for_each(|p| pattern_names(p, names)),
        Pattern::Obj(entries) => {
            for (key, pattern) in entries {
                term_names(key, names);
                pattern_names(pattern, names);
            }
        }
    }
}

/// Every word and format in `tokens`, a superset of the names the source calls.
fn token_words<'s>(tokens: &[Token<&'s str>], words: &mut HashSet<&'s str>) {
    for Token(text, token) in tokens {
        match token {
            Tok::Word | Tok::Fmt => {
                words.insert(*text);
            }
            Tok::Str(parts) => {
                for part in parts {
                    if let StrPart::Term(token) = part {
                        token_words(std::slice::from_ref(token), words);
                    }
                }
            }
            Tok::Block(tokens) => token_words(tokens, words),
            Tok::Var | Tok::Num | Tok::Sym => {}
        }
    }
}

/// The names `code` can reach, or `None` if it does not even lex.
fn reachable<'s>(code: &'s str, prelude: &Prelude) -> Option<HashSet<&'s str>> {
    let tokens = Lexer::new(code).lex().ok()?;
    let mut names = HashSet::new();
    token_words(&tokens, &mut names);

    let mut pending: Vec<&str> = names.iter().copied().collect();
    while let Some(name) = pending.pop() {
        for index in prelude.by_name.get(name).into_iter().flatten() {
            for &called in prelude.calls.get(*index).into_iter().flatten() {
                if names.insert(called) {
                    pending.push(called);
                }
            }
        }
    }
    Some(names)
}

pub fn compile(code: &str) -> Result<Filter, String> {
    let prelude = prelude();
    if let Some(names) = reachable(code, prelude) {
        let defs = prelude
            .defs
            .iter()
            .filter(|def| names.contains(def.name))
            .cloned();
        if let Ok(filter) = compile_with(code, defs, |name| names.contains(name)) {
            return Ok(filter);
        }
    }
    let compiled = compile_with(code, prelude.defs.iter().cloned(), |_| true);
    if compiled.is_ok() {
        FULL_COMPILES.fetch_add(1, Ordering::Relaxed);
    }
    compiled
}

fn compile_with(
    code: &str,
    defs: impl IntoIterator<Item = Def>,
    keep_native: impl Fn(&str) -> bool,
) -> Result<Filter, String> {
    let arena = Arena::default();
    let modules = Loader::new(defs)
        .load(&arena, File { code, path: () })
        .map_err(|errors| {
            // Only one file is loaded, so there is one entry.
            match errors.first() {
                Some((_, error)) => format!("{error:?}"),
                None => "the filter could not be parsed".to_owned(),
            }
        })?;

    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(value::json_funs())
        .filter(|(name, _, _)| keep_native(name));

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
/// produces no boolean at all does not match. `halt` raises an exception in jaq 3, which is
/// skipped like an error.
pub fn matches(filter: &Filter, input: Value) -> bool {
    let ctx = Ctx::<Data>::new(&filter.lut, Vars::new([]));
    filter
        .id
        .run((ctx, input))
        .find_map(|output| output.ok().and_then(|value| value.as_boolean()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use jaq_core::data::JustLut;
    use jaq_json::Val;
    use serde_json::json;

    use super::*;
    use crate::{doc, value::DocRef};

    type ValFilter = jaq_core::Filter<JustLut<Val>>;

    /// The reference: jaq as its documentation uses it, on values parsed from JSON text.
    fn compile_reference(code: &str) -> Result<ValFilter, ()> {
        let defs = jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs())
            .chain(load::parse(EXTRA_DEFS, |p| p.defs()).unwrap());
        let funs = jaq_core::funs()
            .chain(jaq_std::funs())
            .chain(jaq_json::funs());
        let arena = Arena::default();
        let modules = Loader::new(defs)
            .load(&arena, File { code, path: () })
            .map_err(drop)?;
        Compiler::default()
            .with_funs(funs)
            .compile(modules)
            .map_err(drop)
    }

    /// Outputs as text: values as JSON, errors as what `catch` would see.
    fn reference_outputs(filter: &ValFilter, input: &serde_json::Value) -> Vec<String> {
        let input = jaq_json::read::parse_single(input.to_string().as_bytes()).unwrap();
        let ctx = Ctx::<JustLut<Val>>::new(&filter.lut, Vars::new([]));
        filter
            .id
            .run((ctx, input))
            .take(50)
            .map(|output| match output.map_err(|e| e.get_err()) {
                Ok(value) => format!("{value}"),
                Err(Ok(error)) => format!("error: {}", error.into_val()),
                Err(Err(_)) => "halt".to_owned(),
            })
            .collect()
    }

    fn outputs(filter: &Filter, input: &serde_json::Value) -> Vec<String> {
        let mut buffer = Vec::new();
        doc::encode(input, usize::MAX, &mut buffer).unwrap();
        let doc: value::Document = Rc::new(buffer);
        let ctx = Ctx::<Data>::new(&filter.lut, Vars::new([]));
        filter
            .id
            .run((ctx, Value::Doc(DocRef::root(doc))))
            .take(50)
            .map(|output| match output.map_err(|e| e.get_err()) {
                Ok(value) => format!("{value}"),
                Err(Ok(error)) => format!("error: {}", error.into_val()),
                Err(Err(_)) => "halt".to_owned(),
            })
            .collect()
    }

    fn inputs() -> Vec<serde_json::Value> {
        vec![
            json!({
                "topic": "orders", "partition": 3, "offset": 12345, "key": "user-42",
                "payload": r#"{"priority":"high","tenant":"acme","items":[1,2,3]}"#,
                "headers": {"x-user": "michal", "traceparent": "00-abc-def-01", "n": null},
                "items": [
                    {"id": 1, "name": "snow", "price": 1.5, "tags": ["a", "b"]},
                    {"id": 2, "name": "ice", "price": 20, "tags": []},
                    {"id": 3, "name": "slush", "price": -3, "tags": ["b"], "extra": {"deep": [[1], [2, [3]]]}},
                ],
                "empty_obj": {}, "empty_arr": [], "flag": false, "big": 18446744073709551615u64,
                "unicode": "zażółć ☃",
            }),
            json!([1, "two", null, true, [3], {"four": 4}]),
            json!("just a string"),
            json!(42),
            json!(null),
        ]
    }

    /// Filters that exercise every operation of `Value`, its fast paths and its fallbacks.
    const FILTERS: &[&str] = &[
        ".",
        ".topic",
        ".headers[\"x-user\"] == \"michal\"",
        ".headers.n",
        ".missing",
        ".missing.deeper",
        ".items[0].name",
        ".items[-1].extra.deep[1][1][0]",
        ".items[5]",
        ".items[-5]",
        ".items[1.7]",
        ".[0]",
        ".[-1]",
        ".[\"four\"]?",
        ".[]",
        ".[]?",
        ".items[] | .name",
        ".items[] | select(.price > 1) | .id",
        ".items | map(.price) | add",
        ".items | length",
        ".headers | length",
        ".unicode | length",
        ".topic | length",
        "length",
        ".partition | length",
        ".flag | length",
        ".headers | keys",
        ".headers | keys_unsorted",
        ".headers | to_entries",
        ".headers | to_entries | from_entries",
        ".headers | with_entries(.value |= tostring)",
        ".items | map(has(\"extra\"))",
        ".headers | has(\"x-user\"), has(\"nope\")",
        ".items | has(0), has(7)",
        ".items[0].tags | contains([\"a\"])",
        "contains({\"headers\": {\"x-user\": \"mi\"}})",
        ".topic | contains(\"rde\")",
        ".items[0].tags | indices(\"b\")",
        ".topic | indices(\"r\")",
        "[.items[].id] | bsearch(2)",
        ".payload | fromjson | .priority == \"high\" and (.tenant | test(\"^ac\"))",
        ".payload | fromjson | .items | add",
        "tojson",
        ".items[0] | tojson",
        ".headers | tostring",
        ".topic | ascii_upcase",
        ".topic | startswith(\"ord\"), endswith(\"ers\"), ltrimstr(\"or\"), rtrimstr(\"rs\")",
        ".key | split(\"-\")",
        ".key | test(\"user-\\\\d+\")",
        ".unicode | explode | implode",
        ".topic[1:3]",
        ".items[1:]",
        ".items[:-1] | length",
        ".items | first, last",
        ".items | sort_by(.price) | map(.id)",
        ".items | group_by(.tags | length) | map(length)",
        ".items | min_by(.price), max_by(.id)",
        ".items | sort",
        ".items | unique_by(.tags | length) | length",
        "[.items[].price] | sort",
        ".items | reverse | .[0].id",
        "[paths] | length",
        "[.. | numbers] | add",
        "[.. | strings] | length",
        "[leaf_paths] | length",
        "getpath([\"items\", 0, \"tags\", 1])",
        "[getpath([\"items\", 0, \"tags\"], [\"nope\"])]",
        ".items[0].tags[0] = \"z\" | .items[0].tags",
        ".items[] |= .id",
        ".items[0] |= with_entries(select(.key != \"tags\"))",
        ".headers.new = 1 | .headers | keys",
        ".partition += 1 | .partition",
        "del(.headers) | keys",
        "del(.items[0, 2]) | .items | length",
        "to_entries | map(.key) | sort",
        ".items | map(.price) | max, min",
        ".partition == 3, .partition < 4, .partition != 3.0, .offset >= 12345",
        ".big, .big + 1, (.big | tostring)",
        ".items[0].price * 2, .partition / 2, .partition % 2, -.partition",
        ".topic + \"-x\", .topic * 2",
        ".items + [1] | length",
        ".headers + {\"a\": 1} | keys",
        ".headers * {\"x-user\": {\"a\": 1}}",
        ".headers - [1]",
        "[.items[].tags] - [[]]",
        ".flag | not",
        "if .flag then 1 elif .partition then 2 else 3 end",
        ".missing // \"default\"",
        "[.headers[]] | length",
        "try error(\"x\") catch .",
        "try (.topic | .[0]) catch .",
        "try (.items | .a) catch .",
        "try error({\"a\": 1}) catch .a",
        ".[] as [$a, $b] | $a",
        ". as {topic: $t, items: [$first]} | $t, $first.id",
        "reduce .items[] as $i (0; . + $i.price)",
        "foreach .items[] as $i (0; . + 1; [., $i.id])",
        "label $out | .items[] | if .id == 2 then ., break $out else . end | .id",
        "limit(2; .items[]) | .id",
        "first(.items[] | select(.id > 1)) | .name",
        "any(.items[]; .price < 0), all(.items[]; .id > 0)",
        "[.items[] | .tags | length] | add",
        ".items | map(select(.tags | index(\"b\"))) | length",
        "path(.items[0].name)",
        "[paths(type == \"number\")] | length",
        "tostream | select(length == 2) | .[1]",
        "[splits(\"-\")]?",
        ".unicode | @base64 | @base64d",
        "@json \"v: \\(.topic)\"",
        ".topic as $t | \"\\($t)/\\(.partition)\"",
        ".headers | to_entries | map(\"\\(.key)=\\(.value)\") | join(\",\")",
        "[.items[] | {id, name}]",
        "{(.topic): .partition}",
        "type, (.items | type), (.headers.n | type)",
        "[.[] | type]?",
        "isvalid(.items[0])?",
        "env | length",
        "input, [inputs]",
        "halt, 1",
        "now | type",
        "walk(if type == \"number\" then 0 else . end) | .items[0]",
        "[.items[] | .price | floor]",
        "[.items[].price | tostring]",
        ".items | map(.name) | index(\"ice\")",
        "ascii",
        ".items | combinations? | length",
        "splits(\"x\")?",
        "@text, @csv?, @sh?",
        ".items | .[0] == .[0], .[0] == .[1], .[0] < .[1]",
        "[.items[0], .items[0]] | unique | length",
        "{a: .items[0]} == {a: .items[0]}",
        ".headers == .headers, .headers < .items",
        ".items[0].tags == [\"a\", \"b\"]",
        "null == .missing, false == .flag, .flag < true",
        "tojson | fromjson == .",
        "[limit(3; repeat(.partition))]?",
        "getpath([\"a\", \"b\"])?",
        "to_entries? | length",
        "keys? | length",
        "splits(1)?",
        "ltrimstr(1)",
        "tostring | length > 0",
    ];

    #[test]
    fn same_outputs_as_jaq_on_json() {
        let before = FULL_COMPILES.load(Ordering::Relaxed);
        let mut failures = Vec::new();
        for code in FILTERS {
            let Ok(reference) = compile_reference(code) else {
                assert!(compile(code).is_err(), "`{code}` does not compile in jaq");
                continue;
            };
            let filter = compile(code).unwrap_or_else(|e| panic!("`{code}`: {e}"));
            for input in inputs() {
                let expected = reference_outputs(&reference, &input);
                let actual = outputs(&filter, &input);
                if expected != actual {
                    failures.push(format!(
                        "`{code}` on {input}\n  jaq:  {expected:?}\n  here: {actual:?}"
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert_eq!(
            FULL_COMPILES.load(Ordering::Relaxed),
            before,
            "every filter above should compile with the pruned library"
        );
    }

    #[test]
    fn compile_errors() {
        for code in ["", "snow", ".a |", "idk | whatever"] {
            assert!(compile(code).is_err(), "`{code}`");
        }
        let Err(error) = compile("no_such_filter") else {
            panic!()
        };
        assert!(error.contains("no_such_filter"), "{error}");
        // The same message as with the whole library.
        let Err(error) = compile("map(.) | no_such_filter(1)") else {
            panic!()
        };
        assert!(error.contains("no_such_filter"), "{error}");
    }

    #[test]
    fn pruned_is_small() {
        let names = reachable(".a == 1", prelude()).unwrap();
        assert!(names.len() < 10, "{names:?}");
        let names = reachable("map(.a) | to_entries", prelude()).unwrap();
        assert!(names.contains("key_values"), "{names:?}");
    }

    #[test]
    fn halt_does_not_exit() {
        let filter = compile("halt, true").unwrap();
        let mut buffer = Vec::new();
        doc::encode(&json!(null), usize::MAX, &mut buffer).unwrap();
        let input = Value::Doc(DocRef::root(Rc::new(buffer)));
        assert!(matches(&filter, input));
    }
}
