//! The values filters run on.
//!
//! A [`Value`] is either a part of the encoded input, read where it lies ([`Value::Doc`]), or a
//! value the filter built, which is jaq's own JSON value ([`Value::Val`]). Reading the input,
//! which is what nearly all filters mostly do, stays on the first kind: indexing, iterating,
//! comparing a string or a number, `length`, `has`. Anything else turns the part of the input it
//! needs into a [`Val`] and hands the work to jaq's implementation, so that every operation means
//! exactly what it means in jaq.
//!
//! The document is held through a reference count rather than a borrow: jaq requires the
//! iterators that `.[]` produces to be `'static`, which no borrowing value can satisfy.

use std::{borrow::Cow, cell::RefCell, cmp::Ordering, fmt, rc::Rc};

use jaq_core::{
    Bind, Ctx, DataT, Error, Exn, RunPtr, ValR, ValX, ValXs, Vars,
    box_iter::{BoxIter, box_once},
    data::JustLut,
    load::{Arena, File, Loader},
    native::{Fun, bome, run, v},
    path::Opt,
    val::Range,
};
use jaq_json::Val;

use crate::doc::{Children, Elements, Entries, Kind, Node};

/// Filters compiled for [`Value`].
pub struct Data;

impl DataT for Data {
    type V<'a> = Value;
    type Data<'a> = &'a jaq_core::Lut<Data>;
}

/// An encoded document.
pub type Document = Rc<dyn AsRef<[u8]>>;

/// A position in an encoded document.
#[derive(Clone)]
pub struct DocRef {
    doc: Document,
    at: usize,
}

impl DocRef {
    pub fn root(doc: Document) -> Self {
        Self { doc, at: 0 }
    }

    fn node(&self) -> Node<'_> {
        Node {
            doc: (*self.doc).as_ref(),
            at: self.at,
        }
    }

    fn child(&self, node: Node<'_>) -> Value {
        Value::Doc(Self {
            doc: self.doc.clone(),
            at: node.at,
        })
    }
}

/// A value a filter runs on, see the module documentation.
#[derive(Clone)]
pub enum Value {
    Doc(DocRef),
    Val(Val),
}

impl Value {
    /// The value as jaq's own type, built from the document if needed.
    pub fn into_val(self) -> Val {
        match self {
            Self::Doc(doc) => doc.node().to_val(),
            Self::Val(val) => val,
        }
    }

    /// The value, if it is a boolean.
    pub fn as_boolean(&self) -> Option<bool> {
        match self.light() {
            Light::Bool(value) => Some(value),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'_, Val> {
        match self {
            Self::Doc(doc) => Cow::Owned(doc.node().to_val()),
            Self::Val(val) => Cow::Borrowed(val),
        }
    }

    fn doc_kind(&self) -> Option<Kind<'_>> {
        match self {
            Self::Doc(doc) => Some(doc.node().kind()),
            Self::Val(_) => None,
        }
    }

    fn light(&self) -> Light<'_> {
        match self {
            Self::Doc(doc) => match doc.node().kind() {
                Kind::Null => Light::Null,
                Kind::Bool(value) => Light::Bool(value),
                Kind::Str(bytes) => Light::Str(bytes),
                _ => Light::Other,
            },
            Self::Val(Val::Null) => Light::Null,
            Self::Val(Val::Bool(value)) => Light::Bool(*value),
            Self::Val(Val::TStr(bytes) | Val::BStr(bytes)) => Light::Str(bytes),
            Self::Val(_) => Light::Other,
        }
    }

    /// The value as an array or object index, if it is a string.
    fn as_key(&self) -> Option<&[u8]> {
        match self.light() {
            Light::Str(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The value as an array index, if it is a machine-sized integer.
    fn as_index(&self) -> Option<isize> {
        match self {
            Self::Doc(doc) => match doc.node().kind() {
                Kind::Int(value) => isize::try_from(value).ok(),
                _ => None,
            },
            Self::Val(Val::Num(jaq_json::Num::Int(value))) => Some(*value),
            Self::Val(_) => None,
        }
    }

    fn is_number(&self) -> bool {
        match self {
            Self::Doc(doc) => matches!(
                doc.node().kind(),
                Kind::Int(_) | Kind::Float(_) | Kind::BigInt(_)
            ),
            Self::Val(val) => matches!(val, Val::Num(_)),
        }
    }
}

/// Values that compare without building anything, the way [`Val`] compares them.
enum Light<'a> {
    Null,
    Bool(bool),
    Str(&'a [u8]),
    Other,
}

/// Order between two light values. jq orders null, booleans, numbers, strings, arrays, objects.
fn light_cmp(l: &Light<'_>, r: &Light<'_>) -> Option<Ordering> {
    fn rank(light: &Light<'_>) -> u8 {
        match light {
            Light::Null => 0,
            Light::Bool(_) => 1,
            Light::Str(_) => 3,
            Light::Other => 255,
        }
    }
    match (l, r) {
        (Light::Other, _) | (_, Light::Other) => None,
        (Light::Bool(l), Light::Bool(r)) => Some(l.cmp(r)),
        (Light::Str(l), Light::Str(r)) => Some(l.cmp(r)),
        (l, r) => Some(rank(l).cmp(&rank(r))),
    }
}

fn conv_err(error: Error<Val>) -> Error<Value> {
    // `catch` sees exactly what it would have seen on the original error.
    Error::new(Value::Val(error.into_val()))
}

fn conv_r(result: ValR<Val>) -> ValR<Value> {
    result.map(Value::Val).map_err(conv_err)
}

/// An exception raised by jaq's own value code: always an error, never control flow.
fn conv_exn<'a>(exn: Exn<'_, Val>) -> Exn<'a, Value> {
    match exn.get_err() {
        Ok(error) => Exn::from(conv_err(error)),
        Err(_) => Exn::from(Error::str("unexpected exception")),
    }
}

/// Runs `f` on [`Val`]s for a function that expects one on [`Value`]s.
///
/// The update functions (`map_values` and friends) take a callback whose exceptions can be
/// control flow, which has no [`Val`] counterpart. They are kept aside here, and replaced with a
/// placeholder error that ends the update; [`unsmuggle`] puts the real exception back.
fn smuggle<'a, 's>(
    outputs: impl Iterator<Item = ValX<'a, Value>> + 's,
    stash: &'s RefCell<Option<Exn<'a, Value>>>,
) -> impl Iterator<Item = ValX<'a, Val>> + 's {
    outputs.map(move |output| {
        output.map(Value::into_val).map_err(|exn| {
            *stash.borrow_mut() = Some(exn);
            Exn::from(Error::new(Val::Null))
        })
    })
}

fn unsmuggle<'a>(result: ValX<'_, Val>, stash: RefCell<Option<Exn<'a, Value>>>) -> ValX<'a, Value> {
    match result {
        Ok(val) => Ok(Value::Val(val)),
        Err(exn) => Err(stash.into_inner().unwrap_or_else(|| conv_exn(exn))),
    }
}

/// The rest of an array or object in a document, owning its reference to the document.
struct Rest {
    doc: Document,
    at: usize,
    end: usize,
    left: usize,
}

impl Rest {
    fn new(doc: &DocRef, children: Children<'_>) -> Self {
        Self {
            doc: doc.doc.clone(),
            at: children.start,
            end: children.end,
            left: children.count,
        }
    }

    fn elements(&self) -> Elements<'_> {
        Elements {
            doc: (*self.doc).as_ref(),
            at: self.at,
            end: self.end,
            left: self.left,
        }
    }

    fn value(&self, at: usize) -> Value {
        Value::Doc(DocRef {
            doc: self.doc.clone(),
            at,
        })
    }

    fn next_element(&mut self) -> Option<Value> {
        let mut elements = self.elements();
        let at = elements.next()?.at;
        (self.at, self.left) = (elements.at, elements.left);
        Some(self.value(at))
    }

    fn next_entry(&mut self) -> Option<(Value, Value)> {
        let mut entries = Entries(self.elements());
        let (key, at) = entries
            .next()
            .map(|(key, node)| (Val::utf8_str(key.to_vec()), node.at))?;
        (self.at, self.left) = (entries.0.at, entries.0.left);
        Some((Value::Val(key), self.value(at)))
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_cow().fmt(f)
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Value {}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        if let (Self::Val(l), Self::Val(r)) = (self, other) {
            return l.cmp(r);
        }
        light_cmp(&self.light(), &other.light())
            .unwrap_or_else(|| self.to_cow().cmp(&other.to_cow()))
    }
}

macro_rules! binary_op {
    ($trait:ident, $method:ident) => {
        impl core::ops::$trait for Value {
            type Output = ValR<Value>;

            fn $method(self, rhs: Self) -> ValR<Value> {
                conv_r(core::ops::$trait::$method(self.into_val(), rhs.into_val()))
            }
        }
    };
}

binary_op!(Add, add);
binary_op!(Sub, sub);
binary_op!(Mul, mul);
binary_op!(Div, div);
binary_op!(Rem, rem);

impl core::ops::Neg for Value {
    type Output = ValR<Value>;

    fn neg(self) -> ValR<Value> {
        conv_r(-self.into_val())
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Val(Val::from(value))
    }
}

impl From<isize> for Value {
    fn from(value: isize) -> Self {
        Self::Val(Val::from(value))
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::Val(Val::from(value))
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Val(Val::from(value))
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Val(Val::from(value))
    }
}

impl From<Range<Value>> for Value {
    fn from(range: Range<Value>) -> Self {
        let range = range.start.map(Value::into_val)..range.end.map(Value::into_val);
        Self::Val(Val::from(range))
    }
}

impl FromIterator<Value> for Value {
    fn from_iter<T: IntoIterator<Item = Value>>(iter: T) -> Self {
        Self::Val(iter.into_iter().map(Value::into_val).collect())
    }
}

fn val_range<'v>(range: &Range<&'v Value>) -> (Option<Cow<'v, Val>>, Option<Cow<'v, Val>>) {
    (range.start.map(Value::to_cow), range.end.map(Value::to_cow))
}

impl jaq_core::ValT for Value {
    fn from_num(n: &str) -> ValR<Self> {
        conv_r(Val::from_num(n))
    }

    fn from_map<I: IntoIterator<Item = (Self, Self)>>(iter: I) -> ValR<Self> {
        let iter = iter.into_iter().map(|(k, v)| (k.into_val(), v.into_val()));
        conv_r(Val::from_map(iter))
    }

    fn key_values(self) -> BoxIter<'static, ValR<(Self, Self), Self>> {
        if let Self::Doc(doc) = &self {
            match doc.node().kind() {
                Kind::Arr(children) => {
                    let mut rest = Rest::new(doc, children);
                    let mut index = 0isize;
                    return Box::new(core::iter::from_fn(move || {
                        let value = rest.next_element()?;
                        index += 1;
                        Some(Ok((Self::from(index - 1), value)))
                    }));
                }
                Kind::Obj(children) => {
                    let mut rest = Rest::new(doc, children);
                    return Box::new(core::iter::from_fn(move || rest.next_entry().map(Ok)));
                }
                _ => {}
            }
        }
        Box::new(self.into_val().key_values().map(|kv| {
            kv.map(|(k, v)| (Self::Val(k), Self::Val(v)))
                .map_err(conv_err)
        }))
    }

    fn values(self) -> Box<dyn Iterator<Item = ValR<Self>>> {
        if let Self::Doc(doc) = &self {
            match doc.node().kind() {
                Kind::Arr(children) => {
                    let mut rest = Rest::new(doc, children);
                    return Box::new(core::iter::from_fn(move || rest.next_element().map(Ok)));
                }
                Kind::Obj(children) => {
                    let mut rest = Rest::new(doc, children);
                    return Box::new(core::iter::from_fn(move || {
                        rest.next_entry().map(|(_, value)| Ok(value))
                    }));
                }
                _ => {}
            }
        }
        Box::new(self.into_val().values().map(conv_r))
    }

    fn index(self, index: &Self) -> ValR<Self> {
        if let Self::Doc(doc) = &self {
            let node = doc.node();
            let found = match node.kind() {
                Kind::Null => return Ok(Self::Val(Val::Null)),
                Kind::Obj(children) => index.as_key().map(|key| children.get(key)),
                Kind::Arr(children) => index.as_index().map(|index| children.nth(index)),
                _ => None,
            };
            if let Some(found) = found {
                return Ok(found.map_or(Self::Val(Val::Null), |child| doc.child(child)));
            }
        }
        conv_r(self.into_val().index(&index.to_cow()))
    }

    fn range(self, range: Range<&Self>) -> ValR<Self> {
        let (start, end) = val_range(&range);
        conv_r(self.into_val().range(start.as_deref()..end.as_deref()))
    }

    fn map_values<'a, I: Iterator<Item = ValX<'a, Self>>>(
        self,
        opt: Opt,
        f: impl Fn(Self) -> I,
    ) -> ValX<'a, Self> {
        let stash = RefCell::new(None);
        let result = self
            .into_val()
            .map_values(opt, |x| smuggle(f(Self::Val(x)), &stash));
        unsmuggle(result, stash)
    }

    fn map_index<'a, I: Iterator<Item = ValX<'a, Self>>>(
        self,
        index: &Self,
        opt: Opt,
        f: impl Fn(Self) -> I,
    ) -> ValX<'a, Self> {
        let stash = RefCell::new(None);
        let result = self
            .into_val()
            .map_index(&index.to_cow(), opt, |x| smuggle(f(Self::Val(x)), &stash));
        unsmuggle(result, stash)
    }

    fn map_range<'a, I: Iterator<Item = ValX<'a, Self>>>(
        self,
        range: Range<&Self>,
        opt: Opt,
        f: impl Fn(Self) -> I,
    ) -> ValX<'a, Self> {
        let stash = RefCell::new(None);
        let (start, end) = val_range(&range);
        let result = self
            .into_val()
            .map_range(start.as_deref()..end.as_deref(), opt, |x| {
                smuggle(f(Self::Val(x)), &stash)
            });
        unsmuggle(result, stash)
    }

    fn as_bool(&self) -> bool {
        match self {
            Self::Doc(doc) => !matches!(doc.node().kind(), Kind::Null | Kind::Bool(false)),
            Self::Val(val) => val.as_bool(),
        }
    }

    fn into_string(self) -> Self {
        if let Some(Kind::Str(_)) = self.doc_kind() {
            return self;
        }
        Self::Val(self.into_val().into_string())
    }
}

impl jaq_std::ValT for Value {
    fn into_seq<S: FromIterator<Self>>(self) -> Result<S, Self> {
        match self {
            Self::Doc(doc) => match doc.node().kind() {
                Kind::Arr(children) => {
                    let mut rest = Rest::new(&doc, children);
                    Ok(core::iter::from_fn(|| rest.next_element()).collect())
                }
                _ => Err(Self::Doc(doc)),
            },
            Self::Val(val) => match val.into_seq::<Vec<Val>>() {
                Ok(values) => Ok(values.into_iter().map(Self::Val).collect()),
                Err(val) => Err(Self::Val(val)),
            },
        }
    }

    fn is_int(&self) -> bool {
        self.is_number() && self.to_cow().is_int()
    }

    fn as_isize(&self) -> Option<isize> {
        if let Some(index) = self.as_index() {
            return Some(index);
        }
        self.is_number().then(|| self.to_cow().as_isize()).flatten()
    }

    fn as_f64(&self) -> Option<f64> {
        self.is_number().then(|| self.to_cow().as_f64()).flatten()
    }

    fn is_utf8_str(&self) -> bool {
        match self {
            Self::Doc(doc) => matches!(doc.node().kind(), Kind::Str(_)),
            Self::Val(val) => val.is_utf8_str(),
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Doc(doc) => doc.node().as_str(),
            Self::Val(val) => val.as_bytes(),
        }
    }

    fn as_sub_str(&self, sub: &[u8]) -> Self {
        match self {
            Self::Doc(_) => Self::Val(Val::utf8_str(sub.to_vec())),
            Self::Val(val) => Self::Val(val.as_sub_str(sub)),
        }
    }

    fn from_utf8_bytes(b: impl AsRef<[u8]> + Send + 'static) -> Self {
        Self::Val(Val::from_utf8_bytes(b))
    }
}

type NativeDef = (&'static str, Box<[Bind]>, RunPtr<Data>);

/// The natives of jaq-json, which are written for [`Val`] only.
///
/// Each one has a fast path for the document where that is simple, and otherwise runs jaq-json's
/// own implementation on the value built as a [`Val`].
pub fn json_funs() -> impl Iterator<Item = Fun<Data>> {
    let funs: [NativeDef; 8] = [
        ("fromjson", v(0), |cv| delegate(Op::FromJson, cv.1, None)),
        ("tojson", v(0), |cv| delegate(Op::ToJson, cv.1, None)),
        ("tobytes", v(0), |cv| delegate(Op::ToBytes, cv.1, None)),
        ("length", v(0), |cv| {
            if let Some(kind) = cv.1.doc_kind() {
                let length = match kind {
                    Kind::Null => Some(0),
                    Kind::Arr(children) | Kind::Obj(children) => Some(children.count),
                    Kind::Str(bytes) => std::str::from_utf8(bytes).ok().map(|s| s.chars().count()),
                    _ => None,
                };
                if let Some(length) = length {
                    return bome(Ok(Value::from(length)));
                }
            }
            delegate(Op::Length, cv.1, None)
        }),
        ("contains", v(1), |mut cv| {
            let arg = cv.0.pop_var();
            delegate(Op::Contains, cv.1, Some(arg))
        }),
        ("has", v(1), |mut cv| {
            let key = cv.0.pop_var();
            if let (Some(Kind::Obj(children)), Some(key)) = (cv.1.doc_kind(), key.as_key()) {
                return bome(Ok(Value::from(children.get(key).is_some())));
            }
            delegate(Op::Has, cv.1, Some(key))
        }),
        ("indices", v(1), |mut cv| {
            let arg = cv.0.pop_var();
            delegate(Op::Indices, cv.1, Some(arg))
        }),
        ("bsearch", v(1), |mut cv| {
            let arg = cv.0.pop_var();
            delegate(Op::Bsearch, cv.1, Some(arg))
        }),
    ];
    funs.into_iter().map(run::<Data>)
}

#[derive(Clone, Copy)]
enum Op {
    FromJson,
    ToJson,
    ToBytes,
    Length,
    Contains,
    Has,
    Indices,
    Bsearch,
}

impl Op {
    const ALL: [Self; 8] = [
        Self::FromJson,
        Self::ToJson,
        Self::ToBytes,
        Self::Length,
        Self::Contains,
        Self::Has,
        Self::Indices,
        Self::Bsearch,
    ];

    fn code(self) -> &'static str {
        match self {
            Self::FromJson => "fromjson",
            Self::ToJson => "tojson",
            Self::ToBytes => "tobytes",
            Self::Length => "length",
            Self::Contains => "contains($x)",
            Self::Has => "has($x)",
            Self::Indices => "indices($x)",
            Self::Bsearch => "bsearch($x)",
        }
    }
}

type ValFilter = jaq_core::Filter<JustLut<Val>>;

thread_local! {
    /// jaq-json's natives, each compiled into a filter over [`Val`], indexed by [`Op`].
    static VAL_FILTERS: Vec<ValFilter> = Op::ALL.iter().map(|op| compile_val(op.code())).collect();
}

fn compile_val(code: &str) -> ValFilter {
    let arena = Arena::default();
    let modules = Loader::new([])
        .load(&arena, File { code, path: () })
        .unwrap_or_else(|_| unreachable!("`{code}` parses"));
    jaq_core::Compiler::default()
        .with_funs(jaq_json::funs())
        .with_global_vars(["$x"])
        .compile(modules)
        .unwrap_or_else(|_| unreachable!("`{code}` compiles"))
}

fn delegate<'a>(op: Op, input: Value, arg: Option<Value>) -> ValXs<'a, Value> {
    let input = input.into_val();
    let arg = arg.map_or(Val::Null, Value::into_val);
    let outputs: Vec<ValX<'a, Value>> =
        VAL_FILTERS.with(|filters| match filters.get(op as usize) {
            Some(filter) => {
                let ctx = Ctx::<JustLut<Val>>::new(&filter.lut, Vars::new([arg]));
                filter
                    .id
                    .run((ctx, input))
                    .map(|output| output.map(Value::Val).map_err(conv_exn))
                    .collect()
            }
            None => Vec::new(),
        });
    match <[_; 1]>::try_from(outputs) {
        Ok([output]) => box_once(output),
        Err(outputs) => Box::new(outputs.into_iter()),
    }
}
