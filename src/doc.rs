//! The input format: a compact binary encoding of a JSON value that a worker reads where it lies,
//! without parsing it first.
//!
//! The service encodes an input once, straight from anything that implements
//! [`serde::Serialize`], and every filter that runs on it reads the same bytes. A filter only pays
//! for the parts of the input it looks at: `.headers["x-user"]` on a megabyte of message walks
//! past the rest without building it.
//!
//! ```text
//! node   := tag (1 byte) payload
//!
//!   NULL, FALSE, TRUE    no payload
//!   INT                  i64 LE
//!   FLOAT                f64 LE, always finite
//!   NUM                  len (u32 LE) | ASCII digits of an integer that does not fit in an i64
//!   STR                  len (u32 LE) | UTF-8 bytes
//!   ARR                  count (u32 LE) | size (u32 LE) | `count` nodes, `size` bytes in all
//!   OBJ                  count (u32 LE) | size (u32 LE) | `count` entries, `size` bytes in all
//!
//! entry  := key len (u32 LE) | key UTF-8 bytes | node
//! ```
//!
//! The size of a container lets a reader step over it in constant time. The encoding follows
//! `serde_json`'s data model: a value encodes to what its JSON serialization would parse into.
//!
//! The service is the only writer, so a reader can trust the structure. It still checks every
//! offset against the end of the buffer, and reads anything malformed as `null`: a bug in the
//! encoder must not turn into a crash in the worker.

use std::fmt;

use jaq_core::ValT as _;
use jaq_json::{Map, Val};
use serde::ser::{self, Serialize};

const NULL: u8 = 0;
const FALSE: u8 = 1;
const TRUE: u8 = 2;
const INT: u8 = 3;
const FLOAT: u8 = 4;
const NUM: u8 = 5;
const STR: u8 = 6;
const ARR: u8 = 7;
const OBJ: u8 = 8;

/// Tag, count and size.
const CONTAINER_HEADER: usize = 9;

/// Deepest nesting the encoder accepts. Serializing recurses on the service's own stack, so the
/// limit protects the service from a value nested deeper than its stack, whatever the value's
/// `Serialize` implementation does.
pub const MAX_DEPTH: usize = 256;

/// Why a value could not be encoded.
#[derive(Debug)]
pub enum EncodeError {
    /// The encoding grew past the limit. Encoding stopped there, so the exact length is unknown.
    TooLarge,
    /// The value has no JSON representation, or is nested too deeply.
    Invalid(String),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("input is too large"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for EncodeError {}

impl ser::Error for EncodeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Invalid(message.to_string())
    }
}

/// Encodes `value` into `buffer`, which is cleared first. Fails if the encoding would be longer
/// than `max_len` bytes.
pub fn encode<T: Serialize + ?Sized>(
    value: &T,
    max_len: usize,
    buffer: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    buffer.clear();
    let mut encoder = Encoder {
        buffer,
        // Every count and size must fit in a `u32`.
        max_len: max_len.min(u32::MAX as usize),
        depth: 0,
    };
    value.serialize(&mut encoder)?;
    encoder.check_len()
}

struct Encoder<'b> {
    buffer: &'b mut Vec<u8>,
    max_len: usize,
    depth: usize,
}

impl Encoder<'_> {
    fn check_len(&self) -> Result<(), EncodeError> {
        if self.buffer.len() > self.max_len {
            Err(EncodeError::TooLarge)
        } else {
            Ok(())
        }
    }

    fn scalar(&mut self, tag: u8, payload: &[u8]) -> Result<(), EncodeError> {
        self.buffer.push(tag);
        self.buffer.extend_from_slice(payload);
        self.check_len()
    }

    /// Writes a length-prefixed string, without a tag when `tag` is `None` (object keys).
    fn string(&mut self, tag: Option<u8>, bytes: &[u8]) -> Result<(), EncodeError> {
        // Checked before copying, so that an oversized string is not copied first.
        if self.buffer.len() + bytes.len() > self.max_len {
            return Err(EncodeError::TooLarge);
        }
        if let Some(tag) = tag {
            self.buffer.push(tag);
        }
        // Fits: `bytes.len()` is below `max_len`, which is at most `u32::MAX`.
        self.buffer
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buffer.extend_from_slice(bytes);
        self.check_len()
    }

    fn int(&mut self, value: i128) -> Result<(), EncodeError> {
        match i64::try_from(value) {
            Ok(value) => self.scalar(INT, &value.to_le_bytes()),
            Err(_) => self.string(Some(NUM), value.to_string().as_bytes()),
        }
    }

    fn open(&mut self, tag: u8) -> Result<Compound<'_, Self>, EncodeError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(EncodeError::Invalid(format!(
                "input is nested more than {MAX_DEPTH} levels deep"
            )));
        }
        let header = self.buffer.len();
        self.buffer.push(tag);
        self.buffer.extend_from_slice(&[0; CONTAINER_HEADER - 1]);
        self.check_len()?;
        Ok(Compound {
            encoder: self,
            header,
            count: 0,
            variant: None,
        })
    }

    /// Fills in the header of the container that starts at `header`.
    fn close(&mut self, header: usize, count: u32) -> Result<(), EncodeError> {
        self.depth -= 1;
        let size = (self.buffer.len() - header - CONTAINER_HEADER) as u32;
        // Count, then size, both little-endian.
        let fields = (u64::from(count) | u64::from(size) << 32).to_le_bytes();
        if let Some(slot) = self.buffer.get_mut(header + 1..header + CONTAINER_HEADER) {
            slot.copy_from_slice(&fields);
        }
        Ok(())
    }

    /// Opens `{variant: <container>}`, serde_json's representation of tuple and struct variants.
    fn open_variant(&mut self, variant: &str, tag: u8) -> Result<Compound<'_, Self>, EncodeError> {
        let outer = self.open(OBJ)?.into_header();
        self.string(None, variant.as_bytes())?;
        let mut inner = self.open(tag)?;
        inner.variant = Some(outer);
        Ok(inner)
    }
}

/// An open array or object. `E` is always [`Encoder`]; it is a parameter so that the borrow of
/// the encoder can be named.
struct Compound<'a, E> {
    encoder: &'a mut E,
    header: usize,
    count: u32,
    /// Header of the single-entry object wrapped around a variant's fields.
    variant: Option<usize>,
}

impl<'b> Compound<'_, Encoder<'b>> {
    fn into_header(self) -> usize {
        self.header
    }

    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        self.count += 1;
        value.serialize(&mut *self.encoder)
    }

    fn key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), EncodeError> {
        self.count += 1;
        key.serialize(KeyEncoder(&mut *self.encoder))
    }

    fn value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        value.serialize(&mut *self.encoder)
    }

    fn field<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) -> Result<(), EncodeError> {
        self.count += 1;
        self.encoder.string(None, key.as_bytes())?;
        value.serialize(&mut *self.encoder)
    }

    fn end(self) -> Result<(), EncodeError> {
        self.encoder.close(self.header, self.count)?;
        if let Some(outer) = self.variant {
            self.encoder.close(outer, 1)?;
        }
        Ok(())
    }
}

impl<'a, 'b> ser::Serializer for &'a mut Encoder<'b> {
    type Ok = ();
    type Error = EncodeError;
    type SerializeSeq = Compound<'a, Encoder<'b>>;
    type SerializeTuple = Compound<'a, Encoder<'b>>;
    type SerializeTupleStruct = Compound<'a, Encoder<'b>>;
    type SerializeTupleVariant = Compound<'a, Encoder<'b>>;
    type SerializeMap = Compound<'a, Encoder<'b>>;
    type SerializeStruct = Compound<'a, Encoder<'b>>;
    type SerializeStructVariant = Compound<'a, Encoder<'b>>;

    fn serialize_bool(self, value: bool) -> Result<(), EncodeError> {
        self.scalar(if value { TRUE } else { FALSE }, &[])
    }

    fn serialize_i8(self, value: i8) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_i16(self, value: i16) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_i32(self, value: i32) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_i64(self, value: i64) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_i128(self, value: i128) -> Result<(), EncodeError> {
        self.int(value)
    }

    fn serialize_u8(self, value: u8) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_u16(self, value: u16) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_u32(self, value: u32) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_u64(self, value: u64) -> Result<(), EncodeError> {
        self.int(value.into())
    }

    fn serialize_u128(self, value: u128) -> Result<(), EncodeError> {
        match i128::try_from(value) {
            Ok(value) => self.int(value),
            Err(_) => self.string(Some(NUM), value.to_string().as_bytes()),
        }
    }

    fn serialize_f32(self, value: f32) -> Result<(), EncodeError> {
        self.serialize_f64(value.into())
    }

    fn serialize_f64(self, value: f64) -> Result<(), EncodeError> {
        // What serde_json writes for NaN and the infinities.
        if value.is_finite() {
            self.scalar(FLOAT, &value.to_le_bytes())
        } else {
            self.scalar(NULL, &[])
        }
    }

    fn serialize_char(self, value: char) -> Result<(), EncodeError> {
        self.string(Some(STR), value.encode_utf8(&mut [0; 4]).as_bytes())
    }

    fn serialize_str(self, value: &str) -> Result<(), EncodeError> {
        self.string(Some(STR), value.as_bytes())
    }

    /// Bytes become an array of numbers, as in serde_json.
    fn serialize_bytes(self, value: &[u8]) -> Result<(), EncodeError> {
        let mut array = self.open(ARR)?;
        for byte in value {
            array.element(byte)?;
        }
        array.end()
    }

    fn serialize_none(self) -> Result<(), EncodeError> {
        self.scalar(NULL, &[])
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), EncodeError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), EncodeError> {
        self.scalar(NULL, &[])
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), EncodeError> {
        self.scalar(NULL, &[])
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), EncodeError> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        let mut object = self.open(OBJ)?;
        object.field(variant, value)?;
        object.end()
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, EncodeError> {
        self.open(ARR)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, EncodeError> {
        self.open(ARR)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, EncodeError> {
        self.open(ARR)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, EncodeError> {
        self.open_variant(variant, ARR)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, EncodeError> {
        self.open(OBJ)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, EncodeError> {
        self.open(OBJ)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, EncodeError> {
        self.open_variant(variant, OBJ)
    }
}

impl ser::SerializeSeq for Compound<'_, Encoder<'_>> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        self.element(value)
    }

    fn end(self) -> Result<(), EncodeError> {
        Compound::end(self)
    }
}

impl ser::SerializeTuple for Compound<'_, Encoder<'_>> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        self.element(value)
    }

    fn end(self) -> Result<(), EncodeError> {
        Compound::end(self)
    }
}

impl ser::SerializeTupleStruct for Compound<'_, Encoder<'_>> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        self.element(value)
    }

    fn end(self) -> Result<(), EncodeError> {
        Compound::end(self)
    }
}

impl ser::SerializeTupleVariant for Compound<'_, Encoder<'_>> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        self.element(value)
    }

    fn end(self) -> Result<(), EncodeError> {
        Compound::end(self)
    }
}

impl ser::SerializeMap for Compound<'_, Encoder<'_>> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), EncodeError> {
        self.key(key)
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        self.value(value)
    }

    fn end(self) -> Result<(), EncodeError> {
        Compound::end(self)
    }
}

impl ser::SerializeStruct for Compound<'_, Encoder<'_>> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        self.field(key, value)
    }

    fn end(self) -> Result<(), EncodeError> {
        Compound::end(self)
    }
}

impl ser::SerializeStructVariant for Compound<'_, Encoder<'_>> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        self.field(key, value)
    }

    fn end(self) -> Result<(), EncodeError> {
        Compound::end(self)
    }
}

/// Encodes an object key: a string without a tag. Accepts what serde_json accepts as a key.
struct KeyEncoder<'a, 'b>(&'a mut Encoder<'b>);

impl KeyEncoder<'_, '_> {
    fn key(self, key: &str) -> Result<(), EncodeError> {
        self.0.string(None, key.as_bytes())
    }
}

fn key_must_be_a_string() -> EncodeError {
    EncodeError::Invalid("key must be a string".to_owned())
}

impl ser::Serializer for KeyEncoder<'_, '_> {
    type Ok = ();
    type Error = EncodeError;
    type SerializeSeq = ser::Impossible<(), EncodeError>;
    type SerializeTuple = ser::Impossible<(), EncodeError>;
    type SerializeTupleStruct = ser::Impossible<(), EncodeError>;
    type SerializeTupleVariant = ser::Impossible<(), EncodeError>;
    type SerializeMap = ser::Impossible<(), EncodeError>;
    type SerializeStruct = ser::Impossible<(), EncodeError>;
    type SerializeStructVariant = ser::Impossible<(), EncodeError>;

    fn serialize_bool(self, value: bool) -> Result<(), EncodeError> {
        self.key(if value { "true" } else { "false" })
    }

    fn serialize_i8(self, value: i8) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_i16(self, value: i16) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_i32(self, value: i32) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_i64(self, value: i64) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_i128(self, value: i128) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_u8(self, value: u8) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_u16(self, value: u16) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_u32(self, value: u32) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_u64(self, value: u64) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_u128(self, value: u128) -> Result<(), EncodeError> {
        self.key(&value.to_string())
    }

    fn serialize_f32(self, _value: f32) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_f64(self, _value: f64) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_char(self, value: char) -> Result<(), EncodeError> {
        self.key(value.encode_utf8(&mut [0; 4]))
    }

    fn serialize_str(self, value: &str) -> Result<(), EncodeError> {
        self.key(value)
    }

    fn serialize_bytes(self, _value: &[u8]) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_none(self) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_unit(self) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), EncodeError> {
        self.key(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, EncodeError> {
        Err(key_must_be_a_string())
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, EncodeError> {
        Err(key_must_be_a_string())
    }
}

fn read_array<const N: usize>(doc: &[u8], at: usize) -> Option<[u8; N]> {
    doc.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn read_u32(doc: &[u8], at: usize) -> Option<usize> {
    read_array(doc, at).map(|bytes| u32::from_le_bytes(bytes) as usize)
}

/// `len` bytes at `at`, preceded by their length.
fn read_prefixed(doc: &[u8], at: usize) -> Option<&[u8]> {
    let len = read_u32(doc, at)?;
    let start = at + 4;
    doc.get(start..start.checked_add(len)?)
}

/// A value in an encoded document.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    pub(crate) doc: &'a [u8],
    pub(crate) at: usize,
}

/// What a [`Node`] holds.
pub enum Kind<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    /// An integer too large for an `i64`, in decimal.
    BigInt(&'a [u8]),
    Str(&'a [u8]),
    Arr(Children<'a>),
    Obj(Children<'a>),
}

/// The contents of an array or an object.
#[derive(Clone, Copy)]
pub struct Children<'a> {
    pub(crate) doc: &'a [u8],
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub count: usize,
}

impl<'a> Node<'a> {
    /// The value an encoded document holds.
    #[cfg(test)]
    pub fn root(doc: &'a [u8]) -> Self {
        Self { doc, at: 0 }
    }

    pub fn kind(self) -> Kind<'a> {
        self.try_kind().unwrap_or(Kind::Null)
    }

    fn try_kind(self) -> Option<Kind<'a>> {
        let doc = self.doc;
        let payload = self.at + 1;
        Some(match *doc.get(self.at)? {
            NULL => Kind::Null,
            FALSE => Kind::Bool(false),
            TRUE => Kind::Bool(true),
            INT => Kind::Int(i64::from_le_bytes(read_array(doc, payload)?)),
            FLOAT => Kind::Float(f64::from_le_bytes(read_array(doc, payload)?)),
            NUM => Kind::BigInt(read_prefixed(doc, payload)?),
            STR => Kind::Str(read_prefixed(doc, payload)?),
            tag @ (ARR | OBJ) => {
                let count = read_u32(doc, payload)?;
                let size = read_u32(doc, payload + 4)?;
                let start = self.at + CONTAINER_HEADER;
                let end = start.checked_add(size).filter(|end| *end <= doc.len())?;
                let children = Children {
                    doc,
                    start,
                    end,
                    count,
                };
                if tag == ARR {
                    Kind::Arr(children)
                } else {
                    Kind::Obj(children)
                }
            }
            _ => return None,
        })
    }

    /// Offset just past this node.
    fn end(self) -> Option<usize> {
        let payload = self.at + 1;
        let end = match *self.doc.get(self.at)? {
            NULL | FALSE | TRUE => payload,
            INT | FLOAT => payload + 8,
            NUM | STR => payload + 4 + read_u32(self.doc, payload)?,
            ARR | OBJ => payload + 8 + read_u32(self.doc, payload + 4)?,
            _ => return None,
        };
        (end <= self.doc.len()).then_some(end)
    }

    pub fn as_str(self) -> Option<&'a [u8]> {
        match self.kind() {
            Kind::Str(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Builds the value, the whole tree of it.
    pub fn to_val(self) -> Val {
        match self.kind() {
            Kind::Null => Val::Null,
            Kind::Bool(value) => Val::Bool(value),
            Kind::Int(value) => match isize::try_from(value) {
                Ok(value) => Val::from(value),
                Err(_) => big_int(value.to_string().as_bytes()),
            },
            Kind::Float(value) => Val::from(value),
            Kind::BigInt(digits) => big_int(digits),
            Kind::Str(bytes) => Val::utf8_str(bytes.to_vec()),
            Kind::Arr(children) => children.elements().map(Node::to_val).collect(),
            Kind::Obj(children) => {
                let mut map = Map::with_capacity_and_hasher(children.count, Default::default());
                for (key, value) in children.entries() {
                    map.insert(Val::utf8_str(key.to_vec()), value.to_val());
                }
                Val::obj(map)
            }
        }
    }
}

fn big_int(digits: &[u8]) -> Val {
    std::str::from_utf8(digits)
        .ok()
        .and_then(|digits| Val::from_num(digits).ok())
        .unwrap_or(Val::Null)
}

impl<'a> Children<'a> {
    /// The elements of an array.
    pub fn elements(self) -> Elements<'a> {
        Elements {
            doc: self.doc,
            at: self.start,
            end: self.end,
            left: self.count,
        }
    }

    /// The entries of an object.
    pub fn entries(self) -> Entries<'a> {
        Entries(self.elements())
    }

    /// The element of an array at `index`, counted from the end if negative.
    pub fn nth(self, index: isize) -> Option<Node<'a>> {
        let index = if index < 0 {
            self.count.checked_sub(index.unsigned_abs())?
        } else {
            index.unsigned_abs()
        };
        self.elements().nth(index)
    }

    /// The value of an object under `key`. With duplicate keys the last one wins, as it does when
    /// the object is built.
    pub fn get(self, key: &[u8]) -> Option<Node<'a>> {
        let mut found = None;
        for (k, value) in self.entries() {
            if k == key {
                found = Some(value);
            }
        }
        found
    }
}

/// Iterator over the elements of an array.
pub struct Elements<'a> {
    pub(crate) doc: &'a [u8],
    pub(crate) at: usize,
    pub(crate) end: usize,
    pub(crate) left: usize,
}

impl<'a> Iterator for Elements<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        if self.left == 0 {
            return None;
        }
        let node = Node {
            doc: self.doc,
            at: self.at,
        };
        let end = node.end().filter(|end| *end <= self.end);
        match end {
            Some(end) => {
                self.at = end;
                self.left -= 1;
                Some(node)
            }
            None => {
                self.left = 0;
                None
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.left))
    }

    fn nth(&mut self, n: usize) -> Option<Node<'a>> {
        for _ in 0..n {
            self.next()?;
        }
        self.next()
    }
}

/// Iterator over the entries of an object.
pub struct Entries<'a>(pub(crate) Elements<'a>);

impl<'a> Iterator for Entries<'a> {
    type Item = (&'a [u8], Node<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let elements = &mut self.0;
        if elements.left == 0 {
            return None;
        }
        let key = read_prefixed(elements.doc, elements.at).filter(|_| elements.at < elements.end);
        let Some(key) = key else {
            elements.left = 0;
            return None;
        };
        elements.at += 4 + key.len();
        elements.next().map(|value| (key, value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn roundtrip(value: &serde_json::Value) -> Val {
        let mut buffer = Vec::new();
        encode(value, usize::MAX, &mut buffer).unwrap();
        Node::root(&buffer).to_val()
    }

    #[test]
    fn matches_json() {
        for value in [
            json!(null),
            json!(true),
            json!(-12),
            json!(u64::MAX),
            json!(1.5),
            json!("snow ☃"),
            json!([]),
            json!({}),
            json!([1, [2, [3, {"a": [true, null]}]], "x"]),
            json!({"b": 1, "a": {"c": [], "d": {}}, "": ""}),
        ] {
            let parsed = jaq_json::read::parse_single(value.to_string().as_bytes()).unwrap();
            assert_eq!(roundtrip(&value), parsed, "{value}");
        }
    }

    #[test]
    fn navigation() {
        let mut buffer = Vec::new();
        let value = json!({"a": [10, 20, 30], "b": "x", "a ": 1});
        encode(&value, usize::MAX, &mut buffer).unwrap();
        let Kind::Obj(object) = Node::root(&buffer).kind() else {
            panic!()
        };
        let Some(Kind::Arr(array)) = object.get(b"a").map(Node::kind) else {
            panic!()
        };
        assert_eq!(array.count, 3);
        assert!(matches!(array.nth(1).map(Node::kind), Some(Kind::Int(20))));
        assert!(matches!(array.nth(-1).map(Node::kind), Some(Kind::Int(30))));
        assert!(array.nth(3).is_none());
        assert!(array.nth(-4).is_none());
        assert_eq!(object.get(b"b").and_then(Node::as_str), Some(&b"x"[..]));
        assert!(object.get(b"c").is_none());
    }

    #[test]
    fn serde_data_model() {
        #[derive(serde::Serialize)]
        enum E {
            Unit,
            Newtype(u8),
            Tuple(u8, u8),
            Struct { x: u8 },
        }
        #[derive(serde::Serialize)]
        struct S {
            e: Vec<E>,
            o: Option<u8>,
            bytes: serde_bytes_like::Bytes,
            map: std::collections::BTreeMap<u32, char>,
        }
        mod serde_bytes_like {
            pub struct Bytes(pub Vec<u8>);
            impl serde::Serialize for Bytes {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    s.serialize_bytes(&self.0)
                }
            }
        }
        let value = S {
            e: vec![E::Unit, E::Newtype(1), E::Tuple(2, 3), E::Struct { x: 4 }],
            o: None,
            bytes: serde_bytes_like::Bytes(vec![5, 6]),
            map: [(7, 'z')].into(),
        };
        let mut buffer = Vec::new();
        encode(&value, usize::MAX, &mut buffer).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        let parsed = jaq_json::read::parse_single(json.as_bytes()).unwrap();
        assert_eq!(Node::root(&buffer).to_val(), parsed, "{json}");
    }

    #[test]
    fn limits() {
        let mut buffer = Vec::new();
        let result = encode(&json!({"a": "x".repeat(100)}), 50, &mut buffer);
        assert!(matches!(result, Err(EncodeError::TooLarge)), "{result:?}");

        let mut deep = json!(1);
        for _ in 0..MAX_DEPTH + 1 {
            deep = json!([deep]);
        }
        let result = encode(&deep, usize::MAX, &mut buffer);
        assert!(matches!(result, Err(EncodeError::Invalid(_))), "{result:?}");
    }

    #[test]
    fn malformed_reads_as_null() {
        // A container whose size runs past the end, and a string whose length does.
        for doc in [
            &[ARR, 1, 0, 0, 0, 200, 0, 0, 0, TRUE][..],
            &[STR, 9, 0, 0, 0, b'a'],
            &[42],
        ] {
            assert_eq!(Node::root(doc).to_val(), Val::Null);
        }
        // An array claiming more elements than it holds.
        let doc = [ARR, 3, 0, 0, 0, 1, 0, 0, 0, TRUE];
        assert_eq!(
            Node::root(&doc).to_val(),
            [Val::Bool(true)].into_iter().collect::<Val>()
        );
    }
}
