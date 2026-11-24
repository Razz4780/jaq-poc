//! Messages between the service and a worker, over the worker's stream socket.
//!
//! One request, one reply, strictly in turn. All integers are little-endian.
//!
//! ```text
//! check:     0 | id (u64) | source length (u32) | source
//! evaluate:  1 | input | forget count (u32) | filter count (u32) | sources length (u32)
//!              | forget count * id (u64)
//!              | filter count * (id (u64) | source length (u32))
//!              | sources | inline input
//! input:     0 | arena offset (u64) | length (u32)       the input is in the arena
//!            1 | 0 (u64)            | length (u32)       the input follows the request
//!
//! reply:     status (1 byte) | message length (u32) | message
//! ```
//!
//! A check compiles a filter, and caches it under its id unless the id is 0. An evaluation first
//! drops the cached filters listed to forget, then runs every filter on the input. A filter
//! comes with its source the first time it is sent to a worker, and as its id alone after that.
//! Verdicts go to the worker's progress page, not into the reply.
//!
//! The worker reads with blocking `std` I/O and the service with tokio, so each side has its own
//! half of the codec here.

use std::io::{self, Read};

use crate::{Config, shm::MAX_BATCH};

/// Longest message a worker sends back. Compiler errors quote the filter, which can be large.
pub const MAX_MESSAGE_LEN: usize = 4 << 10;
/// Most filters one evaluation may tell a worker to forget.
pub const MAX_FORGET: usize = 1 << 16;

const CHECK: u8 = 0;
const EVALUATE: u8 = 1;
const INPUT_ARENA: u8 = 0;
const INPUT_INLINE: u8 = 1;

/// Where the input of an evaluation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAt {
    Arena { offset: usize, len: usize },
    Inline { len: usize },
}

/// A filter as sent in an evaluation.
pub struct FilterRef<'a> {
    pub id: u64,
    /// `None` if the worker has it cached.
    pub source: Option<&'a str>,
}

pub fn encode_check(buffer: &mut Vec<u8>, id: u64, source: &str) {
    buffer.clear();
    buffer.push(CHECK);
    buffer.extend_from_slice(&id.to_le_bytes());
    // The service checks the length against `Config`, whose limits fit in a `u32`.
    buffer.extend_from_slice(&(source.len() as u32).to_le_bytes());
    buffer.extend_from_slice(source.as_bytes());
}

pub fn encode_evaluate<'a>(
    buffer: &mut Vec<u8>,
    input: InputAt,
    inline: &[u8],
    forget: &[u64],
    filters: impl ExactSizeIterator<Item = FilterRef<'a>> + Clone,
) {
    buffer.clear();
    buffer.push(EVALUATE);
    let (kind, offset, len) = match input {
        InputAt::Arena { offset, len } => (INPUT_ARENA, offset, len),
        InputAt::Inline { len } => (INPUT_INLINE, 0, len),
    };
    buffer.push(kind);
    buffer.extend_from_slice(&(offset as u64).to_le_bytes());
    buffer.extend_from_slice(&(len as u32).to_le_bytes());

    let sources_len: usize = filters
        .clone()
        .filter_map(|filter| filter.source)
        .map(str::len)
        .sum();
    buffer.extend_from_slice(&(forget.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&(filters.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&(sources_len as u32).to_le_bytes());
    for id in forget {
        buffer.extend_from_slice(&id.to_le_bytes());
    }
    for filter in filters.clone() {
        buffer.extend_from_slice(&filter.id.to_le_bytes());
        let len = filter.source.map_or(0, str::len);
        buffer.extend_from_slice(&(len as u32).to_le_bytes());
    }
    for source in filters.filter_map(|filter| filter.source) {
        buffer.extend_from_slice(source.as_bytes());
    }
    if let InputAt::Inline { .. } = input {
        buffer.extend_from_slice(inline);
    }
}

/// A decoded request. Borrows the worker's buffers, which are reused from one request to the
/// next.
pub enum Request<'a> {
    Check {
        id: u64,
        source: &'a str,
    },
    Evaluate {
        input: InputAt,
        /// The inline input, empty if it is in the arena.
        inline: &'a mut Vec<u8>,
        forget: &'a [u64],
        /// `(id, source)`, with an empty source for cached filters.
        filters: Vec<(u64, &'a str)>,
    },
}

/// Buffers a worker reads requests into.
#[derive(Default)]
pub struct RequestBuffers {
    sources: Vec<u8>,
    forget: Vec<u64>,
    lens: Vec<(u64, usize)>,
    inline: Vec<u8>,
}

fn read_u32(reader: &mut impl Read) -> io::Result<usize> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn read_into(reader: &mut impl Read, buffer: &mut Vec<u8>, len: usize) -> io::Result<()> {
    buffer.clear();
    buffer.resize(len, 0);
    reader.read_exact(buffer)
}

impl RequestBuffers {
    /// Reads the next request. Fails when the service has closed the socket, and on a request
    /// the service would never send.
    pub fn read<'a>(
        &'a mut self,
        reader: &mut impl Read,
        config: &Config,
    ) -> io::Result<Request<'a>> {
        let mut kind = [0];
        reader.read_exact(&mut kind)?;
        match kind {
            [CHECK] => {
                let id = read_u64(reader)?;
                let len = read_u32(reader)?;
                if len > config.max_filter_len {
                    return Err(invalid());
                }
                read_into(reader, &mut self.sources, len)?;
                let source = std::str::from_utf8(&self.sources).map_err(|_| invalid())?;
                Ok(Request::Check { id, source })
            }
            [EVALUATE] => self.read_evaluate(reader, config),
            _ => Err(invalid()),
        }
    }

    fn read_evaluate<'a>(
        &'a mut self,
        reader: &mut impl Read,
        config: &Config,
    ) -> io::Result<Request<'a>> {
        let mut kind = [0];
        reader.read_exact(&mut kind)?;
        let offset = read_u64(reader)?;
        let len = read_u32(reader)?;
        let input = match kind {
            [INPUT_ARENA] => InputAt::Arena {
                offset: usize::try_from(offset).map_err(|_| invalid())?,
                len,
            },
            [INPUT_INLINE] if len <= config.max_input_len => InputAt::Inline { len },
            _ => return Err(invalid()),
        };

        let forget_count = read_u32(reader)?;
        let filter_count = read_u32(reader)?;
        let sources_len = read_u32(reader)?;
        if forget_count > MAX_FORGET
            || filter_count > MAX_BATCH
            || sources_len > filter_count.saturating_mul(config.max_filter_len)
        {
            return Err(invalid());
        }

        self.forget.clear();
        for _ in 0..forget_count {
            self.forget.push(read_u64(reader)?);
        }
        self.lens.clear();
        for _ in 0..filter_count {
            let id = read_u64(reader)?;
            let len = read_u32(reader)?;
            self.lens.push((id, len));
        }
        read_into(reader, &mut self.sources, sources_len)?;
        let mut sources = std::str::from_utf8(&self.sources).map_err(|_| invalid())?;
        let mut filters = Vec::with_capacity(filter_count);
        for &(id, len) in &self.lens {
            let source = sources.get(..len).ok_or_else(invalid)?;
            sources = sources.get(len..).ok_or_else(invalid)?;
            filters.push((id, source));
        }
        if !sources.is_empty() {
            return Err(invalid());
        }

        match input {
            InputAt::Inline { len } => read_into(reader, &mut self.inline, len)?,
            InputAt::Arena { .. } => self.inline.clear(),
        }
        Ok(Request::Evaluate {
            input,
            inline: &mut self.inline,
            forget: &self.forget,
            filters,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// Answer to an evaluation: the verdicts are in the progress page.
    Evaluated,
    /// Answer to a check.
    Valid,
    InvalidFilter(String),
}

const EVALUATED: u8 = 0;
const VALID: u8 = 1;
const INVALID_FILTER: u8 = 2;
const HEADER_LEN: usize = 5;

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let (status, message) = match self {
            Self::Evaluated => (EVALUATED, ""),
            Self::Valid => (VALID, ""),
            Self::InvalidFilter(message) => (INVALID_FILTER, message.as_str()),
        };
        let end = message.floor_char_boundary(MAX_MESSAGE_LEN);
        let message = message.get(..end).unwrap_or_default().as_bytes();

        let mut reply = Vec::with_capacity(HEADER_LEN + message.len());
        reply.push(status);
        reply.extend_from_slice(&(message.len() as u32).to_le_bytes());
        reply.extend_from_slice(message);
        reply
    }

    /// Takes one whole reply off the front of `buffer`, if it holds one. Fails on a reply a
    /// worker would never send.
    pub fn take(buffer: &mut Vec<u8>) -> io::Result<Option<Self>> {
        let Some(&[status, l0, l1, l2, l3]) = buffer.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let len = u32::from_le_bytes([l0, l1, l2, l3]) as usize;
        if len > MAX_MESSAGE_LEN {
            return Err(invalid());
        }
        let Some(message) = buffer.get(HEADER_LEN..HEADER_LEN + len) else {
            return Ok(None);
        };
        let reply = match status {
            EVALUATED => Self::Evaluated,
            VALID => Self::Valid,
            INVALID_FILTER => Self::InvalidFilter(String::from_utf8_lossy(message).into_owned()),
            _ => return Err(invalid()),
        };
        buffer.drain(..HEADER_LEN + len);
        Ok(Some(reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_roundtrip() {
        let mut buffer = Vec::new();
        let filters = [
            FilterRef {
                id: 7,
                source: Some(".a"),
            },
            FilterRef {
                id: 8,
                source: None,
            },
            FilterRef {
                id: 9,
                source: Some(".b == 1"),
            },
        ];
        encode_evaluate(
            &mut buffer,
            InputAt::Inline { len: 3 },
            b"xyz",
            &[1, 2],
            filters.iter().map(|f| FilterRef {
                id: f.id,
                source: f.source,
            }),
        );
        let mut buffers = RequestBuffers::default();
        let request = buffers
            .read(&mut buffer.as_slice(), &Config::default())
            .unwrap();
        let Request::Evaluate {
            input,
            inline,
            forget,
            filters,
        } = request
        else {
            panic!()
        };
        assert_eq!(input, InputAt::Inline { len: 3 });
        assert_eq!(inline.as_slice(), b"xyz");
        assert_eq!(forget, &[1, 2]);
        assert_eq!(filters, vec![(7, ".a"), (8, ""), (9, ".b == 1")]);
    }

    #[test]
    fn reply_in_pieces() {
        let encoded = Reply::InvalidFilter("nope".to_owned()).encode();
        let (last, first) = encoded.split_last().unwrap();
        let mut buffer = Vec::new();
        for byte in first {
            buffer.push(*byte);
            assert_eq!(Reply::take(&mut buffer).unwrap(), None);
        }
        buffer.push(*last);
        buffer.extend_from_slice(&Reply::Evaluated.encode());
        assert_eq!(
            Reply::take(&mut buffer).unwrap(),
            Some(Reply::InvalidFilter("nope".to_owned()))
        );
        assert_eq!(Reply::take(&mut buffer).unwrap(), Some(Reply::Evaluated));
        assert!(buffer.is_empty());
    }
}
