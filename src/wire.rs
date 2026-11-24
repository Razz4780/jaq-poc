//! Messages between the service and a worker, over the worker's stream socket.
//!
//! The service sends one request and reads its whole reply before sending the next. Lengths are
//! little-endian `u32`s.
//!
//! - `CHECK`, then the length and text of a filter's source. The reply is [`VALID`], or
//!   [`INVALID`] followed by the length and text of the compiler's message.
//! - `EVALUATE`, then the length and JSON text of the input, the number of filters, and the
//!   length and text of each filter's source. The reply is [`INPUT_OK`] or [`INPUT_INVALID`]
//!   once the input is parsed, and after `INPUT_OK` one [`verdict`] per filter, each written as
//!   soon as the filter is done. A worker that dies over a filter leaves every verdict before it
//!   readable on the socket.

use std::io::{self, Read};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::Config;

const CHECK: u8 = 1;
const EVALUATE: u8 = 2;

pub const VALID: u8 = 1;
pub const INVALID: u8 = 2;
pub const INPUT_OK: u8 = 3;
pub const INPUT_INVALID: u8 = 4;

/// One byte per filter of an `EVALUATE` request.
pub mod verdict {
    pub const FALSE: u8 = 0;
    pub const TRUE: u8 = 1;
    pub const INVALID_FILTER: u8 = 2;
}

/// Longest compiler message a worker sends.
pub const MAX_MESSAGE_LEN: usize = 4096;

/// Most filters in one `EVALUATE` request.
pub const MAX_FILTERS: usize = 1 << 16;

pub fn encode_check(source: &str) -> Vec<u8> {
    let mut request = vec![CHECK];
    put(&mut request, source.as_bytes());
    request
}

pub fn encode_evaluate<'a>(
    input: &[u8],
    filters: impl ExactSizeIterator<Item = &'a str>,
) -> Vec<u8> {
    let mut request = vec![EVALUATE];
    put(&mut request, input);
    request.extend_from_slice(&len(filters.len()).to_le_bytes());
    for source in filters {
        put(&mut request, source.as_bytes());
    }
    request
}

pub fn encode_invalid(message: &str) -> Vec<u8> {
    let mut end = message.len().min(MAX_MESSAGE_LEN);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut reply = vec![INVALID];
    put(
        &mut reply,
        message.as_bytes().get(..end).unwrap_or_default(),
    );
    reply
}

fn put(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&len(bytes.len()).to_le_bytes());
    buffer.extend_from_slice(bytes);
}

/// Lengths are bounded well below `u32::MAX` by [`Config`], which checks that its limits fit.
fn len(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

pub enum Request {
    Check(String),
    Evaluate {
        input: Vec<u8>,
        filters: Vec<String>,
    },
}

/// Reads the next request, or `None` when the service has closed the socket.
pub fn read_request(reader: &mut impl Read, config: &Config) -> io::Result<Option<Request>> {
    let mut tag = [0];
    if reader.read(&mut tag)? == 0 {
        return Ok(None);
    }
    match tag {
        [CHECK] => Ok(Some(Request::Check(read_source(reader, config)?))),
        [EVALUATE] => {
            let input = read_bytes(reader, config.max_input_len)?;
            let count = read_len(reader, MAX_FILTERS)?;
            let filters = (0..count)
                .map(|_| read_source(reader, config))
                .collect::<io::Result<_>>()?;
            Ok(Some(Request::Evaluate { input, filters }))
        }
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

fn read_source(reader: &mut impl Read, config: &Config) -> io::Result<String> {
    String::from_utf8(read_bytes(reader, config.max_filter_len)?)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

fn read_len(reader: &mut impl Read, limit: usize) -> io::Result<usize> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    match usize::try_from(u32::from_le_bytes(len)) {
        Ok(len) if len <= limit => Ok(len),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

fn read_bytes(reader: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let len = read_len(reader, limit)?;
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Reads the compiler's message that follows [`INVALID`].
pub async fn read_message(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<String> {
    let len = reader.read_u32_le().await?;
    match usize::try_from(len) {
        Ok(len) if len <= MAX_MESSAGE_LEN => {
            let mut message = vec![0; len];
            reader.read_exact(&mut message).await?;
            Ok(String::from_utf8_lossy(&message).into_owned())
        }
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let config = Config::default();

        let encoded = encode_check(".a == 1");
        let Some(Request::Check(source)) = read_request(&mut encoded.as_slice(), &config).unwrap()
        else {
            panic!("not a check");
        };
        assert_eq!(source, ".a == 1");

        let encoded = encode_evaluate(br#"{"a":1}"#, [".a", "true"].into_iter());
        let Some(Request::Evaluate { input, filters }) =
            read_request(&mut encoded.as_slice(), &config).unwrap()
        else {
            panic!("not an evaluation");
        };
        assert_eq!(input, br#"{"a":1}"#);
        assert_eq!(filters, [".a", "true"]);

        assert!(read_request(&mut io::empty(), &config).unwrap().is_none());
        assert!(read_request(&mut [9u8].as_slice(), &config).is_err());
        // Truncated.
        assert!(read_request(&mut encoded.get(..6).unwrap(), &config).is_err());
    }

    #[test]
    fn lengths_are_bounded() {
        let config = Config {
            max_filter_len: 4,
            ..Config::default()
        };
        let encoded = encode_check("12345");
        assert!(read_request(&mut encoded.as_slice(), &config).is_err());
    }

    #[test]
    fn long_messages_are_cut_on_a_char_boundary() {
        let message = "ż".repeat(MAX_MESSAGE_LEN);
        let reply = encode_invalid(&message);
        assert!(reply.len() <= 5 + MAX_MESSAGE_LEN);
        assert!(std::str::from_utf8(reply.get(5..).unwrap()).is_ok());
    }
}
