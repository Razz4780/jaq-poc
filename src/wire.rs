//! Messages between the service and a worker, over the worker's stream socket.
//!
//! One request, one reply, strictly in turn:
//!
//! ```text
//! request: kind (1 byte) | filter length (u32 LE) | input length (u32 LE) | filter | input
//! reply:   status (1 byte) | message length (u32 LE) | message
//! ```
//!
//! The worker reads with blocking `std` I/O and the service with tokio, so each side has its own
//! half of the codec here.

use std::io::{self, Read};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::Config;

/// Longest message a worker sends back. Compiler errors quote the filter, which can be large.
const MAX_MESSAGE_LEN: usize = 4 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Compile the filter and report whether it is valid.
    Check,
    /// Run the filter on the input.
    Evaluate,
}

pub fn encode_request(kind: Kind, filter: &str, input: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(9 + filter.len() + input.len());
    request.push(match kind {
        Kind::Check => 0,
        Kind::Evaluate => 1,
    });
    // The service checks both lengths against `Config`, whose limits fit in a `u32`.
    request.extend_from_slice(&(filter.len() as u32).to_le_bytes());
    request.extend_from_slice(&(input.len() as u32).to_le_bytes());
    request.extend_from_slice(filter.as_bytes());
    request.extend_from_slice(input);
    request
}

#[derive(Debug)]
pub struct Request {
    pub kind: Kind,
    pub filter: String,
    pub input: Vec<u8>,
}

impl Request {
    /// Reads the next request. Fails when the service has closed the socket, and on a request the
    /// service would never send.
    pub fn read(reader: &mut impl Read, config: &Config) -> io::Result<Self> {
        let mut header = [0; 9];
        reader.read_exact(&mut header)?;
        let [kind, f0, f1, f2, f3, i0, i1, i2, i3] = header;
        let kind = match kind {
            0 => Kind::Check,
            1 => Kind::Evaluate,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        let filter_len = u32::from_le_bytes([f0, f1, f2, f3]) as usize;
        let input_len = u32::from_le_bytes([i0, i1, i2, i3]) as usize;
        if filter_len > config.max_filter_len || input_len > config.max_input_len {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let mut filter = vec![0; filter_len];
        reader.read_exact(&mut filter)?;
        let filter = String::from_utf8(filter).map_err(|_| io::ErrorKind::InvalidData)?;
        let mut input = vec![0; input_len];
        reader.read_exact(&mut input)?;

        Ok(Self {
            kind,
            filter,
            input,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// Answer to [`Kind::Evaluate`].
    Matched(bool),
    /// Answer to [`Kind::Check`].
    Valid,
    InvalidFilter(String),
    InvalidInput(String),
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let (status, message) = match self {
            Self::Matched(false) => (0, ""),
            Self::Matched(true) => (1, ""),
            Self::Valid => (2, ""),
            Self::InvalidFilter(message) => (3, message.as_str()),
            Self::InvalidInput(message) => (4, message.as_str()),
        };
        let end = message.floor_char_boundary(MAX_MESSAGE_LEN);
        let message = message.get(..end).unwrap_or_default().as_bytes();

        let mut reply = Vec::with_capacity(5 + message.len());
        reply.push(status);
        reply.extend_from_slice(&(message.len() as u32).to_le_bytes());
        reply.extend_from_slice(message);
        reply
    }

    pub async fn read(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Self> {
        let mut header = [0; 5];
        reader.read_exact(&mut header).await?;
        let [status, l0, l1, l2, l3] = header;
        let len = u32::from_le_bytes([l0, l1, l2, l3]) as usize;
        if len > MAX_MESSAGE_LEN {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut message = vec![0; len];
        reader.read_exact(&mut message).await?;
        let message = String::from_utf8_lossy(&message).into_owned();

        match status {
            0 => Ok(Self::Matched(false)),
            1 => Ok(Self::Matched(true)),
            2 => Ok(Self::Valid),
            3 => Ok(Self::InvalidFilter(message)),
            4 => Ok(Self::InvalidInput(message)),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}
