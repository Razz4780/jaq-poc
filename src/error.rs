use std::{fmt, io};

/// Why an evaluation produced no result.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The filter does not parse or compile. The message comes from the jq compiler.
    #[error("jq filter is invalid: {0}")]
    InvalidFilter(String),

    /// The worker could not parse the input as JSON.
    #[error("input is not valid JSON: {0}")]
    InvalidInput(String),

    #[error("jq filter is {len} bytes long, the limit is {limit}")]
    FilterTooLarge { len: usize, limit: usize },

    #[error("input is {len} bytes long, the limit is {limit}")]
    InputTooLarge { len: usize, limit: usize },

    /// The evaluation ran into one of the configured limits and its worker was killed.
    #[error("jq evaluation exceeded its {0} limit")]
    LimitExceeded(Limit),

    /// The worker died in a way no limit explains. The evaluation that was running on it is lost,
    /// other evaluations are not affected.
    #[error("jq worker died unexpectedly: {0}")]
    WorkerDied(String),

    /// The dispatcher process cannot be reached, or it could not create a worker. Without the
    /// dispatcher nothing can be evaluated, and it cannot be started again once the service runs
    /// threads.
    #[error("jq sandbox is unavailable: {0}")]
    Unavailable(#[source] io::Error),
}

/// A per-evaluation limit from [`Config`](crate::Config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    CpuTime,
    WallTime,
    Memory,
    Stack,
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CpuTime => "CPU time",
            Self::WallTime => "wall-clock time",
            Self::Memory => "memory",
            Self::Stack => "stack",
        })
    }
}
