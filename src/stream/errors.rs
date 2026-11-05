use std::fmt;
use std::io;

use crate::modes::errors::ModeError;
use crate::padding::errors::PaddingError;

/// The ways streaming data through a mode can fail.
#[derive(Debug)]
pub enum StreamError {
    /// Reading or writing failed.
    Io(io::Error),
    /// The mode refused its input.
    Mode(ModeError),
    /// The padding is wrong or doesn't fit the block size.
    Padding(PaddingError),
    /// The ciphertext is empty or not a multiple of the block size.
    InvalidCiphertextLength { len: u64, block_size: usize },
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Mode(e) => write!(f, "mode error: {e}"),
            // With ECB and CBC, a wrong key and corrupted data look the same.
            Self::Padding(PaddingError::Invalid) => {
                write!(f, "invalid padding: wrong key or corrupted data")
            }
            Self::Padding(e) => write!(f, "padding error: {e}"),
            Self::InvalidCiphertextLength { len, block_size } => write!(
                f,
                "ciphertext length {len} is not a positive multiple of the {block_size}-byte block size (truncated or corrupted data)"
            ),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<io::Error> for StreamError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ModeError> for StreamError {
    fn from(e: ModeError) -> Self {
        Self::Mode(e)
    }
}

impl From<PaddingError> for StreamError {
    fn from(e: PaddingError) -> Self {
        Self::Padding(e)
    }
}
