use std::fmt;
use std::fmt::Formatter;

/// The ways a mode can refuse its input.
#[derive(Debug, PartialEq, Eq)]
pub enum ModeError {
    /// The data isn't a whole number of blocks.
    InvalidLength { len: usize, block_size: usize },
    /// The IV isn't exactly one block long.
    InvalidIvLength { len: usize, expected: usize },
    /// More data arrived after a chunk that ended in a partial block.
    DataAfterPartialBlock,
}

impl fmt::Display for ModeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { len, block_size } => {
                write!(f, "data length {len} is not a multiple of block size {block_size}")
            }
            Self::InvalidIvLength { len, expected } => {
                write!(f, "IV length {len} is invalid, expected {expected}")
            }
            Self::DataAfterPartialBlock => {
                write!(f, "only the last chunk of a message may end in a partial block")
            }
        }
    }
}

impl std::error::Error for ModeError {}
