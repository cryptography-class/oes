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
    /// The mode doesn't support the cipher's block size, as GCM needs 16 bytes.
    UnsupportedBlockSize { block_size: usize },
    /// The message is longer than one nonce allows.
    MessageTooLong { max: u64 },
    /// The tag doesn't match: wrong key, or changed data, nonce, AAD or tag.
    AuthenticationFailed,
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
            Self::UnsupportedBlockSize { block_size } => {
                write!(f, "a {block_size}-byte block isn't supported by this mode")
            }
            Self::MessageTooLong { max } => {
                write!(f, "the message is longer than the {max} bytes one nonce allows")
            }
            Self::AuthenticationFailed => {
                write!(f, "authentication failed: wrong key or changed data")
            }
        }
    }
}

impl std::error::Error for ModeError {}
