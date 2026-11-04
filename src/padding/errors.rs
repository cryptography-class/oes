use std::fmt;
use std::fmt::Formatter;

/// The ways adding or removing padding can fail.
#[derive(Debug, PartialEq, Eq)]
pub enum PaddingError {
    /// Block size is 0 or > 255 (the pad length must fit in one byte).
    InvalidBlockSize(usize),
    /// PKCS#5 is only defined for 8-byte blocks.
    Pkcs5RequiresBlock8(usize),
    /// Input has the wrong length for the operation.
    InvalidLength { len: usize, block_size: usize },
    /// Padding is corrupted, which is also the usual result of decrypting with a wrong key.
    Invalid,
    /// The OS random source failed.
    Rng
}

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(n) => write!(f, "invalid block size {n}"),
            Self::Pkcs5RequiresBlock8(n) => write!(f, "PKCS#5 requires an 8-byte block, got {n}; use PKCS#7"),
            Self::InvalidLength { len, block_size } => write!(f, "length {len} is invalid for block size {block_size}"),
            Self::Invalid => write!(f, "invalid padding"),
            Self::Rng => write!(f, "random number generator failure")
        }
    }
}

impl std::error::Error for PaddingError {}