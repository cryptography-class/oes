use std::fmt;
use std::io;

/// The ways reading or writing a container header can fail.
#[derive(Debug)]
pub enum ContainerError {
    /// Reading or writing failed.
    Io(io::Error),
    /// The input doesn't start with the container signature.
    BadMagic,
    /// The header has a format version this program doesn't know.
    UnsupportedVersion(u8),
    /// A header field holds a code this program doesn't know.
    UnknownCode { field: &'static str, value: u8 },
    /// The input ends inside the header.
    Truncated,
    /// Fields that are valid on their own but not together, such as CTR with padding.
    InvalidCombination(&'static str),
}

impl fmt::Display for ContainerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::BadMagic => write!(f, "not an encrypted container (bad signature)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported container version {v}"),
            Self::UnknownCode { field, value } => {
                write!(f, "unknown {field} code {value} in container header")
            }
            Self::Truncated => write!(f, "container header is truncated"),
            Self::InvalidCombination(msg) => write!(f, "invalid container header: {msg}"),
        }
    }
}

impl std::error::Error for ContainerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ContainerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
