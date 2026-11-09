use std::fmt;
use std::io;

use crate::container::Algorithm;

/// The ways creating, loading or saving a key can fail. None of them holds key
/// bytes, so they are safe to print.
#[derive(Debug)]
pub enum KeyError {
    /// Reading, writing or the random generator failed.
    Io(io::Error),
    /// The key has the wrong length for its algorithm.
    InvalidLength {
        algorithm: Algorithm,
        expected: usize,
        actual: u64,
    },
    /// A DES key byte has even parity. `byte` is its zero-based position.
    BadParity { byte: usize },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "key file error: {e}"),
            Self::InvalidLength {
                algorithm,
                expected,
                actual,
            } => write!(
                f,
                "invalid key length: {algorithm:?} needs {expected} bytes, got {actual}"
            ),
            Self::BadParity { byte } => write!(
                f,
                "invalid DES key: byte {byte} fails the odd parity check (wrong or corrupted key)"
            ),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for KeyError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
