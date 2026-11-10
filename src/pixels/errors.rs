use std::fmt;
use std::io;

use crate::container::errors::ContainerError;
use crate::modes::errors::ModeError;
use crate::padding::errors::PaddingError;

/// The ways pixel encryption, decryption or the metadata file can fail.
#[derive(Debug)]
pub enum PixelError {
    /// Reading or writing a file failed.
    Io(io::Error),
    /// The image can't be decoded or encoded.
    Image(image::ImageError),
    /// The metadata holds an unknown code, or a combination the container format
    /// doesn't allow, such as PKCS#5 with a block size other than 8.
    Container(ContainerError),
    /// The metadata file doesn't start with the expected signature.
    BadMagic,
    /// The metadata file has a format version this program doesn't know.
    UnsupportedVersion(u8),
    /// The metadata file ends too early.
    Truncated,
    /// The request or the metadata is invalid, for example CTR mode or an
    /// unsupported output extension.
    Invalid(&'static str),
    /// The image doesn't have the dimensions recorded in the metadata.
    DimensionMismatch {
        expected: (u32, u32),
        actual: (u32, u32),
    },
    /// The encrypted tail stored in the image and in the metadata disagree.
    TailMismatch,
    /// The mode refused its input.
    Mode(ModeError),
    /// Padding failed, which for the tail block usually means a wrong key.
    Padding(PaddingError),
}

impl fmt::Display for PixelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Image(e) => write!(f, "image error: {e}"),
            Self::Container(e) => write!(f, "invalid pixel metadata: {e}"),
            Self::BadMagic => write!(f, "not a pixel metadata file (bad signature)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported pixel metadata version {v}"),
            Self::Truncated => write!(f, "pixel metadata file is truncated"),
            Self::Invalid(msg) => write!(f, "{msg}"),
            Self::DimensionMismatch { expected, actual } => write!(
                f,
                "the image is {}x{} but the metadata describes {}x{}",
                actual.0, actual.1, expected.0, expected.1
            ),
            Self::TailMismatch => write!(
                f,
                "the encrypted image and its metadata don't belong together, or the image was modified"
            ),
            Self::Mode(e) => write!(f, "mode error: {e}"),
            Self::Padding(PaddingError::Invalid) => write!(
                f,
                "invalid padding in the tail block: wrong key or corrupted data"
            ),
            Self::Padding(e) => write!(f, "padding error: {e}"),
        }
    }
}

impl std::error::Error for PixelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Image(e) => Some(e),
            Self::Container(e) => Some(e),
            Self::Mode(e) => Some(e),
            Self::Padding(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PixelError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<image::ImageError> for PixelError {
    fn from(e: image::ImageError) -> Self {
        Self::Image(e)
    }
}

impl From<ContainerError> for PixelError {
    fn from(e: ContainerError) -> Self {
        Self::Container(e)
    }
}

impl From<ModeError> for PixelError {
    fn from(e: ModeError) -> Self {
        Self::Mode(e)
    }
}

impl From<PaddingError> for PixelError {
    fn from(e: PaddingError) -> Self {
        Self::Padding(e)
    }
}
