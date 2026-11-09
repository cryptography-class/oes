use crate::container::errors::ContainerError;
use crate::padding::{Fill, Padding};

/// The format of the original file, recorded so the user knows what decryption
/// gives back. Any file can be encrypted; unrecognized ones are `Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageType {
    Unknown,
    Bmp,
    Png,
    Jpeg,
}

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const JPEG_SIGNATURE: [u8; 3] = [0xFF, 0xD8, 0xFF];
const BMP_SIGNATURE: [u8; 2] = *b"BM";

impl ImageType {
    /// Recognises the format from the first bytes of a file. Eight bytes are
    /// enough for every supported format; shorter input gives `Unknown` unless
    /// it holds a whole signature.
    ///
    /// # Examples
    ///
    /// ```
    /// use oes::container::ImageType;
    ///
    /// assert_eq!(ImageType::from_signature(b"BM\x36\x00"), ImageType::Bmp);
    /// assert_eq!(ImageType::from_signature(b"GIF89a"), ImageType::Unknown);
    /// ```
    pub fn from_signature(prefix: &[u8]) -> Self {
        if prefix.starts_with(&PNG_SIGNATURE) {
            Self::Png
        } else if prefix.starts_with(&JPEG_SIGNATURE) {
            Self::Jpeg
        } else if prefix.starts_with(&BMP_SIGNATURE) {
            Self::Bmp
        } else {
            Self::Unknown
        }
    }

    pub(super) fn to_byte(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Bmp => 1,
            Self::Png => 2,
            Self::Jpeg => 3,
        }
    }

    pub(super) fn from_byte(value: u8) -> Result<Self, ContainerError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Bmp),
            2 => Ok(Self::Png),
            3 => Ok(Self::Jpeg),
            _ => Err(ContainerError::UnknownCode {
                field: "image type",
                value,
            }),
        }
    }
}

/// The block cipher used. **DES must not protect real data**: its 56-bit key
/// can be found by brute force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Des,
}

impl Algorithm {
    /// Returns the cipher's block size in bytes.
    pub fn block_size(self) -> usize {
        match self {
            Self::Des => 8,
        }
    }

    /// Returns the key length in bytes, including DES parity bits.
    pub fn key_len(self) -> usize {
        match self {
            Self::Des => 8,
        }
    }

    pub(super) fn to_byte(self) -> u8 {
        match self {
            Self::Des => 1,
        }
    }

    pub(super) fn from_byte(value: u8) -> Result<Self, ContainerError> {
        match value {
            1 => Ok(Self::Des),
            _ => Err(ContainerError::UnknownCode {
                field: "algorithm",
                value,
            }),
        }
    }
}

/// The mode of operation. **ECB must not protect real data**: equal plaintext
/// blocks give equal ciphertext blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Ecb,
    Cbc,
    Ctr,
}

impl Mode {
    /// Returns the length of the IV or initial counter block this mode stores
    /// in the header: none for ECB, one block for CBC and CTR.
    pub fn iv_len(self, algorithm: Algorithm) -> usize {
        match self {
            Self::Ecb => 0,
            Self::Cbc | Self::Ctr => algorithm.block_size(),
        }
    }

    pub(super) fn to_byte(self) -> u8 {
        match self {
            Self::Ecb => 1,
            Self::Cbc => 2,
            Self::Ctr => 3,
        }
    }

    pub(super) fn from_byte(value: u8) -> Result<Self, ContainerError> {
        match value {
            1 => Ok(Self::Ecb),
            2 => Ok(Self::Cbc),
            3 => Ok(Self::Ctr),
            _ => Err(ContainerError::UnknownCode {
                field: "mode",
                value,
            }),
        }
    }
}

/// Encodes the padding field, where 0 means no padding.
pub(super) fn padding_to_byte(padding: Option<Padding>) -> u8 {
    match padding {
        None => 0,
        Some(Padding::Pkcs7) => 1,
        Some(Padding::Pkcs5) => 2,
        Some(Padding::AnsiX923(Fill::Zeros)) => 3,
        Some(Padding::AnsiX923(Fill::Random)) => 4,
    }
}

pub(super) fn padding_from_byte(value: u8) -> Result<Option<Padding>, ContainerError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(Padding::Pkcs7)),
        2 => Ok(Some(Padding::Pkcs5)),
        3 => Ok(Some(Padding::AnsiX923(Fill::Zeros))),
        4 => Ok(Some(Padding::AnsiX923(Fill::Random))),
        _ => Err(ContainerError::UnknownCode {
            field: "padding",
            value,
        }),
    }
}
