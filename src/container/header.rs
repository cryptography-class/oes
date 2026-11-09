//! The container header, written in front of the ciphertext.
//!
//! ```text
//! offset  size  field
//! 0       4     magic "OESC"
//! 4       1     format version (1)
//! 5       1     original image type   (0 unknown, 1 BMP, 2 PNG, 3 JPEG)
//! 6       1     algorithm             (1 DES)
//! 7       1     mode                  (1 ECB, 2 CBC, 3 CTR)
//! 8       1     padding               (0 none, 1 PKCS#7, 2 PKCS#5,
//!                                      3 ANSI X9.23 zeros, 4 ANSI X9.23 random)
//! 9       8     original length in bytes, u64 big-endian
//! 17      n     IV or initial counter block: n = 0 for ECB, one block for CBC and CTR
//! 17+n    ...   ciphertext
//! ```
//!
//! The IV length isn't stored, because the algorithm and mode determine it.
//! Codes for AES (algorithm 2 to 4) and GCM (mode 4, followed by a 16-byte tag
//! at the end of the file) will be added without moving any field.

use std::io::{ErrorKind, Read, Write};

use super::errors::ContainerError;
use super::fields::{Algorithm, ImageType, Mode, padding_from_byte, padding_to_byte};
use crate::padding::Padding;

const MAGIC: [u8; 4] = *b"OESC";
const VERSION: u8 = 1;
/// Everything before the IV.
const FIXED_LEN: usize = 17;

/// Everything needed to decrypt a container except the key, which is never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub image_type: ImageType,
    pub algorithm: Algorithm,
    pub mode: Mode,
    /// `None` exactly when the mode needs no padding (CTR).
    pub padding: Option<Padding>,
    /// The IV for CBC or the initial counter block for CTR; empty for ECB.
    pub iv: Vec<u8>,
    /// The plaintext length, which the decrypted output must match.
    pub original_len: u64,
}

impl Header {
    /// Checks that the fields make sense together. [`write_to`](Self::write_to)
    /// and [`read_from`](Self::read_from) both call it.
    ///
    /// # Errors
    ///
    /// [`ContainerError::InvalidCombination`] if ECB or CBC has no padding, CTR
    /// has padding, or the IV length isn't [`Mode::iv_len`].
    pub fn validate(&self) -> Result<(), ContainerError> {
        let needs_padding = match self.mode {
            Mode::Ecb | Mode::Cbc => true,
            Mode::Ctr => false,
        };
        if needs_padding && self.padding.is_none() {
            return Err(ContainerError::InvalidCombination(
                "ECB and CBC need a padding scheme",
            ));
        }
        if !needs_padding && self.padding.is_some() {
            return Err(ContainerError::InvalidCombination("CTR takes no padding"));
        }
        if self.iv.len() != self.mode.iv_len(self.algorithm) {
            return Err(ContainerError::InvalidCombination(
                "the IV must be one block for CBC and CTR and empty for ECB",
            ));
        }
        Ok(())
    }

    /// Validates the header and writes it. Nothing is written if validation fails.
    ///
    /// # Errors
    ///
    /// [`ContainerError::InvalidCombination`] as in [`validate`](Self::validate),
    /// or [`ContainerError::Io`] if writing fails.
    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), ContainerError> {
        self.validate()?;
        let mut fixed = [0u8; FIXED_LEN];
        fixed[..4].copy_from_slice(&MAGIC);
        fixed[4] = VERSION;
        fixed[5] = self.image_type.to_byte();
        fixed[6] = self.algorithm.to_byte();
        fixed[7] = self.mode.to_byte();
        fixed[8] = padding_to_byte(self.padding);
        fixed[9..].copy_from_slice(&self.original_len.to_be_bytes());
        writer.write_all(&fixed)?;
        writer.write_all(&self.iv)?;
        Ok(())
    }

    /// Reads and validates a header, leaving `reader` at the start of the ciphertext.
    ///
    /// # Errors
    ///
    /// Checked in this order:
    /// - [`ContainerError::Truncated`] if the input ends inside the header.
    /// - [`ContainerError::BadMagic`] if the signature is wrong.
    /// - [`ContainerError::UnsupportedVersion`] for any version but 1.
    /// - [`ContainerError::UnknownCode`] for an unknown image type, algorithm,
    ///   mode or padding code.
    /// - [`ContainerError::InvalidCombination`] as in [`validate`](Self::validate).
    /// - [`ContainerError::Io`] if reading fails.
    pub fn read_from<R: Read + ?Sized>(reader: &mut R) -> Result<Self, ContainerError> {
        let mut fixed = [0u8; FIXED_LEN];
        read_exact_or_truncated(reader, &mut fixed)?;
        if fixed[..4] != MAGIC {
            return Err(ContainerError::BadMagic);
        }
        if fixed[4] != VERSION {
            return Err(ContainerError::UnsupportedVersion(fixed[4]));
        }
        let image_type = ImageType::from_byte(fixed[5])?;
        let algorithm = Algorithm::from_byte(fixed[6])?;
        let mode = Mode::from_byte(fixed[7])?;
        let padding = padding_from_byte(fixed[8])?;
        let mut len = [0u8; 8];
        len.copy_from_slice(&fixed[9..]);

        let mut iv = vec![0u8; mode.iv_len(algorithm)];
        read_exact_or_truncated(reader, &mut iv)?;

        let header = Header {
            image_type,
            algorithm,
            mode,
            padding,
            iv,
            original_len: u64::from_be_bytes(len),
        };
        header.validate()?;
        Ok(header)
    }
}

/// Fills `buf`, reporting an early end of input as [`ContainerError::Truncated`].
fn read_exact_or_truncated<R: Read + ?Sized>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), ContainerError> {
    reader.read_exact(buf).map_err(|e| match e.kind() {
        ErrorKind::UnexpectedEof => ContainerError::Truncated,
        _ => ContainerError::Io(e),
    })
}
