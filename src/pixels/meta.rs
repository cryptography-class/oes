//! The metadata file written next to an encrypted image.
//!
//! ```text
//! offset  size  field
//! 0       4     magic "OESP"
//! 4       1     format version (1)
//! 5       1     algorithm   (container codes: 1 DES)
//! 6       1     mode        (container codes: 1 ECB, 2 CBC)
//! 7       1     padding     (container codes 1 to 4; 0, no padding, is invalid here)
//! 8       4     width in pixels,  u32 big-endian
//! 12      4     height in pixels, u32 big-endian
//! 16      n     IV: n = 0 for ECB, one block for CBC
//! 16+n    t     encrypted tail block: t = 0 if width * height * 3 is a multiple
//!               of the block size, otherwise one block
//! ```
//!
//! The IV and tail lengths aren't stored, because the other fields determine
//! them. The pixel format is always 8-bit RGB. The key is never stored.

use std::fs;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::path::Path;

use super::errors::PixelError;
use crate::container::{Algorithm, Header, ImageType, Mode, padding_from_byte, padding_to_byte};
use crate::padding::Padding;

const MAGIC: [u8; 4] = *b"OESP";
const VERSION: u8 = 1;
/// Everything before the IV.
const FIXED_LEN: usize = 16;
/// Bytes per pixel of 8-bit RGB.
const BYTES_PER_PIXEL: u128 = 3;

/// The settings of one pixel encryption, everything except the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PixelParams {
    pub algorithm: Algorithm,
    /// ECB or CBC.
    pub mode: Mode,
    pub padding: Padding,
    /// One block for CBC, empty for ECB.
    pub iv: Vec<u8>,
}

impl PixelParams {
    /// Checks that the settings make sense together, with the same rules as the
    /// container header.
    ///
    /// # Errors
    ///
    /// - [`PixelError::Invalid`] for CTR, which pixel encryption doesn't support.
    /// - [`PixelError::Container`] if the IV length or padding doesn't fit, as in
    ///   [`Header::validate`].
    pub fn validate(&self) -> Result<(), PixelError> {
        if self.mode == Mode::Ctr {
            return Err(PixelError::Invalid(
                "pixel encryption supports ECB and CBC only",
            ));
        }
        Header {
            image_type: ImageType::Unknown,
            algorithm: self.algorithm,
            mode: self.mode,
            padding: Some(self.padding),
            iv: self.iv.clone(),
            original_len: 0,
        }
        .validate()?;
        Ok(())
    }
}

/// The content of a metadata file: the settings, the image dimensions and the
/// encrypted tail block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PixelMeta {
    pub params: PixelParams,
    pub width: u32,
    pub height: u32,
    /// The encrypted, padded last partial block; empty if the pixel data is
    /// block-aligned.
    pub tail_block: Vec<u8>,
}

impl PixelMeta {
    /// Returns the length of the RGB pixel data in bytes. It is a `u128` because
    /// width times height times 3 can exceed `u64::MAX`.
    pub fn pixel_len(&self) -> u128 {
        u128::from(self.width) * u128::from(self.height) * BYTES_PER_PIXEL
    }

    /// Returns the tail block length the dimensions call for: 0 if the pixel data
    /// is block-aligned, otherwise one block.
    pub fn expected_tail_len(&self) -> usize {
        let block_size = self.params.algorithm.block_size();
        if self.pixel_len().is_multiple_of(block_size as u128) {
            0
        } else {
            block_size
        }
    }

    /// Checks the settings, that neither dimension is zero, and that the tail
    /// block has [`expected_tail_len`](Self::expected_tail_len) bytes.
    /// [`write_to`](Self::write_to) and [`read_from`](Self::read_from) both call it.
    ///
    /// # Errors
    ///
    /// [`PixelError::Invalid`] for a zero dimension or a wrong tail length, and the
    /// errors of [`PixelParams::validate`].
    pub fn validate(&self) -> Result<(), PixelError> {
        self.params.validate()?;
        if self.width == 0 || self.height == 0 {
            return Err(PixelError::Invalid("image dimensions must be non-zero"));
        }
        if self.tail_block.len() != self.expected_tail_len() {
            return Err(PixelError::Invalid(
                "the tail block in the metadata doesn't fit the image size",
            ));
        }
        Ok(())
    }

    /// Validates the metadata and writes it. Nothing is written if validation fails.
    ///
    /// # Errors
    ///
    /// The errors of [`validate`](Self::validate), or [`PixelError::Io`] if
    /// writing fails.
    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), PixelError> {
        self.validate()?;
        let mut fixed = [0u8; FIXED_LEN];
        fixed[..4].copy_from_slice(&MAGIC);
        fixed[4] = VERSION;
        fixed[5] = self.params.algorithm.to_byte();
        fixed[6] = self.params.mode.to_byte();
        fixed[7] = padding_to_byte(Some(self.params.padding));
        fixed[8..12].copy_from_slice(&self.width.to_be_bytes());
        fixed[12..].copy_from_slice(&self.height.to_be_bytes());
        writer.write_all(&fixed)?;
        writer.write_all(&self.params.iv)?;
        writer.write_all(&self.tail_block)?;
        Ok(())
    }

    /// Reads and validates metadata, leaving `reader` just after it.
    ///
    /// # Errors
    ///
    /// Checked in this order:
    /// - [`PixelError::Truncated`] if the input ends inside the metadata.
    /// - [`PixelError::BadMagic`] if the signature is wrong.
    /// - [`PixelError::UnsupportedVersion`] for any version but 1.
    /// - [`PixelError::Container`] for an unknown algorithm, mode or padding code.
    /// - [`PixelError::Invalid`] for no padding, and the errors of
    ///   [`validate`](Self::validate).
    /// - [`PixelError::Io`] if reading fails.
    pub fn read_from<R: Read + ?Sized>(reader: &mut R) -> Result<Self, PixelError> {
        let mut fixed = [0u8; FIXED_LEN];
        read_exact_or_truncated(reader, &mut fixed)?;
        if fixed[..4] != MAGIC {
            return Err(PixelError::BadMagic);
        }
        if fixed[4] != VERSION {
            return Err(PixelError::UnsupportedVersion(fixed[4]));
        }
        let algorithm = Algorithm::from_byte(fixed[5])?;
        let mode = Mode::from_byte(fixed[6])?;
        let padding = padding_from_byte(fixed[7])?.ok_or(PixelError::Invalid(
            "pixel metadata must name a padding scheme",
        ))?;
        let mut width = [0u8; 4];
        width.copy_from_slice(&fixed[8..12]);
        let mut height = [0u8; 4];
        height.copy_from_slice(&fixed[12..]);

        let mut iv = vec![0u8; mode.iv_len(algorithm)];
        read_exact_or_truncated(reader, &mut iv)?;
        let mut meta = PixelMeta {
            params: PixelParams {
                algorithm,
                mode,
                padding,
                iv,
            },
            width: u32::from_be_bytes(width),
            height: u32::from_be_bytes(height),
            tail_block: Vec::new(),
        };
        // CTR is refused before the tail length is used.
        meta.params.validate()?;
        meta.tail_block = vec![0u8; meta.expected_tail_len()];
        read_exact_or_truncated(reader, &mut meta.tail_block)?;
        meta.validate()?;
        Ok(meta)
    }

    /// Parses a whole metadata file held in memory.
    ///
    /// # Errors
    ///
    /// The errors of [`read_from`](Self::read_from), or [`PixelError::Invalid`] if
    /// any bytes follow the metadata.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PixelError> {
        let mut cursor = Cursor::new(bytes);
        let meta = Self::read_from(&mut cursor)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(PixelError::Invalid(
                "unexpected data after the pixel metadata",
            ));
        }
        Ok(meta)
    }

    /// Reads and parses the metadata file at `path`.
    ///
    /// # Errors
    ///
    /// [`PixelError::Io`] if the file can't be read, and the errors of
    /// [`from_bytes`](Self::from_bytes).
    pub fn read_file(path: &Path) -> Result<Self, PixelError> {
        Self::from_bytes(&fs::read(path)?)
    }
}

/// Fills `buf`, reporting an early end of input as [`PixelError::Truncated`].
fn read_exact_or_truncated<R: Read + ?Sized>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), PixelError> {
    reader.read_exact(buf).map_err(|e| match e.kind() {
        ErrorKind::UnexpectedEof => PixelError::Truncated,
        _ => PixelError::Io(e),
    })
}
