use std::io::Write;
use std::path::Path;

use super::buffer::{decrypt_buffer, encrypt_buffer};
use super::errors::PixelError;
use super::image_io::{encode, load_rgb, output_format};
use super::meta::{PixelMeta, PixelParams};
use crate::modes::BlockMode;
use crate::stream::AtomicFile;

/// Encrypts the pixels of the image at `input`, writes a viewable image of the
/// same dimensions to `output` and the metadata needed to decrypt it to
/// `meta_path`, and returns that metadata.
///
/// `mode` must be built with the key and with `params.iv`. The output format,
/// PNG or BMP, comes from the extension of `output`. Both files are written
/// through [`AtomicFile`], and the metadata is committed first, so a failed run
/// never leaves an encrypted image without its metadata.
///
/// # Errors
///
/// - [`PixelError::Invalid`] if `output` and `meta_path` are the same path,
///   `output` doesn't end in `.png` or `.bmp`, or `mode`'s block size doesn't
///   match `params.algorithm`.
/// - The errors of [`PixelParams::validate`] and [`encrypt_buffer`].
/// - [`PixelError::Image`] if `input` can't be decoded.
/// - [`PixelError::Io`] if a file can't be read or written, including an output
///   that exists while `overwrite` is false.
pub fn encrypt_image_file(
    input: &Path,
    output: &Path,
    meta_path: &Path,
    overwrite: bool,
    mode: &mut dyn BlockMode,
    params: PixelParams,
) -> Result<PixelMeta, PixelError> {
    if output == meta_path {
        return Err(PixelError::Invalid(
            "the image and the metadata need different output paths",
        ));
    }
    let format = output_format(output)?;
    params.validate()?;
    check_block_size(mode, &params)?;

    let mut image = load_rgb(input)?;
    let (width, height) = image.dimensions();
    let tail_block = encrypt_buffer(mode, params.padding, &mut image)?;
    let meta = PixelMeta {
        params,
        width,
        height,
        tail_block,
    };
    let encoded = encode(&image, format)?;

    let mut image_file = AtomicFile::create(output, overwrite)?;
    image_file.write_all(&encoded)?;
    let mut meta_file = AtomicFile::create(meta_path, overwrite)?;
    meta.write_to(&mut meta_file)?;
    meta_file.commit()?;
    image_file.commit()?;
    Ok(meta)
}

/// Restores an image encrypted by [`encrypt_image_file`] and writes it to
/// `output`, whose extension picks PNG or BMP.
///
/// `mode` must be built with the key and with the IV from `meta`. The input must
/// be the unchanged encrypted image: a changed pixel decrypts to wrong pixels
/// without an error, and with a block-aligned image a wrong key goes unnoticed.
/// Nothing is written on failure.
///
/// # Errors
///
/// - [`PixelError::Invalid`] if `output` doesn't end in `.png` or `.bmp`, or
///   `mode`'s block size doesn't match the metadata.
/// - The errors of [`PixelMeta::validate`] and [`decrypt_buffer`].
/// - [`PixelError::Image`] if `input` can't be decoded.
/// - [`PixelError::DimensionMismatch`] if the image doesn't have the dimensions in
///   `meta`.
/// - [`PixelError::Io`] if a file can't be read or written, including an output
///   that exists while `overwrite` is false.
pub fn decrypt_image_file(
    input: &Path,
    output: &Path,
    meta: &PixelMeta,
    overwrite: bool,
    mode: &mut dyn BlockMode,
) -> Result<(), PixelError> {
    let format = output_format(output)?;
    meta.validate()?;
    check_block_size(mode, &meta.params)?;

    let mut image = load_rgb(input)?;
    let actual = image.dimensions();
    let expected = (meta.width, meta.height);
    if actual != expected {
        return Err(PixelError::DimensionMismatch { expected, actual });
    }
    decrypt_buffer(mode, meta.params.padding, &mut image, &meta.tail_block)?;
    let encoded = encode(&image, format)?;

    let mut image_file = AtomicFile::create(output, overwrite)?;
    image_file.write_all(&encoded)?;
    image_file.commit()?;
    Ok(())
}

/// Refuses a mode whose block size differs from the algorithm in `params`.
fn check_block_size(mode: &dyn BlockMode, params: &PixelParams) -> Result<(), PixelError> {
    if mode.block_size() != params.algorithm.block_size() {
        return Err(PixelError::Invalid(
            "the mode's block size doesn't match the algorithm in the metadata",
        ));
    }
    Ok(())
}
