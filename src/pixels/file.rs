use std::io::Write;
use std::path::Path;

use super::buffer::{decrypt_buffer, encrypt_buffer};
use super::errors::PixelError;
use super::image_io::{encode, load_rgb, output_format};
use super::meta::{PixelMeta, PixelParams};
use crate::ciphers::traits::BlockCipher;
use crate::container::Mode;
use crate::modes::{Cbc, Ctr, Ecb, GcmDecryptor, GcmEncryptor};
use crate::stream::AtomicFile;

/// Encrypts the pixels of the image at `input`, writes a viewable image of the
/// same dimensions to `output` and the metadata needed to decrypt it to
/// `meta_path`, and returns that metadata.
///
/// `cipher` must be built with the key; the mode and its IV come from `params`.
/// For GCM, the tag goes into the metadata, and it also covers the metadata's
/// settings and dimensions.
/// The output format, PNG or BMP, comes from the extension of `output`. Both
/// files are written through [`AtomicFile`], and the metadata is committed
/// first, so a failed run never leaves an encrypted image without its metadata.
///
/// # Errors
///
/// - [`PixelError::Invalid`] if `output` and `meta_path` are the same path,
///   `output` doesn't end in `.png` or `.bmp`, or `cipher`'s block size doesn't
///   match `params.algorithm`.
/// - The errors of [`PixelParams::validate`] and [`encrypt_buffer`].
/// - [`PixelError::Image`] if `input` can't be decoded.
/// - [`PixelError::Io`] if a file can't be read or written, including an output
///   that exists while `overwrite` is false.
pub fn encrypt_image_file<C: BlockCipher>(
    input: &Path,
    output: &Path,
    meta_path: &Path,
    overwrite: bool,
    cipher: C,
    params: PixelParams,
) -> Result<PixelMeta, PixelError> {
    if output == meta_path {
        return Err(PixelError::Invalid(
            "the image and the metadata need different output paths",
        ));
    }
    let format = output_format(output)?;
    params.validate()?;
    check_block_size::<C>(&params)?;

    let mut image = load_rgb(input)?;
    let (width, height) = image.dimensions();
    let mut meta = PixelMeta {
        params,
        width,
        height,
        tail_block: Vec::new(),
        tag: None,
    };
    let params = &meta.params;
    match (params.mode, params.padding) {
        (Mode::Ecb, Some(padding)) => {
            meta.tail_block = encrypt_buffer(&mut Ecb::new(cipher), padding, &mut image)?;
        }
        (Mode::Cbc, Some(padding)) => {
            let mut cbc = Cbc::new(cipher, &params.iv)?;
            meta.tail_block = encrypt_buffer(&mut cbc, padding, &mut image)?;
        }
        (Mode::Ctr, _) => Ctr::new(cipher, &params.iv)?.apply_keystream(&mut image)?,
        (Mode::Gcm, _) => {
            let mut gcm = GcmEncryptor::new(cipher, &params.iv, &meta.fixed_bytes())?;
            gcm.update(&mut image)?;
            meta.tag = Some(gcm.finish());
        }
        (Mode::Ecb | Mode::Cbc, None) => return Err(missing_padding()),
    }
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
/// `cipher` must be built with the key; the mode and its IV come from `meta`.
/// The input must be the unchanged encrypted image. When the metadata names GCM,
/// its tag is checked before anything is written, so a changed pixel or metadata
/// field, or a wrong key, is refused; see `meta.rs` for why this depends on the
/// mode byte. The other modes decrypt a changed pixel to wrong pixels without an
/// error, and miss a wrong key unless the padding of an ECB or CBC tail block
/// catches it. Nothing is written on failure.
///
/// # Errors
///
/// - [`PixelError::Invalid`] if `output` doesn't end in `.png` or `.bmp`, or
///   `cipher`'s block size doesn't match the metadata.
/// - The errors of [`PixelMeta::validate`] and [`decrypt_buffer`].
/// - [`PixelError::Mode`] with [`ModeError::AuthenticationFailed`](crate::modes::errors::ModeError::AuthenticationFailed)
///   if the GCM tag doesn't match.
/// - [`PixelError::Image`] if `input` can't be decoded.
/// - [`PixelError::DimensionMismatch`] if the image doesn't have the dimensions in
///   `meta`.
/// - [`PixelError::Io`] if a file can't be read or written, including an output
///   that exists while `overwrite` is false.
pub fn decrypt_image_file<C: BlockCipher>(
    input: &Path,
    output: &Path,
    meta: &PixelMeta,
    overwrite: bool,
    cipher: C,
) -> Result<(), PixelError> {
    let format = output_format(output)?;
    meta.validate()?;
    let params = &meta.params;
    check_block_size::<C>(params)?;

    let mut image = load_rgb(input)?;
    let actual = image.dimensions();
    let expected = (meta.width, meta.height);
    if actual != expected {
        return Err(PixelError::DimensionMismatch { expected, actual });
    }
    match (params.mode, params.padding, &meta.tag) {
        (Mode::Ecb, Some(padding), _) => {
            decrypt_buffer(&mut Ecb::new(cipher), padding, &mut image, &meta.tail_block)?;
        }
        (Mode::Cbc, Some(padding), _) => {
            let mut cbc = Cbc::new(cipher, &params.iv)?;
            decrypt_buffer(&mut cbc, padding, &mut image, &meta.tail_block)?;
        }
        (Mode::Ctr, _, _) => Ctr::new(cipher, &params.iv)?.apply_keystream(&mut image)?,
        // The tag is checked before anything is encoded or written.
        (Mode::Gcm, _, Some(tag)) => {
            let mut gcm = GcmDecryptor::new(cipher, &params.iv, &meta.fixed_bytes())?;
            gcm.update(&mut image)?;
            gcm.verify(tag)?;
        }
        (Mode::Ecb | Mode::Cbc, None, _) => return Err(missing_padding()),
        (Mode::Gcm, _, None) => {
            return Err(PixelError::Invalid("the metadata holds no GCM tag"));
        }
    }
    let encoded = encode(&image, format)?;

    let mut image_file = AtomicFile::create(output, overwrite)?;
    image_file.write_all(&encoded)?;
    image_file.commit()?;
    Ok(())
}

/// Refuses a cipher whose block size differs from the algorithm in `params`.
fn check_block_size<C: BlockCipher>(params: &PixelParams) -> Result<(), PixelError> {
    if C::BLOCK_SIZE != params.algorithm.block_size() {
        return Err(PixelError::Invalid(
            "the cipher's block size doesn't match the algorithm in the metadata",
        ));
    }
    Ok(())
}

/// The error for ECB or CBC without padding, which [`PixelParams::validate`]
/// already refuses.
fn missing_padding() -> PixelError {
    PixelError::Invalid("ECB and CBC need a padding scheme")
}
