use std::io::Cursor;
use std::path::{Path, PathBuf};

use image::{ImageFormat, ImageReader, RgbImage};

use super::errors::PixelError;

/// Decodes the PNG or BMP image at `path` into 8-bit RGB, dropping any alpha
/// channel. The format is detected from the content, not the extension.
///
/// # Errors
///
/// [`PixelError::Io`] if the file can't be read, or [`PixelError::Image`] if it
/// isn't a PNG or BMP image that can be decoded.
pub fn load_rgb(path: &Path) -> Result<RgbImage, PixelError> {
    Ok(ImageReader::open(path)?
        .with_guessed_format()?
        .decode()?
        .to_rgb8())
}

/// Returns the lossless format named by the extension of `path`, `.png` or
/// `.bmp` in any case.
pub(super) fn output_format(path: &Path) -> Result<ImageFormat, PixelError> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("png") => Ok(ImageFormat::Png),
        Some("bmp") => Ok(ImageFormat::Bmp),
        _ => Err(PixelError::Invalid(
            "the output image must end in .png or .bmp",
        )),
    }
}

/// Encodes `image` in `format` in memory.
pub(super) fn encode(image: &RgbImage, format: ImageFormat) -> Result<Vec<u8>, PixelError> {
    let mut cursor = Cursor::new(Vec::new());
    image.write_to(&mut cursor, format)?;
    Ok(cursor.into_inner())
}

/// Returns the default metadata path for an encrypted image: the image path
/// with `.pixmeta` appended, so `a.png` and `a.bmp` don't share one.
///
/// # Examples
///
/// ```
/// use std::path::{Path, PathBuf};
/// use oes::pixels::default_meta_path;
///
/// assert_eq!(default_meta_path(Path::new("out/a.png")), PathBuf::from("out/a.png.pixmeta"));
/// ```
pub fn default_meta_path(image_path: &Path) -> PathBuf {
    let mut name = image_path.as_os_str().to_owned();
    name.push(".pixmeta");
    PathBuf::from(name)
}
