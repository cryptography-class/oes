//! Pixel encryption: encrypts only the decoded pixels of an image and writes a
//! viewable image of the same dimensions, so ECB and CBC can be compared by eye.
//!
//! An image is decoded to 8-bit RGB (alpha is dropped), its pixel bytes are
//! encrypted in place with ECB or CBC, and the result is saved as lossless PNG or
//! BMP. Everything decryption needs except the key goes into a separate metadata
//! file, whose layout is documented in `meta.rs`. The caller builds the mode with
//! the key and IV, so this module never handles keys.
//!
//! Whole images are loaded into memory; large files belong in [`crate::stream`].
//!
//! **ECB and DES must not protect real data.** ECB is here to show why: flat
//! areas of an image keep their outline after encryption.

mod buffer;
pub mod errors;
mod file;
mod image_io;
mod meta;

pub use buffer::{count_distinct_blocks, decrypt_buffer, encrypt_buffer};
pub use errors::PixelError;
pub use file::{decrypt_image_file, encrypt_image_file};
pub use image_io::{default_meta_path, load_rgb};
pub use meta::{PixelMeta, PixelParams};

#[cfg(test)]
mod tests;
