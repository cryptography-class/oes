//! The encrypted file container: a header in front of the ciphertext, holding
//! everything decryption needs except the key.
//!
//! The header records the original image type, algorithm, mode, padding, IV and
//! original length. Its byte layout is documented in `header.rs`. The key is
//! never stored. The header isn't authenticated, so a changed header is caught
//! only when it gives invalid codes or makes decryption fail.
//!
//! **DES and ECB must not protect real data.**

pub mod errors;
mod fields;
mod header;

pub use fields::{Algorithm, ImageType, Mode};
pub use header::Header;

#[cfg(test)]
mod tests;
