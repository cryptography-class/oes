//! Modes of operation that apply a block cipher to data longer than one block,
//! as specified in NIST SP 800-38A.
//!
//! **ECB and DES must not protect real data.** ECB is here to show why: equal
//! plaintext blocks give equal ciphertext blocks, so patterns stay visible.
//!
//! ECB and CBC work in place on a whole number of blocks, with padding as a
//! separate step in [`crate::padding`]. CTR works in place on any length and needs
//! no padding. None of these three authenticates anything, so changed ciphertext
//! decrypts to wrong bytes without an error.
//!
//! GCM (NIST SP 800-38D) is counter mode plus an authentication tag, so changed
//! data is rejected. It has separate types for the two directions,
//! [`GcmEncryptor`] and [`GcmDecryptor`].
//!
//! Modes keep their state between calls, so data can be processed chunk by chunk.
//! Use a new instance for each encryption or decryption run.
//!
//! Each mode can split its work between the threads of a Rayon pool, with the
//! same output as on one thread. This covers ECB, CTR, CBC decryption and the
//! counter step of GCM. CBC encryption always runs on one thread, because each
//! block needs the ciphertext of the block before it, and so does GHASH.

mod blocks;
mod cbc;
mod ctr;
mod ecb;
pub mod errors;
pub mod gcm;
mod ghash;
#[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
mod pclmul;
mod traits;
#[cfg(all(feature = "vpclmulqdq", target_arch = "x86_64"))]
mod vpclmul;

pub use cbc::Cbc;
pub use ctr::Ctr;
pub use ecb::Ecb;
pub use gcm::{GcmDecryptor, GcmEncryptor};
pub use traits::BlockMode;

#[cfg(test)]
mod tests;
