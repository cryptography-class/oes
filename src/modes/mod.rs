//! Modes of operation that apply a block cipher to data longer than one block,
//! as specified in NIST SP 800-38A.
//!
//! **ECB and DES must not protect real data.** ECB is here to show why: equal
//! plaintext blocks give equal ciphertext blocks, so patterns stay visible.
//!
//! ECB and CBC work in place on a whole number of blocks, with padding as a
//! separate step in [`crate::padding`]. CTR works in place on any length and needs
//! no padding. None of them authenticates anything, so changed ciphertext decrypts
//! to wrong bytes without an error.
//!
//! Modes keep their state between calls, so data can be processed chunk by chunk.
//! Use a new instance for each encryption or decryption run.
//!
//! Each mode can split its work between the threads of a Rayon pool, with the
//! same output as on one thread. This covers ECB, CTR and CBC decryption. CBC
//! encryption always runs on one thread, because each block needs the ciphertext
//! of the block before it.

mod blocks;
mod cbc;
mod ctr;
mod ecb;
pub mod errors;
mod traits;

pub use cbc::Cbc;
pub use ctr::Ctr;
pub use ecb::Ecb;
pub use traits::BlockMode;

#[cfg(test)]
mod tests;
