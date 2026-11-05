//! Modes of operation that apply a block cipher to data longer than one block,
//! as specified in NIST SP 800-38A.
//!
//! **ECB and DES must not protect real data.** ECB is here to show why: equal
//! plaintext blocks give equal ciphertext blocks, so patterns stay visible.
//!
//! ECB and CBC work in place on a whole number of blocks, with padding as a
//! separate step in [`crate::padding`]. Neither of them authenticates anything, so
//! changed ciphertext decrypts to wrong bytes without an error.
//!
//! Modes keep their state between calls, so data can be processed chunk by chunk.
//! Use a new instance for each encryption or decryption run.

mod blocks;
mod cbc;
mod ecb;
pub mod errors;
mod traits;

pub use cbc::Cbc;
pub use ecb::Ecb;
pub use traits::BlockMode;

#[cfg(test)]
mod tests;
