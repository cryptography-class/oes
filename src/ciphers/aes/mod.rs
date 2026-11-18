//! The Advanced Encryption Standard (AES) block cipher, as specified in FIPS 197.
//!
//! AES encrypts 128-bit blocks with a 128, 192 or 256-bit key. Only the key
//! schedule and the number of rounds depend on the key length. The code follows
//! the specification step by step:
//!
//! - `key_schedule` expands the key into the round keys.
//! - `round` holds the round transformations and the full cipher and inverse cipher.
//! - `tables` holds the S-box, its inverse and the round constants.
//!
//! With the `aes-ni` Cargo feature on x86 and x86-64, `aes_ni` runs the same cipher on
//! the processor's AES instructions. The choice is made when a cipher is built, and
//! the code above is used on processors without those instructions.
//!
//! [`AesCipher`] is the entry point, with the aliases [`Aes128Cipher`],
//! [`Aes192Cipher`] and [`Aes256Cipher`].

#[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
mod aes_ni;
pub mod cipher;
mod key_schedule;
mod round;
mod tables;

pub use cipher::{Aes128Cipher, Aes192Cipher, Aes256Cipher, AesCipher};

#[cfg(test)]
mod tests;
