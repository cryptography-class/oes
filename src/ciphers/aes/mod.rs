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
//! [`AesCipher`] is the entry point, with the aliases [`Aes128Cipher`],
//! [`Aes192Cipher`] and [`Aes256Cipher`].

pub mod cipher;
mod key_schedule;
mod round;
mod tables;

pub use cipher::{Aes128Cipher, Aes192Cipher, Aes256Cipher, AesCipher};

#[cfg(test)]
mod tests;
