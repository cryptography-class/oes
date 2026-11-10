//! The Data Encryption Standard (DES) block cipher, as specified in FIPS 46-3.
//!
//! **DES is broken and must not protect real data.** Its 56-bit effective key can
//! be found by brute force. It is implemented here for study and comparison.
//!
//! DES encrypts 64-bit blocks with a 64-bit key, of which 8 bits are parity. The
//! code follows the specification step by step:
//!
//! - `key_schedule` derives the 16 round keys.
//! - `round` runs the 16 Feistel rounds, on several independent blocks at once
//!   when the experimental `interleave` feature is on (the default).
//! - `permutations` applies the initial and final permutations with delta swaps,
//!   in place of reading their tables bit by bit.
//! - `sp_tables` merges each S-box with the permutation P into one lookup table,
//!   built at compile time.
//! - `tables` holds the permutations and S-boxes from the specification.
//! - [`parity`] checks and sets the key's parity bits.
//!
//! [`DesCipher`] is the entry point.

pub mod cipher;
mod key_schedule;
mod permutations;
mod round;
mod sp_tables;
mod tables;
pub mod parity;

pub use cipher::DesCipher;

#[cfg(test)]
mod tests;
