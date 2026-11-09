//! Cipher keys: generation, key files and validation.
//!
//! A key file holds only the raw key bytes, so the caller names the algorithm
//! when loading it. Every [`Key`] has been checked for length and, for DES,
//! parity, and is erased from memory when dropped.

pub mod errors;
mod key;

pub use key::Key;

#[cfg(test)]
mod tests;
