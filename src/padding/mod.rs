//! Padding schemes that extend data to a whole number of cipher blocks.
//!
//! Padding always adds at least one byte, so data that is already block-aligned
//! gains a full block. That way the last byte can always be read as the padding
//! length when it is removed.
//!
//! Padding is not authentication. Decrypting with a wrong key or tampered data
//! usually gives [`errors::PaddingError::Invalid`], but sometimes produces bytes
//! that happen to pass the check. Revealing whether the check passed can also leak
//! plaintext in CBC mode.

pub mod errors;
mod scheme;

pub use scheme::{Fill, Padding};

#[cfg(test)]
mod tests;
