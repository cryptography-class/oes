//! Parity bits of DES keys.
//!
//! FIPS 46-3 reserves the lowest bit of each key byte so that the byte has an odd
//! number of ones. They only detect corrupted keys: the cipher itself ignores them.

mod odd_parity;

pub use odd_parity::{check_parity, first_bad_parity_byte, set_parity};

#[cfg(test)]
mod tests;