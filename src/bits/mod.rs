//! Bit-level helpers for the DES implementation.
//!
//! The DES specification (FIPS 46-3) numbers bits from the left, starting at 1,
//! while Rust's shift operators count from the right, starting at 0. These helpers
//! take positions as the specification writes them, so its tables can be used as
//! they are printed. For an 8-bit value:
//!
//! ```text
//! specification position   1  2  3  4  5  6  7  8
//! shift to reach the bit   7  6  5  4  3  2  1  0
//! ```
//!
//! `delta_swap` is the exception: it moves many bits at once, selected by a mask,
//! so it counts from the right as the shift operators do.
//!
//! The helpers don't validate their arguments. They are meant for fixed tables,
//! not for external input. Each function's `# Panics` section says what happens
//! when an argument is out of range.

mod ops;

pub use ops::{delta_swap, get_bit, permute, rotl28};

#[cfg(test)]
mod tests;
