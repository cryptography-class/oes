//! GHASH multiplication on the processor's carry-less multiply instruction,
//! `PCLMULQDQ`.
//!
//! The instruction multiplies two 64-bit polynomials over GF(2), so four of them give
//! the full product of two blocks. The shift and the reduction that follow are those of
//! Gueron and Kounavis, "Intel Carry-Less Multiplication Instruction and its Usage for
//! Computing the GCM Mode". Blocks are big-endian `u128` values, as in the textbook
//! code: the coefficient of `x^i` is bit `127 - i` of the integer.
//!
//! Every function marked `#[target_feature]` may only run on a processor with this
//! instruction. [`Pclmul::detect`] is the only way to get a [`Pclmul`] and checks for it
//! first, so holding one proves that the check passed.

#[cfg(target_arch = "x86")]
use std::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64 as arch;

use arch::{_mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};

use super::ghash::BLOCK_LEN;

/// Returns the carry-less product of two 64-bit values.
#[target_feature(enable = "pclmulqdq")]
#[inline]
fn clmul(x: u64, y: u64) -> u128 {
    let product =
        _mm_clmulepi64_si128::<0x00>(_mm_set_epi64x(0, x as i64), _mm_set_epi64x(0, y as i64));
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is 16 writable bytes, and this store has no alignment requirement.
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), product) };
    // x86 processors are little-endian, so the low half of the register comes first.
    u128::from_le_bytes(bytes)
}

/// Returns `x * y` in GF(2^128), with the same result as the textbook `gf_mul`.
#[target_feature(enable = "pclmulqdq")]
#[inline]
fn multiply(x: u128, y: u128) -> u128 {
    let (x1, x0) = ((x >> 64) as u64, x as u64);
    let (y1, y0) = ((y >> 64) as u64, y as u64);

    let middle = clmul(x0, y1) ^ clmul(x1, y0);
    let high = clmul(x1, y1) ^ (middle >> 64);
    let low = clmul(x0, y0) ^ (middle << 64);

    // The bit order is reflected, so the 255-bit product sits one bit too low.
    let high = (high << 1) | (low >> 127);
    let low = low << 1;

    // `low` now holds x^128 to x^255, and x^128 = x^7 + x^2 + x + 1. The right shifts
    // below multiply by those terms, so the bits they would push off the end are folded
    // back in first.
    let low = low ^ (low << 127) ^ (low << 126) ^ (low << 121);
    high ^ low ^ (low >> 1) ^ (low >> 2) ^ (low >> 7)
}

/// Absorbs each whole block of `blocks` into `y`. The loop stays inside this function
/// because a `#[target_feature]` function can't be inlined into a caller without it.
#[target_feature(enable = "pclmulqdq")]
fn absorb_all(mut y: u128, h: u128, blocks: &[u8]) -> u128 {
    for block in blocks.chunks_exact(BLOCK_LEN) {
        let mut bytes = [0u8; BLOCK_LEN];
        bytes.copy_from_slice(block);
        y = multiply(y ^ u128::from_be_bytes(bytes), h);
    }
    y
}

/// Proof that the processor has `PCLMULQDQ`.
#[derive(Clone, Copy)]
pub(super) struct Pclmul(());

impl Pclmul {
    /// Returns the proof, or `None` if the processor lacks the instruction.
    pub(super) fn detect() -> Option<Self> {
        (is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("sse2"))
            .then_some(Self(()))
    }

    /// Returns `y` after `Y_i = (Y_{i-1} ^ X_i) * H` for each whole block of `blocks`.
    /// Any bytes past the last whole block are ignored.
    pub(super) fn absorb(self, y: u128, h: u128, blocks: &[u8]) -> u128 {
        // SAFETY: `detect` is the only constructor, and it checks for this instruction.
        unsafe { absorb_all(y, h, blocks) }
    }
}
