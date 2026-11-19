//! GHASH multiplication on the processor's carry-less multiply instruction,
//! `PCLMULQDQ`.
//!
//! The instruction multiplies two 64-bit polynomials over GF(2), so four of them give
//! the full product of two blocks. The shift and the reduction that follow are those of
//! Gueron and Kounavis, "Intel Carry-Less Multiplication Instruction and its Usage for
//! Computing the GCM Mode". Blocks are big-endian `u128` values, as in the textbook
//! code: the coefficient of `x^i` is bit `127 - i` of the integer. Registers hold that
//! integer with its low half first, so each block's bytes are reversed when loaded,
//! which needs SSSE3.
//!
//! Whole blocks are absorbed four at a time with the aggregated reduction from the same
//! paper. Four steps of `Y = (Y ^ X) * H` give the same result as
//! `(Y ^ X1) * H^4 ^ X2 * H^3 ^ X3 * H^2 ^ X4 * H`, and those four products don't depend
//! on each other, so the processor overlaps them. They are added before reduction,
//! which is linear, so one reduction serves all four.
//!
//! Every function marked `#[target_feature]` may only run on a processor with these
//! instructions. [`Pclmul::detect`] is the only way to get a [`Pclmul`] and checks for
//! them first, so holding one proves that the check passed.
//!
//! The `vpclmul` module builds its 8-block loop on the conversions, the multiplication
//! and the reduction here.

#[cfg(target_arch = "x86")]
use std::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64 as arch;

use arch::{
    __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_or_si128, _mm_set_epi8, _mm_set_epi64x,
    _mm_shuffle_epi8, _mm_slli_epi64, _mm_slli_si128, _mm_srli_epi64, _mm_srli_si128,
    _mm_storeu_si128, _mm_xor_si128,
};

use super::ghash::BLOCK_LEN;

/// Moves a `u128` into a register, low half first.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
pub(super) fn from_u128(value: u128) -> __m128i {
    _mm_set_epi64x((value >> 64) as i64, value as i64)
}

/// Moves a register back into a `u128`.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
pub(super) fn to_u128(value: __m128i) -> u128 {
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is 16 writable bytes, and this store has no alignment requirement.
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), value) };
    // x86 processors are little-endian, so the low half of the register comes first.
    u128::from_le_bytes(bytes)
}

/// Loads a block as the big-endian integer the field arithmetic works on.
///
/// # Panics
///
/// Panics if `block` isn't exactly 16 bytes long.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn load_block(block: &[u8]) -> __m128i {
    assert_eq!(block.len(), BLOCK_LEN);
    // SAFETY: the assertion above makes the 16 bytes readable, and this load has no
    // alignment requirement.
    let bytes = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
    let reverse = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    _mm_shuffle_epi8(bytes, reverse)
}

/// Returns the full product of `a` and `b`, before reduction, as `(low, high)`.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
fn mul_wide(a: __m128i, b: __m128i) -> (__m128i, __m128i) {
    let low = _mm_clmulepi64_si128::<0x00>(a, b);
    let high = _mm_clmulepi64_si128::<0x11>(a, b);
    let middle = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x01>(a, b),
        _mm_clmulepi64_si128::<0x10>(a, b),
    );
    (
        _mm_xor_si128(low, _mm_slli_si128::<8>(middle)),
        _mm_xor_si128(high, _mm_srli_si128::<8>(middle)),
    )
}

/// Reduces a product from [`mul_wide`] to a block. The shifts work on 64-bit halves, so
/// the bits that cross from one half to the other are moved separately.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
pub(super) fn reduce(low: __m128i, high: __m128i) -> __m128i {
    // The bit order is reflected, so the 255-bit product sits one bit too low. Shift
    // all 256 bits left by one.
    let carry_low = _mm_srli_epi64::<63>(low);
    let carry_high = _mm_srli_epi64::<63>(high);
    let low = _mm_or_si128(_mm_slli_epi64::<1>(low), _mm_slli_si128::<8>(carry_low));
    let high = _mm_or_si128(
        _mm_or_si128(_mm_slli_epi64::<1>(high), _mm_slli_si128::<8>(carry_high)),
        _mm_srli_si128::<8>(carry_low),
    );

    // `low` now holds x^128 to x^255, and x^128 = x^7 + x^2 + x + 1. The right shifts
    // below multiply by those terms, so the bits they would push off the end are folded
    // back in first: `low << 127`, `<< 126` and `<< 121` as 128-bit shifts, which only
    // reach the upper half.
    let folded = _mm_xor_si128(
        _mm_xor_si128(_mm_slli_epi64::<63>(low), _mm_slli_epi64::<62>(low)),
        _mm_slli_epi64::<57>(low),
    );
    let low = _mm_xor_si128(low, _mm_slli_si128::<8>(folded));

    // `high ^ low ^ (low >> 1) ^ (low >> 2) ^ (low >> 7)` with 128-bit shifts.
    let upper = _mm_srli_si128::<8>(low);
    let right1 = _mm_xor_si128(_mm_srli_epi64::<1>(low), _mm_slli_epi64::<63>(upper));
    let right2 = _mm_xor_si128(_mm_srli_epi64::<2>(low), _mm_slli_epi64::<62>(upper));
    let right7 = _mm_xor_si128(_mm_srli_epi64::<7>(low), _mm_slli_epi64::<57>(upper));
    _mm_xor_si128(
        _mm_xor_si128(high, low),
        _mm_xor_si128(right1, _mm_xor_si128(right2, right7)),
    )
}

/// Returns `a * b` in GF(2^128), with the same result as the textbook `gf_mul`.
#[target_feature(enable = "pclmulqdq,ssse3")]
#[inline]
pub(super) fn multiply(a: __m128i, b: __m128i) -> __m128i {
    let (low, high) = mul_wide(a, b);
    reduce(low, high)
}

/// Absorbs each whole block of `blocks` into `y`, four at a time and then one at a
/// time. The loop stays inside this function because a `#[target_feature]` function
/// can't be inlined into a caller without it.
///
/// The powers of `h` are computed on each call, so they stay in registers and on the
/// stack, like `h` itself, rather than being stored.
#[target_feature(enable = "pclmulqdq,ssse3")]
fn absorb_all(y: u128, h: u128, blocks: &[u8]) -> u128 {
    let h1 = from_u128(h);
    let mut y = from_u128(y);
    let mut groups = blocks.chunks_exact(4 * BLOCK_LEN);

    if blocks.len() >= 4 * BLOCK_LEN {
        let h2 = multiply(h1, h1);
        let h3 = multiply(h2, h1);
        let h4 = multiply(h2, h2);
        for group in &mut groups {
            let first = _mm_xor_si128(y, load_block(&group[..16]));
            let (low0, high0) = mul_wide(first, h4);
            let (low1, high1) = mul_wide(load_block(&group[16..32]), h3);
            let (low2, high2) = mul_wide(load_block(&group[32..48]), h2);
            let (low3, high3) = mul_wide(load_block(&group[48..]), h1);
            let low = _mm_xor_si128(_mm_xor_si128(low0, low1), _mm_xor_si128(low2, low3));
            let high = _mm_xor_si128(_mm_xor_si128(high0, high1), _mm_xor_si128(high2, high3));
            y = reduce(low, high);
        }
    }

    for block in groups.remainder().chunks_exact(BLOCK_LEN) {
        y = multiply(_mm_xor_si128(y, load_block(block)), h1);
    }
    to_u128(y)
}

/// Proof that the processor has `PCLMULQDQ` and SSSE3.
#[derive(Clone, Copy)]
pub(super) struct Pclmul(());

impl Pclmul {
    /// Returns the proof, or `None` if the processor lacks either instruction set.
    pub(super) fn detect() -> Option<Self> {
        (is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("ssse3"))
            .then_some(Self(()))
    }

    /// Returns `y` after `Y_i = (Y_{i-1} ^ X_i) * H` for each whole block of `blocks`.
    /// Any bytes past the last whole block are ignored.
    pub(super) fn absorb(self, y: u128, h: u128, blocks: &[u8]) -> u128 {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { absorb_all(y, h, blocks) }
    }

    /// Returns `a * b` in GF(2^128), with the same result as the textbook `gf_mul`.
    pub(super) fn multiply(self, a: u128, b: u128) -> u128 {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { to_u128(multiply(from_u128(a), from_u128(b))) }
    }
}
