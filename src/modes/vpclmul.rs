//! GHASH on the processor's 256-bit carry-less multiply instruction, `VPCLMULQDQ`.
//!
//! The instruction does the work of `PCLMULQDQ` on both 128-bit halves of a register,
//! so each step multiplies two blocks. Whole groups of eight blocks are absorbed with
//! one reduction each, the same aggregation that the `pclmul` module uses for four:
//! eight steps of `Y = (Y ^ X) * H` give the same result as
//! `(Y ^ X1) * H^8 ^ X2 * H^7 ^ ... ^ X8 * H`. The eight products are taken two per
//! register and added before reduction, which is linear, and the two halves of the sum
//! are added together before the one reduction. The conversions, the multiplication of
//! the powers of `H` and the reduction come from the `pclmul` module.
//!
//! This is x86-64 only, like the 256-bit AES code.
//!
//! Every function marked `#[target_feature]` may only run on a processor with these
//! instructions. [`Vpclmul::detect`] is the only way to get a [`Vpclmul`] and checks
//! for them first, so holding one proves that the check passed.

use std::arch::x86_64::{
    __m256i, _mm_set_epi8, _mm_setzero_si128, _mm_xor_si128, _mm256_broadcastsi128_si256,
    _mm256_castsi256_si128, _mm256_clmulepi64_epi128, _mm256_extracti128_si256, _mm256_loadu_si256,
    _mm256_set_m128i, _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_slli_si256,
    _mm256_srli_si256, _mm256_xor_si256,
};

use super::ghash::BLOCK_LEN;
use super::pclmul::{from_u128, multiply, reduce, to_u128};

/// The number of blocks absorbed per reduction.
const GROUP_BLOCKS: usize = 8;

/// Loads two blocks into a register, each as the big-endian integer the field
/// arithmetic works on, the first block in the low half.
///
/// # Panics
///
/// Panics if `pair` isn't exactly 32 bytes long.
#[target_feature(enable = "avx2")]
#[inline]
fn load_pair(pair: &[u8]) -> __m256i {
    assert_eq!(pair.len(), 2 * BLOCK_LEN);
    // SAFETY: the assertion above makes the 32 bytes readable, and this load has no
    // alignment requirement.
    let bytes = unsafe { _mm256_loadu_si256(pair.as_ptr().cast()) };
    let reverse = _mm256_broadcastsi128_si256(_mm_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ));
    _mm256_shuffle_epi8(bytes, reverse)
}

/// Absorbs each whole group of `blocks` into `y`, and returns the new `y` and the
/// bytes after the last group. The powers of `h` are computed on each call that has a
/// whole group, so they stay in registers and on the stack rather than being stored.
#[target_feature(enable = "pclmulqdq,ssse3,avx2,vpclmulqdq")]
fn absorb_groups(y: u128, h: u128, blocks: &[u8]) -> (u128, &[u8]) {
    if blocks.len() < GROUP_BLOCKS * BLOCK_LEN {
        return (y, blocks);
    }
    let h1 = from_u128(h);
    let h2 = multiply(h1, h1);
    let h3 = multiply(h2, h1);
    let h4 = multiply(h2, h2);
    let h5 = multiply(h4, h1);
    let h6 = multiply(h3, h3);
    let h7 = multiply(h6, h1);
    let h8 = multiply(h4, h4);
    // The earlier block of each pair is in the low half, so it takes the higher power.
    let powers = [
        _mm256_set_m128i(h7, h8),
        _mm256_set_m128i(h5, h6),
        _mm256_set_m128i(h3, h4),
        _mm256_set_m128i(h1, h2),
    ];

    let mut y = from_u128(y);
    let mut groups = blocks.chunks_exact(GROUP_BLOCKS * BLOCK_LEN);
    for group in &mut groups {
        let mut low = _mm256_setzero_si256();
        let mut high = _mm256_setzero_si256();
        for (i, (pair, power)) in group.chunks_exact(2 * BLOCK_LEN).zip(powers).enumerate() {
            let mut x = load_pair(pair);
            if i == 0 {
                x = _mm256_xor_si256(x, _mm256_set_m128i(_mm_setzero_si128(), y));
            }
            // The full product of each half, as in `mul_wide` of the `pclmul` module.
            let middle = _mm256_xor_si256(
                _mm256_clmulepi64_epi128::<0x01>(x, power),
                _mm256_clmulepi64_epi128::<0x10>(x, power),
            );
            low = _mm256_xor_si256(low, _mm256_clmulepi64_epi128::<0x00>(x, power));
            low = _mm256_xor_si256(low, _mm256_slli_si256::<8>(middle));
            high = _mm256_xor_si256(high, _mm256_clmulepi64_epi128::<0x11>(x, power));
            high = _mm256_xor_si256(high, _mm256_srli_si256::<8>(middle));
        }
        let low = _mm_xor_si128(
            _mm256_castsi256_si128(low),
            _mm256_extracti128_si256::<1>(low),
        );
        let high = _mm_xor_si128(
            _mm256_castsi256_si128(high),
            _mm256_extracti128_si256::<1>(high),
        );
        y = reduce(low, high);
    }
    (to_u128(y), groups.remainder())
}

/// Proof that the processor has `PCLMULQDQ`, SSSE3, AVX2 and `VPCLMULQDQ`.
#[derive(Clone, Copy)]
pub(super) struct Vpclmul(());

impl Vpclmul {
    /// Returns the proof, or `None` if the processor lacks any of these instruction
    /// sets.
    pub(super) fn detect() -> Option<Self> {
        (is_x86_feature_detected!("pclmulqdq")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("avx2")
            && is_x86_feature_detected!("vpclmulqdq"))
        .then_some(Self(()))
    }

    /// Absorbs each whole group of 8 blocks of `blocks` into `y` as
    /// `Y_i = (Y_{i-1} ^ X_i) * H`, and returns the new `y` and the bytes after the
    /// last group. Input shorter than a group comes straight back.
    pub(super) fn absorb_groups(self, y: u128, h: u128, blocks: &[u8]) -> (u128, &[u8]) {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { absorb_groups(y, h, blocks) }
    }
}
