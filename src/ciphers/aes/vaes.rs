//! AES on the processor's 256-bit AES instructions, known as VAES.
//!
//! VAES runs the same rounds as AES-NI on both 128-bit halves of a 256-bit register,
//! so one instruction carries two independent blocks through a round. Blocks go in
//! groups of 16, two to each of 8 registers, and each round key is copied into both
//! halves of a register once per call. Only whole groups are handled here: each
//! function returns the bytes after the last whole group, and the caller runs them on
//! AES-NI.
//!
//! This is x86-64 only. 32-bit x86 has 8 vector registers, too few for the 8 states of
//! a group and a round key.
//!
//! Every function marked `#[target_feature]` may only run on a processor with these
//! instructions. [`Vaes::detect`] is the only way to get a [`Vaes`] and checks for
//! them first, so holding one proves that the check passed.

use std::arch::x86_64::{
    __m256i, _mm_loadu_si128, _mm256_aesdec_epi128, _mm256_aesdeclast_epi128, _mm256_aesenc_epi128,
    _mm256_aesenclast_epi128, _mm256_broadcastsi128_si256, _mm256_loadu_si256,
    _mm256_setzero_si256, _mm256_storeu_si256, _mm256_xor_si256,
};

/// The number of registers in a group, each holding two blocks.
const WIDE: usize = 8;

/// The length of a group in bytes: [`WIDE`] registers of two 16-byte blocks.
const GROUP_LEN: usize = WIDE * 32;

/// Reads 32 bytes, two blocks, into a register.
///
/// # Panics
///
/// Panics if `bytes` isn't exactly 32 bytes long.
#[target_feature(enable = "avx2")]
#[inline]
fn load(bytes: &[u8]) -> __m256i {
    assert_eq!(bytes.len(), 32);
    // SAFETY: the assertion above makes the 32 bytes readable, and this load has no
    // alignment requirement.
    unsafe { _mm256_loadu_si256(bytes.as_ptr().cast()) }
}

/// Writes a register to 32 bytes.
///
/// # Panics
///
/// Panics if `bytes` isn't exactly 32 bytes long.
#[target_feature(enable = "avx2")]
#[inline]
fn store(bytes: &mut [u8], value: __m256i) {
    assert_eq!(bytes.len(), 32);
    // SAFETY: the assertion above makes the 32 bytes writable through this exclusive
    // reference, and this store has no alignment requirement.
    unsafe { _mm256_storeu_si256(bytes.as_mut_ptr().cast(), value) }
}

/// Returns each round key copied into both halves of a register. Entries past the
/// last key stay zero, and keys past the 15th are ignored.
#[target_feature(enable = "avx2")]
fn wide_keys(keys: &[[u8; 16]]) -> [__m256i; 15] {
    let mut wide = [_mm256_setzero_si256(); 15];
    for (wide, key) in wide.iter_mut().zip(keys) {
        // SAFETY: `key` is 16 readable bytes, and this load has no alignment requirement.
        let key = unsafe { _mm_loadu_si128(key.as_ptr().cast()) };
        *wide = _mm256_broadcastsi128_si256(key);
    }
    wide
}

/// Encrypts each whole group of `data` in place and returns the bytes after the last
/// one. `keys` holds the `Nr + 1` round keys in encryption order.
#[target_feature(enable = "aes,avx2,vaes")]
fn encrypt_groups<'a>(data: &'a mut [u8], keys: &[[u8; 16]]) -> &'a mut [u8] {
    let rounds = keys.len() - 1;
    let wide = wide_keys(keys);
    let mut groups = data.chunks_exact_mut(GROUP_LEN);
    for group in &mut groups {
        let mut states = [_mm256_setzero_si256(); WIDE];
        for (state, pair) in states.iter_mut().zip(group.chunks_exact(32)) {
            *state = _mm256_xor_si256(load(pair), wide[0]);
        }
        for key in &wide[1..rounds] {
            for state in &mut states {
                *state = _mm256_aesenc_epi128(*state, *key);
            }
        }
        for (state, pair) in states.iter().zip(group.chunks_exact_mut(32)) {
            store(pair, _mm256_aesenclast_epi128(*state, wide[rounds]));
        }
    }
    groups.into_remainder()
}

/// Decrypts each whole group of `data` in place and returns the bytes after the last
/// one. `keys` holds the `Nr + 1` round keys of the equivalent inverse cipher.
#[target_feature(enable = "aes,avx2,vaes")]
fn decrypt_groups<'a>(data: &'a mut [u8], keys: &[[u8; 16]]) -> &'a mut [u8] {
    let rounds = keys.len() - 1;
    let wide = wide_keys(keys);
    let mut groups = data.chunks_exact_mut(GROUP_LEN);
    for group in &mut groups {
        let mut states = [_mm256_setzero_si256(); WIDE];
        for (state, pair) in states.iter_mut().zip(group.chunks_exact(32)) {
            *state = _mm256_xor_si256(load(pair), wide[0]);
        }
        for key in &wide[1..rounds] {
            for state in &mut states {
                *state = _mm256_aesdec_epi128(*state, *key);
            }
        }
        for (state, pair) in states.iter().zip(group.chunks_exact_mut(32)) {
            store(pair, _mm256_aesdeclast_epi128(*state, wide[rounds]));
        }
    }
    groups.into_remainder()
}

/// Proof that the processor has AES-NI, AVX2 and VAES.
#[derive(Clone, Copy)]
pub(super) struct Vaes(());

impl Vaes {
    /// Returns the proof, or `None` if the processor lacks any of these instruction
    /// sets.
    pub(super) fn detect() -> Option<Self> {
        (is_x86_feature_detected!("aes")
            && is_x86_feature_detected!("avx2")
            && is_x86_feature_detected!("vaes"))
        .then_some(Self(()))
    }

    /// Encrypts each whole group of 16 blocks of `data` in place and returns the bytes
    /// after the last one. `keys` holds the `Nr + 1` round keys in encryption order.
    ///
    /// # Panics
    ///
    /// Panics if `keys` is empty or holds more than 15 keys.
    pub(super) fn encrypt_groups<'a>(self, data: &'a mut [u8], keys: &[[u8; 16]]) -> &'a mut [u8] {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { encrypt_groups(data, keys) }
    }

    /// Decrypts each whole group of 16 blocks of `data` in place and returns the bytes
    /// after the last one. `keys` holds the `Nr + 1` round keys of the equivalent
    /// inverse cipher.
    ///
    /// # Panics
    ///
    /// Panics if `keys` is empty or holds more than 15 keys.
    pub(super) fn decrypt_groups<'a>(self, data: &'a mut [u8], keys: &[[u8; 16]]) -> &'a mut [u8] {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { decrypt_groups(data, keys) }
    }
}
