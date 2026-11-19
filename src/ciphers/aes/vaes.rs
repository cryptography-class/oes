//! AES on the processor's 256-bit AES instructions, known as VAES.
//!
//! VAES runs the same rounds as AES-NI on both 128-bit halves of a 256-bit register,
//! so one instruction carries two independent blocks through a round. Blocks go in
//! groups of 16, two to each of 8 registers, and each round key is copied into both
//! halves of a register once per call. Only whole groups are handled here: each
//! function returns the bytes after the last whole group, and the caller runs them on
//! AES-NI. Input shorter than a group comes straight back, before any key is copied.
//!
//! This is x86-64 only. 32-bit x86 has 8 vector registers, too few for the 8 states of
//! a group and a round key.
//!
//! Every function marked `#[target_feature]` may only run on a processor with these
//! instructions. [`Vaes::detect`] is the only way to get a [`Vaes`] and checks for
//! them first, so holding one proves that the check passed.

use std::arch::x86_64::{
    __m256i, _mm_loadu_si128, _mm_set_epi8, _mm_storeu_si128, _mm256_add_epi64,
    _mm256_aesdec_epi128, _mm256_aesdeclast_epi128, _mm256_aesenc_epi128, _mm256_aesenclast_epi128,
    _mm256_broadcastsi128_si256, _mm256_extracti128_si256, _mm256_loadu_si256,
    _mm256_permute2x128_si256, _mm256_set_epi64x, _mm256_setzero_si256, _mm256_shuffle_epi8,
    _mm256_storeu_si256, _mm256_xor_si256,
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
    if data.len() < GROUP_LEN {
        return data;
    }
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
    if data.len() < GROUP_LEN {
        return data;
    }
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

/// XORs the CTR keystream that starts at the 16-byte big-endian `counter` into each
/// whole group of `data`, leaves `counter` one past the last block used, and returns
/// the bytes after the last group. `keys` holds the `Nr + 1` round keys in encryption
/// order.
///
/// Each register holds two counters byte-reversed, so `_mm256_add_epi64` adds to the
/// low 64 bits of both, and one shuffle turns each half back into a big-endian block.
/// A group in which the low 64 bits would wrap builds its counters from a `u128`
/// instead, so the carry reaches the high half.
#[target_feature(enable = "aes,avx2,vaes")]
fn ctr_apply_groups<'a>(counter: &mut [u8], data: &'a mut [u8], keys: &[[u8; 16]]) -> &'a mut [u8] {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(counter);
    if data.len() < GROUP_LEN {
        return data;
    }
    let mut value = u128::from_be_bytes(bytes);
    let rounds = keys.len() - 1;
    let wide = wide_keys(keys);
    // Byte i of each half of the result is byte 15 - i of the same half of the input.
    let swap = _mm256_broadcastsi128_si256(_mm_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ));
    let mut groups = data.chunks_exact_mut(GROUP_LEN);
    for group in &mut groups {
        let low = value as u64;
        let mut states = [_mm256_setzero_si256(); WIDE];
        if low <= u64::MAX - (2 * WIDE as u64 - 1) {
            let high = (value >> 64) as i64;
            let base = _mm256_set_epi64x(high, low as i64, high, low as i64);
            for (i, state) in states.iter_mut().enumerate() {
                // The first block of the pair is the low half of the register.
                let step = _mm256_set_epi64x(0, 2 * i as i64 + 1, 0, 2 * i as i64);
                let next = _mm256_shuffle_epi8(_mm256_add_epi64(base, step), swap);
                *state = _mm256_xor_si256(next, wide[0]);
            }
        } else {
            for (i, state) in states.iter_mut().enumerate() {
                let first = value.wrapping_add(2 * i as u128);
                let mut pair = [0u8; 32];
                pair[..16].copy_from_slice(&first.to_be_bytes());
                pair[16..].copy_from_slice(&first.wrapping_add(1).to_be_bytes());
                *state = _mm256_xor_si256(load(&pair), wide[0]);
            }
        }
        value = value.wrapping_add(2 * WIDE as u128);
        for key in &wide[1..rounds] {
            for state in &mut states {
                *state = _mm256_aesenc_epi128(*state, *key);
            }
        }
        for (state, pair) in states.iter().zip(group.chunks_exact_mut(32)) {
            let keystream = _mm256_aesenclast_epi128(*state, wide[rounds]);
            store(pair, _mm256_xor_si256(keystream, load(pair)));
        }
    }
    counter.copy_from_slice(&value.to_be_bytes());
    groups.into_remainder()
}

/// Decrypts each whole group of `data` in place in CBC mode, chained from `chain`, the
/// ciphertext block before it, and returns the bytes after the last group. `chain` is
/// left holding the last ciphertext block of the last group. `keys` holds the `Nr + 1`
/// round keys of the equivalent inverse cipher.
///
/// Each register holds a pair of ciphertext blocks, which stay in registers for the
/// XOR step. Pair `j` is XORed with the two blocks one position earlier: the high half
/// of pair `j - 1` and the low half of pair `j`, which `_mm256_permute2x128_si256`
/// puts together. For the first pair of a group, the high half of `before` holds the
/// block before the group.
#[target_feature(enable = "aes,avx2,vaes")]
fn cbc_decrypt_groups<'a>(
    chain: &mut [u8; 16],
    data: &'a mut [u8],
    keys: &[[u8; 16]],
) -> &'a mut [u8] {
    if data.len() < GROUP_LEN {
        return data;
    }
    let rounds = keys.len() - 1;
    let wide = wide_keys(keys);
    // SAFETY: `chain` is 16 readable bytes, and this load has no alignment requirement.
    let mut before = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(chain.as_ptr().cast()) });
    let mut groups = data.chunks_exact_mut(GROUP_LEN);
    for group in &mut groups {
        let mut ciphertext = [_mm256_setzero_si256(); WIDE];
        let mut states = [_mm256_setzero_si256(); WIDE];
        for (j, pair) in group.chunks_exact(32).enumerate() {
            ciphertext[j] = load(pair);
            states[j] = _mm256_xor_si256(ciphertext[j], wide[0]);
        }
        for key in &wide[1..rounds] {
            for state in &mut states {
                *state = _mm256_aesdec_epi128(*state, *key);
            }
        }
        for (j, pair) in group.chunks_exact_mut(32).enumerate() {
            let earlier = if j == 0 { before } else { ciphertext[j - 1] };
            let shifted = _mm256_permute2x128_si256::<0x21>(earlier, ciphertext[j]);
            let decrypted = _mm256_aesdeclast_epi128(states[j], wide[rounds]);
            store(pair, _mm256_xor_si256(decrypted, shifted));
        }
        before = ciphertext[WIDE - 1];
    }
    let last = _mm256_extracti128_si256::<1>(before);
    // SAFETY: `chain` is 16 writable bytes through this exclusive reference, and this
    // store has no alignment requirement.
    unsafe { _mm_storeu_si128(chain.as_mut_ptr().cast(), last) };
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
    /// Panics if `data` holds a whole group and `keys` is empty or holds more than 15
    /// keys.
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
    /// Panics if `data` holds a whole group and `keys` is empty or holds more than 15
    /// keys.
    pub(super) fn decrypt_groups<'a>(self, data: &'a mut [u8], keys: &[[u8; 16]]) -> &'a mut [u8] {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { decrypt_groups(data, keys) }
    }

    /// XORs the CTR keystream that starts at the 16-byte big-endian `counter` into each
    /// whole group of 16 blocks of `data`, leaves `counter` one past the last block
    /// used, and returns the bytes after the last group. The counter wraps at 2^128.
    /// `keys` holds the `Nr + 1` round keys in encryption order.
    ///
    /// # Panics
    ///
    /// Panics if `counter` isn't exactly 16 bytes long, or if `data` holds a whole group
    /// and `keys` is empty or holds more than 15 keys.
    pub(super) fn ctr_apply_groups<'a>(
        self,
        counter: &mut [u8],
        data: &'a mut [u8],
        keys: &[[u8; 16]],
    ) -> &'a mut [u8] {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { ctr_apply_groups(counter, data, keys) }
    }

    /// Decrypts each whole group of 16 blocks of `data` in place in CBC mode, chained
    /// from `chain`, the ciphertext block before it, and returns the bytes after the
    /// last group. `chain` is left holding the last ciphertext block of the last group,
    /// which those bytes chain from. `keys` holds the `Nr + 1` round keys of the
    /// equivalent inverse cipher.
    ///
    /// # Panics
    ///
    /// Panics if `data` holds a whole group and `keys` is empty or holds more than 15
    /// keys.
    pub(super) fn cbc_decrypt_groups<'a>(
        self,
        chain: &mut [u8; 16],
        data: &'a mut [u8],
        keys: &[[u8; 16]],
    ) -> &'a mut [u8] {
        // SAFETY: `detect` is the only constructor, and it checks for these instructions.
        unsafe { cbc_decrypt_groups(chain, data, keys) }
    }
}
