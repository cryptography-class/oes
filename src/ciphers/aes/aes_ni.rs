//! AES on the processor's AES instructions, known as AES-NI.
//!
//! The instructions carry out whole rounds of FIPS 197, so the S-box lookups of the
//! table-based code disappear. Key expansion follows the per-key-size routines in
//! Shay Gueron's Intel white paper "Advanced Encryption Standard (AES) New
//! Instructions Set". Decryption uses the equivalent inverse cipher of FIPS 197
//! section 5.3.5, which is the order of operations that `aesdec` implements.
//!
//! Every function marked `#[target_feature]` may only run on a processor with these
//! instructions. [`AesNiKeys::empty`] is the only way to get an [`AesNiKeys`] and
//! checks for them first, so holding one proves that the check passed.

#[cfg(target_arch = "x86")]
use std::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64 as arch;

use arch::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aesimc_si128, _mm_aeskeygenassist_si128, _mm_loadl_epi64, _mm_loadu_si128,
    _mm_shuffle_epi32, _mm_slli_si128, _mm_srli_si128, _mm_storeu_si128, _mm_unpacklo_epi64,
    _mm_xor_si128,
};

use crate::secret::wipe;

/// Round keys as bytes in FIPS 197 order, with room for the 15 of a 256-bit key.
type RoundKeys = [[u8; 16]; 15];

/// Reads 16 bytes into a register.
///
/// # Panics
///
/// Panics if `bytes` isn't exactly 16 bytes long.
#[target_feature(enable = "aes")]
#[inline]
fn load(bytes: &[u8]) -> __m128i {
    assert_eq!(bytes.len(), 16);
    // SAFETY: the assertion above makes the 16 bytes readable, and this load has no
    // alignment requirement.
    unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
}

/// Reads 8 bytes into the low half of a register and clears the high half.
///
/// # Panics
///
/// Panics if `bytes` isn't exactly 8 bytes long.
#[target_feature(enable = "aes")]
#[inline]
fn load_low(bytes: &[u8]) -> __m128i {
    assert_eq!(bytes.len(), 8);
    // SAFETY: the assertion above makes the 8 bytes this load reads available, and it
    // has no alignment requirement.
    unsafe { _mm_loadl_epi64(bytes.as_ptr().cast()) }
}

/// Writes a register to 16 bytes.
///
/// # Panics
///
/// Panics if `bytes` isn't exactly 16 bytes long.
#[target_feature(enable = "aes")]
#[inline]
fn store(bytes: &mut [u8], value: __m128i) {
    assert_eq!(bytes.len(), 16);
    // SAFETY: the assertion above makes the 16 bytes writable through this exclusive
    // reference, and this store has no alignment requirement.
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), value) }
}

/// XORs each word of `key` with all the words before it, which is the chain
/// `w[i] = w[i - Nk] ^ w[i - 1]` of FIPS 197 section 5.2 done four words at once.
#[target_feature(enable = "aes")]
#[inline]
fn chain_words(key: __m128i) -> __m128i {
    let key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));
    let key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));
    _mm_xor_si128(key, _mm_slli_si128::<4>(key))
}

/// Derives four words from `older` using SubWord, RotWord and `RCON` on the last word
/// of `newest`.
#[target_feature(enable = "aes")]
#[inline]
fn next_with_rcon<const RCON: i32>(older: __m128i, newest: __m128i) -> __m128i {
    let assist = _mm_shuffle_epi32::<0xFF>(_mm_aeskeygenassist_si128::<RCON>(newest));
    _mm_xor_si128(chain_words(older), assist)
}

/// Fills the 11 round keys of a 128-bit key.
#[target_feature(enable = "aes")]
fn expand_128(key: &[u8], keys: &mut RoundKeys) {
    let mut current = load(key);
    store(&mut keys[0], current);

    current = next_with_rcon::<0x01>(current, current);
    store(&mut keys[1], current);
    current = next_with_rcon::<0x02>(current, current);
    store(&mut keys[2], current);
    current = next_with_rcon::<0x04>(current, current);
    store(&mut keys[3], current);
    current = next_with_rcon::<0x08>(current, current);
    store(&mut keys[4], current);
    current = next_with_rcon::<0x10>(current, current);
    store(&mut keys[5], current);
    current = next_with_rcon::<0x20>(current, current);
    store(&mut keys[6], current);
    current = next_with_rcon::<0x40>(current, current);
    store(&mut keys[7], current);
    current = next_with_rcon::<0x80>(current, current);
    store(&mut keys[8], current);
    current = next_with_rcon::<0x1B>(current, current);
    store(&mut keys[9], current);
    current = next_with_rcon::<0x36>(current, current);
    store(&mut keys[10], current);
}

/// Derives the next six words of a 192-bit schedule: four in the first register
/// returned, and two in the low half of the second.
#[target_feature(enable = "aes")]
#[inline]
fn next_192<const RCON: i32>(high: __m128i, low: __m128i) -> (__m128i, __m128i) {
    // The last word so far is word 1 of `low`, which the assist result holds in word 1.
    let assist = _mm_shuffle_epi32::<0x55>(_mm_aeskeygenassist_si128::<RCON>(low));
    let high = _mm_xor_si128(chain_words(high), assist);
    let carry = _mm_shuffle_epi32::<0xFF>(high);
    let low = _mm_xor_si128(_mm_xor_si128(low, _mm_slli_si128::<4>(low)), carry);
    (high, low)
}

/// Joins the low halves of two registers, `first` below `second`.
#[target_feature(enable = "aes")]
#[inline]
fn join_low(first: __m128i, second: __m128i) -> __m128i {
    _mm_unpacklo_epi64(first, second)
}

/// Joins the high half of `first` below the low half of `second`.
#[target_feature(enable = "aes")]
#[inline]
fn join_high_low(first: __m128i, second: __m128i) -> __m128i {
    _mm_unpacklo_epi64(_mm_srli_si128::<8>(first), second)
}

/// Fills the 13 round keys of a 192-bit key.
///
/// Each step yields six words but a round key takes four, so two steps fill three
/// round keys and the halves are joined across steps.
#[target_feature(enable = "aes")]
fn expand_192(key: &[u8], keys: &mut RoundKeys) {
    let (high0, low0) = (load(&key[..16]), load_low(&key[16..]));
    store(&mut keys[0], high0);

    let (high1, low1) = next_192::<0x01>(high0, low0);
    store(&mut keys[1], join_low(low0, high1));
    store(&mut keys[2], join_high_low(high1, low1));

    let (high2, low2) = next_192::<0x02>(high1, low1);
    store(&mut keys[3], high2);

    let (high3, low3) = next_192::<0x04>(high2, low2);
    store(&mut keys[4], join_low(low2, high3));
    store(&mut keys[5], join_high_low(high3, low3));

    let (high4, low4) = next_192::<0x08>(high3, low3);
    store(&mut keys[6], high4);

    let (high5, low5) = next_192::<0x10>(high4, low4);
    store(&mut keys[7], join_low(low4, high5));
    store(&mut keys[8], join_high_low(high5, low5));

    let (high6, low6) = next_192::<0x20>(high5, low5);
    store(&mut keys[9], high6);

    let (high7, low7) = next_192::<0x40>(high6, low6);
    store(&mut keys[10], join_low(low6, high7));
    store(&mut keys[11], join_high_low(high7, low7));

    let (high8, _) = next_192::<0x80>(high7, low7);
    store(&mut keys[12], high8);
}

/// Derives four words from `older` using only SubWord on the last word of `newest`,
/// the extra step that FIPS 197 section 5.2 adds for 256-bit keys.
#[target_feature(enable = "aes")]
#[inline]
fn next_without_rcon(older: __m128i, newest: __m128i) -> __m128i {
    let assist = _mm_shuffle_epi32::<0xAA>(_mm_aeskeygenassist_si128::<0>(newest));
    _mm_xor_si128(chain_words(older), assist)
}

/// Fills the 15 round keys of a 256-bit key.
#[target_feature(enable = "aes")]
fn expand_256(key: &[u8], keys: &mut RoundKeys) {
    let mut older = load(&key[..16]);
    let mut newer = load(&key[16..]);
    store(&mut keys[0], older);
    store(&mut keys[1], newer);

    older = next_with_rcon::<0x01>(older, newer);
    store(&mut keys[2], older);
    newer = next_without_rcon(newer, older);
    store(&mut keys[3], newer);
    older = next_with_rcon::<0x02>(older, newer);
    store(&mut keys[4], older);
    newer = next_without_rcon(newer, older);
    store(&mut keys[5], newer);
    older = next_with_rcon::<0x04>(older, newer);
    store(&mut keys[6], older);
    newer = next_without_rcon(newer, older);
    store(&mut keys[7], newer);
    older = next_with_rcon::<0x08>(older, newer);
    store(&mut keys[8], older);
    newer = next_without_rcon(newer, older);
    store(&mut keys[9], newer);
    older = next_with_rcon::<0x10>(older, newer);
    store(&mut keys[10], older);
    newer = next_without_rcon(newer, older);
    store(&mut keys[11], newer);
    older = next_with_rcon::<0x20>(older, newer);
    store(&mut keys[12], older);
    newer = next_without_rcon(newer, older);
    store(&mut keys[13], newer);
    older = next_with_rcon::<0x40>(older, newer);
    store(&mut keys[14], older);
}

/// Derives the decryption keys of the equivalent inverse cipher, FIPS 197 section
/// 5.3.5: the encryption keys reversed, with InvMixColumns applied to all but the
/// first and last.
#[target_feature(enable = "aes")]
fn invert_keys(encrypt: &RoundKeys, decrypt: &mut RoundKeys, rounds: usize) {
    decrypt[0] = encrypt[rounds];
    for (inverse, key) in decrypt[1..rounds]
        .iter_mut()
        .zip(encrypt[1..rounds].iter().rev())
    {
        store(inverse, _mm_aesimc_si128(load(key)));
    }
    decrypt[rounds] = encrypt[0];
}

/// Encrypts one block held as bytes, in place.
#[target_feature(enable = "aes")]
#[inline]
fn encrypt_in_place(block: &mut [u8], keys: &RoundKeys, rounds: usize) {
    let mut state = _mm_xor_si128(load(block), load(&keys[0]));
    for key in &keys[1..rounds] {
        state = _mm_aesenc_si128(state, load(key));
    }
    store(block, _mm_aesenclast_si128(state, load(&keys[rounds])));
}

/// Decrypts one block held as bytes, in place, with keys from [`invert_keys`].
#[target_feature(enable = "aes")]
#[inline]
fn decrypt_in_place(block: &mut [u8], keys: &RoundKeys, rounds: usize) {
    let mut state = _mm_xor_si128(load(block), load(&keys[0]));
    for key in &keys[1..rounds] {
        state = _mm_aesdec_si128(state, load(key));
    }
    store(block, _mm_aesdeclast_si128(state, load(&keys[rounds])));
}

/// The round keys of one AES key, usable only on a processor with AES-NI.
pub struct AesNiKeys {
    /// The round keys in the order encryption uses them.
    pub(super) encrypt: RoundKeys,
    /// The round keys of the equivalent inverse cipher.
    decrypt: RoundKeys,
    /// `Nr`, the number of rounds.
    pub(super) rounds: usize,
}

impl AesNiKeys {
    /// Returns blank keys, or `None` if the processor lacks AES-NI.
    pub fn empty() -> Option<Self> {
        if !(is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2")) {
            return None;
        }
        Some(Self {
            encrypt: [[0; 16]; 15],
            decrypt: [[0; 16]; 15],
            rounds: 0,
        })
    }

    /// Derives the round keys from `key`, in place so that no copy of them is left
    /// behind when they are wiped. `KEY_SIZE` must be 16, 24 or 32.
    pub fn expand_key<const KEY_SIZE: usize>(&mut self, key: &[u8; KEY_SIZE]) {
        self.rounds = KEY_SIZE / 4 + 6;
        // SAFETY: `empty` is the only constructor, and it checks for these instructions.
        unsafe {
            match KEY_SIZE {
                16 => expand_128(key, &mut self.encrypt),
                24 => expand_192(key, &mut self.encrypt),
                _ => expand_256(key, &mut self.encrypt),
            }
            invert_keys(&self.encrypt, &mut self.decrypt, self.rounds);
        }
    }

    /// Encrypts one block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        // SAFETY: `empty` is the only constructor, and it checks for these instructions.
        unsafe { encrypt_in_place(block, &self.encrypt, self.rounds) }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        // SAFETY: `empty` is the only constructor, and it checks for these instructions.
        unsafe { decrypt_in_place(block, &self.decrypt, self.rounds) }
    }

    /// Erases the round keys from memory.
    pub fn wipe(&mut self) {
        wipe(&mut self.encrypt);
        wipe(&mut self.decrypt);
    }
}
