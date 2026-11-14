//! Key expansion, FIPS 197 section 5.2.
//!
//! Written for any key length: `Nk` and `Nr` follow from the size of the key.

use super::tables::{ROUND_CONSTANTS, SBOX};

/// Size of the key schedule for the largest key: `4 * (Nr + 1)` with `Nr = 14`.
pub const MAX_WORDS: usize = 60;

/// SubWord: applies the S-box to each byte of a word.
fn sub_word(word: u32) -> u32 {
    u32::from_be_bytes(word.to_be_bytes().map(|byte| SBOX[byte as usize]))
}

/// RotWord: `[a0, a1, a2, a3]` becomes `[a1, a2, a3, a0]`.
fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

/// Fills `w` with the round keys and returns `Nr`. `KEY_SIZE` must be 16, 24 or 32.
///
/// The schedule is written in place so that no copy of it is left behind when
/// the caller wipes `w`.
pub fn expand_key<const KEY_SIZE: usize>(key: &[u8; KEY_SIZE], w: &mut [u32; MAX_WORDS]) -> usize {
    let nk = KEY_SIZE / 4;
    let nr = nk + 6;

    for (word, bytes) in w.iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }

    for i in nk..4 * (nr + 1) {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ ROUND_CONSTANTS[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }

    nr
}
