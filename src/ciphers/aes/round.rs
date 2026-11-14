//! The AES round transformations and the full cipher, FIPS 197 sections 5.1 and 5.3.
//!
//! The state is stored as the 16 input bytes in their original order. FIPS 197
//! fills its 4x4 state column by column, so row `r` of column `c` is at index
//! `r + 4 * c`.

use super::tables::{INV_SBOX, SBOX};

pub type State = [u8; 16];

/// FIPS 197 section 5.1.1: SubBytes.
fn sub_bytes(state: &mut State) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

/// FIPS 197 section 5.3.2: InvSubBytes.
fn inv_sub_bytes(state: &mut State) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

/// ShiftRows (FIPS 197 section 5.1.2): row `r` rotates left by `r` positions.
fn shift_rows(state: &mut State) {
    let old = *state;
    for r in 0..4 {
        for c in 0..4 {
            state[r + 4 * c] = old[r + 4 * ((c + r) % 4)];
        }
    }
}

/// InvShiftRows (FIPS 197 section 5.3.1): row `r` rotates right by `r` positions.
fn inv_shift_rows(state: &mut State) {
    let old = *state;
    for r in 0..4 {
        for c in 0..4 {
            state[r + 4 * ((c + r) % 4)] = old[r + 4 * c];
        }
    }
}

/// Multiplication by `x` in GF(2^8), FIPS 197 section 4.2.1. Reduces by the AES polynomial
/// `x^8 + x^4 + x^3 + x + 1` when the top bit falls off, without branching.
#[inline(always)]
fn xtime(b: u8) -> u8 {
    (b << 1) ^ (0x1b & (b >> 7).wrapping_neg())
}

/// FIPS 197 section 5.1.3: MixColumns.
fn mix_columns(state: &mut State) {
    for column in state.chunks_exact_mut(4) {
        let [s0, s1, s2, s3] = [column[0], column[1], column[2], column[3]];
        // {03}.b is {02}.b ^ b.
        column[0] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        column[1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        column[2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        column[3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

/// The multiples of `b` that InvMixColumns needs: `{09}, {0b}, {0d}, {0e}`.
#[inline(always)]
fn inv_multiples(b: u8) -> (u8, u8, u8, u8) {
    let x2 = xtime(b);
    let x4 = xtime(x2);
    let x8 = xtime(x4);
    (x8 ^ b, x8 ^ x2 ^ b, x8 ^ x4 ^ b, x8 ^ x4 ^ x2)
}

/// FIPS 197 section 5.3.3: InvMixColumns.
fn inv_mix_columns(state: &mut State) {
    for column in state.chunks_exact_mut(4) {
        let (s0_9, s0_b, s0_d, s0_e) = inv_multiples(column[0]);
        let (s1_9, s1_b, s1_d, s1_e) = inv_multiples(column[1]);
        let (s2_9, s2_b, s2_d, s2_e) = inv_multiples(column[2]);
        let (s3_9, s3_b, s3_d, s3_e) = inv_multiples(column[3]);
        column[0] = s0_e ^ s1_b ^ s2_d ^ s3_9;
        column[1] = s0_9 ^ s1_e ^ s2_b ^ s3_d;
        column[2] = s0_d ^ s1_9 ^ s2_e ^ s3_b;
        column[3] = s0_b ^ s1_d ^ s2_9 ^ s3_e;
    }
}

/// AddRoundKey (FIPS 197 section 5.1.4): XORs one word of the schedule into each column.
/// It is its own inverse.
fn add_round_key(state: &mut State, round_key: &[u32]) {
    for (column, word) in state.chunks_exact_mut(4).zip(round_key) {
        for (byte, key_byte) in column.iter_mut().zip(word.to_be_bytes()) {
            *byte ^= key_byte;
        }
    }
}

/// The four schedule words of round `round`.
#[inline(always)]
fn round_key(w: &[u32], round: usize) -> &[u32] {
    &w[4 * round..4 * round + 4]
}

/// FIPS 197 section 5.1: Cipher.
pub fn encrypt(state: &mut State, w: &[u32], nr: usize) {
    add_round_key(state, round_key(w, 0));
    for round in 1..nr {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key(w, round));
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key(w, nr));
}

/// FIPS 197 section 5.3: InvCipher.
pub fn decrypt(state: &mut State, w: &[u32], nr: usize) {
    add_round_key(state, round_key(w, nr));
    for round in (1..nr).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_key(w, round));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_key(w, 0));
}
