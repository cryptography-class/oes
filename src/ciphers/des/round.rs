use crate::bits::permute;
use crate::ciphers::des::tables::{
    E_BOX_EXPANSION, FINAL_PERM, INITIAL_PERM, P_BOX_PERM, SBOX_1, SBOX_2, SBOX_3, SBOX_4, SBOX_5,
    SBOX_6, SBOX_7, SBOX_8,
};

/// Computes the cipher function f of FIPS 46-3 for one round.
///
/// Expands the 32-bit half to 48 bits, XORs in the round key, substitutes each
/// 6-bit group through its S-box to get 32 bits, then applies the P permutation.
#[inline]
pub(super) fn feistel(right: u32, round_key: u64) -> u32 {
    let expanded = permute(right as u64, &E_BOX_EXPANSION, 32);
    let mixed = expanded ^ round_key;

    let s_boxes = [
        &SBOX_1, &SBOX_2, &SBOX_3, &SBOX_4, &SBOX_5, &SBOX_6, &SBOX_7, &SBOX_8,
    ];

    let mut substituted = 0u32;

    for (i, sbox) in s_boxes.iter().enumerate() {
        // S1 takes the leftmost 6 of the 48 bits, S2 the next 6, and so on.
        let shift = 42 - (i * 6);
        let chunk = ((mixed >> shift) & 0x3F) as usize;

        // The outer two bits pick the row and the middle four pick the column.
        let row = ((chunk & 0x20) >> 4) | (chunk & 1);
        let col = (chunk >> 1) & 0x0F;

        let value = sbox[row][col] as u32;

        substituted = (substituted << 4) | value;
    }

    permute(substituted as u64, &P_BOX_PERM, 32) as u32
}

/// Encrypts or decrypts one block in place: IP, 16 Feistel rounds, then IP^-1.
///
/// Decryption is the same process with the round keys in reverse order, which is
/// what the Feistel structure allows.
pub(super) fn crypt(block: &mut u64, round_keys: &[u64; 16], decrypt: bool) {
    let value = permute(*block, &INITIAL_PERM, 64);

    let mut left = (value >> 32) as u32;
    let mut right = value as u32;

    for round in 0..16 {
        let key_index = if decrypt { 15 - round } else { round };

        let next_left = right;
        let next_right = left ^ feistel(right, round_keys[key_index]);

        left = next_left;
        right = next_right;
    }

    // The specification doesn't swap after the last round, so undo the loop's swap.
    let preoutput = ((right as u64) << 32) | (left as u64);

    *block = permute(preoutput, &FINAL_PERM, 64);
}
