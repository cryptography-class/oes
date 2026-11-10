use crate::bits::permute;
use crate::ciphers::des::permutations::expand;
use crate::ciphers::des::sp_tables::SP_TABLES;
use crate::ciphers::des::tables::{FINAL_PERM, INITIAL_PERM};

/// Computes the cipher function f of FIPS 46-3 for one round.
///
/// Expands the 32-bit half to 48 bits and XORs in the round key. Each 6-bit group
/// then goes through its S-box and the permutation P in a single lookup in
/// [`SP_TABLES`], and the eight results are ORed together.
#[inline]
pub(super) fn feistel(right: u32, round_key: u64) -> u32 {
    let mixed = expand(right) ^ round_key;

    let mut output = 0;
    for (i, table) in SP_TABLES.iter().enumerate() {
        // S1 takes the leftmost 6 of the 48 bits, S2 the next 6, and so on.
        output |= table[((mixed >> (42 - 6 * i)) & 0x3F) as usize];
    }
    output
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
