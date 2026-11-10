use crate::ciphers::des::permutations::{expand, final_permutation, initial_permutation};
use crate::ciphers::des::sp_tables::SP_TABLES;

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
/// The order of `round_keys` alone decides the direction. Decryption is the same
/// process with the keys reversed, which is what the Feistel structure allows.
pub(super) fn crypt(block: &mut u64, round_keys: &[u64; 16]) {
    let value = initial_permutation(*block);

    let mut left = (value >> 32) as u32;
    let mut right = value as u32;

    // Each round sets L(i) = R(i-1) and R(i) = L(i-1) ^ f(R(i-1), K(i)). Instead
    // of swapping the halves after every round, each step runs two rounds and lets
    // the variables trade roles: the first line leaves R(i) in `left` while `right`
    // still holds R(i-1), which is L(i). The second line then computes R(i+1) into
    // `right`, so after each step `left` and `right` are back to L and R.
    for keys in round_keys.chunks_exact(2) {
        left ^= feistel(right, keys[0]);
        right ^= feistel(left, keys[1]);
    }

    // The specification doesn't swap the halves after the last round, so the
    // preoutput is R16 followed by L16.
    let preoutput = ((right as u64) << 32) | (left as u64);

    *block = final_permutation(preoutput);
}
