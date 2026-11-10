use crate::ciphers::des::permutations::{final_permutation, initial_permutation};
use crate::ciphers::des::sp_tables::SP_TABLES;

/// Computes the expansion E of a 32-bit half XORed with a round key, as the eight
/// 6-bit S-box inputs of FIPS 46-3, without building the 48-bit value.
///
/// E's output group `j` (0 to 7, from the left) is the six consecutive bits `4j` to
/// `4j + 5` of `right`, where bit 0 stands for bit 32. Rotating `right` right by
/// `27 - 4j` would bring that group to the bottom. One rotation lines up four
/// groups at once, one per byte, because the rotations they need differ by 8:
///
/// ```text
/// word   rotation          byte 3    byte 2    byte 1    byte 0
/// even   right by 3        group 0   group 2   group 4   group 6
/// odd    left by 1         group 1   group 3   group 5   group 7
/// ```
///
/// The low 6 bits of each byte then hold one group, and `round_key`, split the
/// same way by `key_schedule::split_round_key`, is XORed in. The top 2 bits of
/// each byte hold other bits of `right`, which the caller masks off.
#[inline(always)]
pub(super) fn mix_key(right: u32, round_key: [u32; 2]) -> [u32; 2] {
    [
        right.rotate_right(3) ^ round_key[0],
        right.rotate_left(1) ^ round_key[1],
    ]
}

/// Computes the cipher function f of FIPS 46-3 for one round.
///
/// [`mix_key`] gives the eight S-box inputs, two words of four bytes. Each input
/// then goes through its S-box and the permutation P in a single lookup in
/// [`SP_TABLES`], and the eight results are ORed together.
#[inline]
pub(super) fn feistel(right: u32, round_key: [u32; 2]) -> u32 {
    let [even, odd] = mix_key(right, round_key);
    let group = |word: u32, byte: u32| ((word >> (8 * byte)) & 0x3F) as usize;

    SP_TABLES[0][group(even, 3)]
        | SP_TABLES[1][group(odd, 3)]
        | SP_TABLES[2][group(even, 2)]
        | SP_TABLES[3][group(odd, 2)]
        | SP_TABLES[4][group(even, 1)]
        | SP_TABLES[5][group(odd, 1)]
        | SP_TABLES[6][group(even, 0)]
        | SP_TABLES[7][group(odd, 0)]
}

/// Encrypts or decrypts `N` independent blocks in place: IP, 16 Feistel rounds,
/// then IP^-1, on each block.
///
/// The order of `round_keys` alone decides the direction. Decryption is the same
/// process with the keys reversed, which is what the Feistel structure allows.
/// Each key is split as `key_schedule::split_round_key` does.
///
/// Every block goes through exactly the steps of FIPS 46-3, so the result is the
/// same as running the blocks one at a time.
pub(super) fn crypt_n<const N: usize>(blocks: &mut [u64; N], round_keys: &[[u32; 2]; 16]) {
    let mut left = [0u32; N];
    let mut right = [0u32; N];
    for (j, block) in blocks.iter().enumerate() {
        let value = initial_permutation(*block);
        left[j] = (value >> 32) as u32;
        right[j] = value as u32;
    }

    // Each round sets L(i) = R(i-1) and R(i) = L(i-1) ^ f(R(i-1), K(i)). Instead
    // of swapping the halves after every round, each step runs two rounds and lets
    // the variables trade roles: the first loop leaves R(i) in `left` while `right`
    // still holds R(i-1), which is L(i). The second loop then computes R(i+1) into
    // `right`, so after each step `left` and `right` are back to L and R.
    //
    // A round runs over all N blocks before the next round starts. The blocks
    // don't depend on each other, so the processor can overlap their table
    // lookups instead of waiting for each one in turn.
    for keys in round_keys.chunks_exact(2) {
        for j in 0..N {
            left[j] ^= feistel(right[j], keys[0]);
        }
        for j in 0..N {
            right[j] ^= feistel(left[j], keys[1]);
        }
    }

    // The specification doesn't swap the halves after the last round, so the
    // preoutput is R16 followed by L16.
    for (j, block) in blocks.iter_mut().enumerate() {
        let preoutput = ((right[j] as u64) << 32) | (left[j] as u64);
        *block = final_permutation(preoutput);
    }
}
