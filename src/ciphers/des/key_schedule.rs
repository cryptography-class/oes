use super::tables::{PC_1, PC_2, SHIFTS};
use crate::bits::{permute, rotl28};

/// Derives the 16 round keys from a DES key (FIPS 46-3, Key Schedule Calculation).
///
/// PC-1 drops the 8 parity bits and leaves two 28-bit halves, C and D. Each round
/// rotates both halves left and uses PC-2 to select 48 of their 56 bits as that
/// round's key, right-aligned in the `u64`.
pub(super) fn generate_round_keys(key: &[u8; 8]) -> [u64; 16] {
    let mut round_keys = [0u64; 16];

    let key = u64::from_be_bytes(*key);

    let pc1_total = permute(key, &PC_1, 64);

    let mut left = ((pc1_total >> 28) & 0x0FFF_FFFF) as u32;
    let mut right = (pc1_total & 0x0FFF_FFFF) as u32;

    for (round, round_key) in round_keys.iter_mut().enumerate() {
        let shift = SHIFTS[round] as u32;

        left = rotl28(left, shift);
        right = rotl28(right, shift);

        let combined = ((left as u64) << 28) | (right as u64);

        *round_key = permute(combined, &PC_2, 56);
    }

    round_keys
}

/// Splits a 48-bit round key into the two words that `round::mix_key` XORs in.
///
/// The key's eight 6-bit groups, numbered 0 to 7 from the left, are the S-box
/// inputs' key parts. The first word holds groups 0, 2, 4 and 6 and the second
/// groups 1, 3, 5 and 7, each group in the low 6 bits of its own byte, from the
/// top byte down. The top 2 bits of each byte are zero.
pub(super) fn split_round_key(round_key: u64) -> [u32; 2] {
    let group = |j: u32| ((round_key >> (42 - 6 * j)) & 0x3F) as u32;
    [
        group(0) << 24 | group(2) << 16 | group(4) << 8 | group(6),
        group(1) << 24 | group(3) << 16 | group(5) << 8 | group(7),
    ]
}
