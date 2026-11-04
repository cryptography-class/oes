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
