use super::tables::SHIFTS;
use crate::bits::{delta_swap, rotl28};

/// Derives the 16 round keys from a DES key (FIPS 46-3, Key Schedule Calculation).
///
/// PC-1 drops the 8 parity bits and leaves two 28-bit halves, C and D. Each round
/// rotates both halves left and uses PC-2 to select 48 of their 56 bits as that
/// round's key, right-aligned in the `u64`.
pub(super) fn generate_round_keys(key: &[u8; 8]) -> [u64; 16] {
    let mut round_keys = [0u64; 16];

    let pc1_total = pc1(u64::from_be_bytes(*key));

    let mut left = ((pc1_total >> 28) & 0x0FFF_FFFF) as u32;
    let mut right = (pc1_total & 0x0FFF_FFFF) as u32;

    for (round, round_key) in round_keys.iter_mut().enumerate() {
        let shift = SHIFTS[round] as u32;

        left = rotl28(left, shift);
        right = rotl28(right, shift);

        let combined = ((left as u64) << 28) | (right as u64);

        *round_key = pc2(combined);
    }

    round_keys
}

/// Applies the permuted choice PC-1 of FIPS 46-3 to a key, returning C and D as
/// one 56-bit value, right-aligned.
///
/// Eight delta swaps move the 56 key bits into PC-1's order at the top of the
/// word, and the shift drops the parity bits left at the bottom. The swaps are
/// those of the RustCrypto `des` crate, version 0.9 (MIT or Apache-2.0).
pub(super) fn pc1(key: u64) -> u64 {
    let mut key = delta_swap(key, 2, 0x3333_0000_3333_0000);
    key = delta_swap(key, 4, 0x0F0F_0F0F_0000_0000);
    key = delta_swap(key, 8, 0x009A_000A_00A2_00A8);
    key = delta_swap(key, 16, 0x0000_6C6C_0000_CCCC);
    key = delta_swap(key, 1, 0x1045_5005_0055_0550);
    key = delta_swap(key, 32, 0x0000_0000_F0F0_F5FA);
    key = delta_swap(key, 8, 0x0055_0055_006A_00AA);
    key = delta_swap(key, 2, 0x0000_3333_3000_0300);
    key >> 8
}

/// Applies the permuted choice PC-2 of FIPS 46-3 to C and D, given as one 56-bit
/// value, right-aligned, and returns the 48-bit round key, right-aligned.
///
/// PC-2 drops 8 bits and scatters the rest, so it isn't a series of swaps. Each
/// term below selects a few bits with a mask and moves them into place. A shift
/// moves bits by the same distance, and a multiplication moves several bits by
/// different distances at once: multiplying by a constant adds one shifted copy of
/// the selected bits per set bit of the constant, and the last mask keeps the
/// copies that land in the right places. In two terms some copies overlap, which
/// makes the addition carry, but only above every bit the last mask keeps, so the
/// result is the same as with XOR and the function only moves bits.
///
/// The terms are those of the RustCrypto `des` crate, version 0.9 (MIT or
/// Apache-2.0). They work on the 56 bits at the top of the word and leave the
/// result at the top, hence the shifts on the way in and out.
pub(super) fn pc2(cd: u64) -> u64 {
    let key = (cd << 8).rotate_left(61);
    let b1 = (key & 0x0021_0000_0200_0000) >> 7;
    let b2 = (key & 0x0008_0200_1008_0000) << 1;
    let b3 = key & 0x0002_2000_0000_0000;
    let b4 = (key & 0x0000_0000_0010_0020) << 19;
    let b5 = (key.rotate_left(54) & 0x0005_3124_0000_0011).wrapping_mul(0x0000_0000_9420_0201)
        & 0xEA40_1008_8000_0000;
    let b6 = (key.rotate_left(7) & 0x0022_1100_0001_2001).wrapping_mul(0x0001_0000_0061_0006)
        & 0x1185_0044_0000_0000;
    let b7 = (key.rotate_left(6) & 0x0000_5200_4020_0002).wrapping_mul(0x0000_0080_0000_00C1)
        & 0x0028_8110_0020_0000;
    let b8 =
        (key & 0x0100_0004_C001_1100).wrapping_mul(0x0000_0000_0000_4284) & 0x0400_0822_4440_0000;
    let b9 = (key.rotate_left(60) & 0x0000_0000_0082_0280).wrapping_mul(0x0000_0000_0008_9001)
        & 0x0000_0001_1088_0000;
    let b10 = (key.rotate_left(49) & 0x0000_0000_0002_4084).wrapping_mul(0x0000_0000_0204_0005)
        & 0x0000_0000_0A03_0000;
    (b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | b9 | b10) >> 16
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
