use crate::bits::delta_swap;

/// Applies the initial permutation IP of FIPS 46-3 to a block.
///
/// Laid out as an 8 × 8 grid with one input byte per row, IP is a regular
/// rearrangement. Each output byte collects the same bit position from all eight
/// input bytes, last byte first: output byte 1 takes bit 2 of every byte, then
/// come bits 4, 6 and 8, then 1, 3, 5 and 7. That is a transpose of the grid
/// followed by a reordering of its rows, and five delta swaps do it. The first
/// three, with distances 9, 18 and 36, swap 1-, 2- and then 4-bit squares across
/// the anti-diagonal, which mirrors the grid along that diagonal, so the last
/// byte's bits come first. The two with distance 24 then move whole bytes into
/// IP's row order. This is the sequence used by the RustCrypto `des` crate.
#[inline(always)]
pub(super) fn initial_permutation(block: u64) -> u64 {
    let mut block = delta_swap(block, 9, 0x0055_0055_0055_0055);
    block = delta_swap(block, 18, 0x0000_3333_0000_3333);
    block = delta_swap(block, 36, 0x0000_0000_0F0F_0F0F);
    block = delta_swap(block, 24, 0x0000_0000_FF00_FF00);
    delta_swap(block, 24, 0x0000_00FF_0000_00FF)
}

/// Applies the final permutation IP^-1 of FIPS 46-3 to a block.
///
/// A delta swap undoes itself, so this is [`initial_permutation`]'s five swaps in
/// reverse order.
#[inline(always)]
pub(super) fn final_permutation(block: u64) -> u64 {
    let mut block = delta_swap(block, 24, 0x0000_00FF_0000_00FF);
    block = delta_swap(block, 24, 0x0000_0000_FF00_FF00);
    block = delta_swap(block, 36, 0x0000_0000_0F0F_0F0F);
    block = delta_swap(block, 18, 0x0000_3333_0000_3333);
    delta_swap(block, 9, 0x0055_0055_0055_0055)
}

/// Computes the expansion E of FIPS 46-3, widening a 32-bit half to 48 bits.
///
/// E splits the half into eight 4-bit groups and widens each one to 6 bits with
/// the bit on either side, wrapping around at the ends. Output group `j` (0 to 7,
/// from the left) is therefore the six consecutive input bits `4j` to `4j + 5`,
/// where bit 0 stands for bit 32. Rotating right by `27 - 4j` brings those six
/// bits to the bottom, where a mask keeps them:
///
/// ```text
/// group   row of the E table     rotate right by
///   0     32  1  2  3  4  5      27
///   1      4  5  6  7  8  9      23
///   2      8  9 10 11 12 13      19
///   3     12 13 14 15 16 17      15
///   4     16 17 18 19 20 21      11
///   5     20 21 22 23 24 25       7
///   6     24 25 26 27 28 29       3
///   7     28 29 30 31 32  1      31 (left by 1)
/// ```
///
/// This gives the same 48 bits as reading the table one bit at a time, with
/// eight rotations in place of 48 single-bit reads.
#[inline(always)]
pub(super) fn expand(right: u32) -> u64 {
    let mut expanded = 0;
    for group in 0..8 {
        // Group 7's rotation of -1 wraps around to a right rotation by 31.
        let bits = right.rotate_right((27 + 32 - 4 * group) % 32) & 0x3F;
        expanded |= u64::from(bits) << (42 - 6 * group);
    }
    expanded
}
