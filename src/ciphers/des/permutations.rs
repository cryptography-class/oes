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
