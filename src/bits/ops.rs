/// Returns the bit at 1-indexed position `pos` of a `width`-bit value, as `0` or `1`.
///
/// Positions count from the left: position 1 is the most significant bit and
/// position `width` is the least significant. Bits of `value` above `width` are
/// ignored.
///
/// # Arguments
///
/// * `value` - Holds the `width`-bit value in its low bits.
/// * `pos` - The position to read, in `1..=width`.
/// * `width` - The size of the value in bits, in `1..=64`.
///
/// # Panics
///
/// Arguments are not validated, and only some invalid ones are caught, by the
/// overflow checks of debug builds:
///
/// * `pos > width` panics.
/// * `pos == 0` panics only if `width` is 64. With a smaller `width` it returns
///   the bit just above the value, without any error.
/// * `width > 64` panics only if `width - pos` is 64 or more.
///
/// Release builds have no overflow checks, so there the result is meaningless
/// for every invalid argument.
///
/// # Examples
///
/// ```
/// use oes::bits::get_bit;
///
/// let value = 0b1000_0010;
///
/// assert_eq!(get_bit(value, 1, 8), 1); // leftmost bit
/// assert_eq!(get_bit(value, 7, 8), 1);
/// assert_eq!(get_bit(value, 8, 8), 0); // rightmost bit
/// ```
#[inline(always)]
pub fn get_bit(value: u64, pos: u64, width: u64) -> u64 {
    (value >> (width - pos)) & 1
}

/// Builds a new value by reading bits of `value` in the order given by `table`.
///
/// Entry `i` of `table` names the input position that supplies bit `i` of the
/// output. Both count from the left and from 1, as in the tables of FIPS 46-3,
/// which can be passed without any conversion. The result has `N` significant
/// bits, right-aligned in the returned `u64`.
///
/// A table doesn't have to use each input bit exactly once. Repeating an entry
/// expands the input and leaving one out compresses it, which is how the DES
/// E expansion and the PC-1 and PC-2 key selections work.
///
/// # Arguments
///
/// * `value` - Holds the input in its low `in_bits` bits. Higher bits are ignored.
/// * `table` - The input positions, each in `1..=in_bits`. `N` must be at most
///   64: with a longer table the bits read first are shifted out of the result.
/// * `in_bits` - The size of the input in bits, in `1..=64`.
///
/// # Panics
///
/// Each table entry is passed to [`get_bit`] and can panic as described there.
/// An invalid entry doesn't always panic, so a new table needs its own test.
///
/// # Examples
///
/// ```
/// use oes::bits::permute;
///
/// // Reorder: swap the two halves of a byte.
/// assert_eq!(permute(0xA5, &[5, 6, 7, 8, 1, 2, 3, 4], 8), 0x5A);
///
/// // Expand: repeat the first bit, to get 5 output bits from 4 input bits.
/// assert_eq!(permute(0b1010, &[1, 1, 2, 3, 4], 4), 0b11010);
///
/// // Compress: keep only the two outer bits.
/// assert_eq!(permute(0b1001, &[1, 4], 4), 0b11);
/// ```
#[inline(always)]
pub fn permute<const N: usize>(value: u64, table: &[u64; N], in_bits: u64) -> u64 {
    let mut out: u64 = 0;
    for &pos in table {
        out = (out << 1) | get_bit(value, pos, in_bits)
    }
    out
}

/// Rotates a 28-bit `value` left by `shift` bits.
///
/// Bits leaving the top of the 28-bit value come back in at the bottom. DES uses
/// this to rotate the C and D halves of its key schedule (FIPS 46-3, the "Key
/// Schedule Calculation" appendix section).
///
/// # Arguments
///
/// * `value` - The value to rotate, which must fit in 28 bits. Higher bits are not
///   ignored: they rotate into the result and make it meaningless.
/// * `shift` - The number of positions to rotate by, in `0..=28`. Both 0 and 28
///   return `value` unchanged.
///
/// # Panics
///
/// In debug builds, panics if `shift > 28`. Release builds don't check, and the
/// result is meaningless.
///
/// # Examples
///
/// ```
/// use oes::bits::rotl28;
///
/// // Bit 27, the top one, wraps around to bit 0.
/// assert_eq!(rotl28(0x800_0001, 1), 0x000_0003);
/// ```
#[inline(always)]
pub fn rotl28(value: u32, shift: u32) -> u32 {
    (value << shift | value >> (28 - shift)) & 0x0FFF_FFFF
}

/// Swaps each bit of `value` selected by `mask` with the bit `delta` places above it.
///
/// For every set bit of `mask` at shift `s`, bits `s` and `s + delta` of `value`
/// trade places, and all other bits stay put. All pairs move at once, in six
/// operations, so a fixed permutation such as the DES initial permutation can be
/// done as a short series of these swaps instead of one bit at a time.
///
/// Unlike the other helpers in this module, it counts bits from the right,
/// starting at 0, as Rust's shift operators do.
///
/// # Arguments
///
/// * `value` - The 64-bit value whose bits are swapped.
/// * `delta` - The distance between the two bits of each pair, in `1..64`.
/// * `mask` - The lower bit of each pair. The pairs must not overlap, so no bit
///   may be set in both `mask` and `mask << delta`, and `mask << delta` must not
///   lose bits off the top. This isn't checked: otherwise the result is not a
///   rearrangement of `value`.
///
/// # Panics
///
/// In debug builds, panics if `delta` is 64 or more. Release builds don't check,
/// and the result is meaningless.
///
/// # Examples
///
/// ```
/// use oes::bits::delta_swap;
///
/// // Swap the two halves of a byte: the mask picks the low half, and each of its
/// // bits trades places with the bit 4 above it.
/// assert_eq!(delta_swap(0x3C, 4, 0x0F), 0xC3);
/// ```
#[inline(always)]
pub fn delta_swap(value: u64, delta: u32, mask: u64) -> u64 {
    // Where the two bits of a pair differ, flipping both swaps them.
    let differ = (value ^ (value >> delta)) & mask;
    value ^ differ ^ (differ << delta)
}
