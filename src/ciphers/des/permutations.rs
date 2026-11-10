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
