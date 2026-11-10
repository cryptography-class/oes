use super::tables::{P_BOX_PERM, SBOX_1, SBOX_2, SBOX_3, SBOX_4, SBOX_5, SBOX_6, SBOX_7, SBOX_8};

/// The eight S-boxes of FIPS 46-3, each merged with the permutation P that follows
/// them, indexed `[box][input]` with boxes numbered from 0.
///
/// Entry `[i][x]` is what the cipher function f outputs when S-box `i + 1` gets the
/// 6-bit input `x` and every other S-box outputs zero: the S-box value placed in its
/// 4-bit slot, then permuted by P. P only moves bits, so applying it to all eight
/// S-box outputs at once gives the same result as ORing the eight entries together.
/// An entry is indexed by the raw 6-bit input, so the split into row and column
/// happens here, once, when the tables are built at compile time.
///
/// The lookups use positions that depend on the key and the data. The original
/// S-box lookups had the same property, and it means DES here doesn't run in
/// constant time.
pub(super) static SP_TABLES: [[u32; 64]; 8] = build();

/// Builds [`SP_TABLES`] from the S-boxes and P in `tables`.
const fn build() -> [[u32; 64]; 8] {
    let s_boxes = [
        &SBOX_1, &SBOX_2, &SBOX_3, &SBOX_4, &SBOX_5, &SBOX_6, &SBOX_7, &SBOX_8,
    ];
    let mut tables = [[0; 64]; 8];

    let mut i = 0;
    while i < 8 {
        let mut x = 0;
        while x < 64 {
            // The outer two bits pick the row and the middle four pick the column.
            let value = s_boxes[i][((x & 0x20) >> 4) | (x & 1)][(x >> 1) & 0x0F];
            // S1 fills the leftmost 4 of the 32 bits, S2 the next 4, and so on.
            tables[i][x] = apply_p(value << (28 - 4 * i));
            x += 1;
        }
        i += 1;
    }
    tables
}

/// Applies the permutation P to a 32-bit value, reading `P_BOX_PERM` one bit at a
/// time. A `const fn` version of `bits::permute`, which can't run at compile time.
const fn apply_p(value: u64) -> u32 {
    let mut out = 0;
    let mut i = 0;
    while i < 32 {
        out = (out << 1) | ((value >> (32 - P_BOX_PERM[i])) & 1);
        i += 1;
    }
    out as u32
}
