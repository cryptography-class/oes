use super::sample;
use crate::modes::ghash::{Ghash, gf_mul};
use crate::modes::vpclmul::Vpclmul;

// ---- Ghash::new ----

/// A detection bug would only make GCM slower, so no other test would notice it.
#[test]
fn new_selects_vpclmulqdq_exactly_when_the_processor_has_it() {
    let available = is_x86_feature_detected!("pclmulqdq")
        && is_x86_feature_detected!("ssse3")
        && is_x86_feature_detected!("avx2")
        && is_x86_feature_detected!("vpclmulqdq");
    assert_eq!(Ghash::new(&[0; 16]).vpclmul.is_some(), available);
}

// ---- absorb_groups ----

/// Covers fewer blocks than a group, which come straight back, and one to three
/// groups of eight with every count of blocks left over. The starting `y` is nonzero,
/// so it has to go into the first block of a group. Passes without checking anything
/// on a processor that lacks the instruction.
#[test]
fn absorb_groups_matches_textbook_across_lengths() {
    let Some(vpclmul) = Vpclmul::detect() else {
        return;
    };
    // Any nonzero values work. These are `H` and the ciphertext of test case 2 in
    // McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)".
    let h = 0x66E9_4BD4_EF8A_2C3B_884C_FA59_CA34_2B2E;
    let start = 0x0388_DACE_60B6_A392_F328_C2B9_71B2_FE78;
    let data = sample(25 * 16);

    for count in 0..=25 {
        let blocks = &data[..count * 16];
        let consumed = count / 8 * 8;
        let mut expected = start;
        for block in blocks[..consumed * 16].chunks_exact(16) {
            let x = u128::from_be_bytes(block.try_into().unwrap());
            expected = gf_mul(expected ^ x, h);
        }
        let (y, rest) = vpclmul.absorb_groups(start, h, blocks);
        assert_eq!(y, expected, "{count} blocks");
        assert_eq!(rest, &blocks[consumed * 16..], "{count} blocks");
    }
}
