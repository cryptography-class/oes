use super::sample;
use crate::modes::ghash::{Ghash, gf_mul};
use crate::modes::pclmul::Pclmul;

// ---- Ghash::new ----

/// A detection bug would only make GCM slower, so no other test would notice it.
#[test]
fn new_selects_pclmulqdq_exactly_when_the_processor_has_it() {
    let available = is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("ssse3");
    assert_eq!(Ghash::new(&[0; 16]).pclmul.is_some(), available);
}

// ---- absorb ----

/// Both multiplications are linear in each argument, so agreeing on every pair of
/// single-bit blocks means agreeing on all inputs. Passes without checking anything on
/// a processor that lacks the instruction.
#[test]
fn absorb_matches_textbook_on_every_pair_of_basis_blocks() {
    let Some(pclmul) = Pclmul::detect() else {
        return;
    };
    for i in 0..128 {
        for j in 0..128 {
            let (x, h) = (1u128 << i, 1u128 << j);
            let product = pclmul.absorb(0, h, &x.to_be_bytes());
            assert_eq!(product, gf_mul(x, h), "bit {i} of x, bit {j} of h");
        }
    }
}

/// Covers one and two groups of four blocks, with every count of blocks left over,
/// and a nonzero starting `y`, which has to go into the first block of a group.
#[test]
fn absorb_matches_textbook_across_lengths() {
    let Some(pclmul) = Pclmul::detect() else {
        return;
    };
    // Any nonzero values work. These are `H` and the ciphertext of test case 2 in
    // McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)".
    let h = 0x66E9_4BD4_EF8A_2C3B_884C_FA59_CA34_2B2E;
    let start = 0x0388_DACE_60B6_A392_F328_C2B9_71B2_FE78;
    let data = sample(9 * 16);

    for count in 0..=9 {
        let blocks = &data[..count * 16];
        let mut expected = start;
        for block in blocks.chunks_exact(16) {
            let x = u128::from_be_bytes(block.try_into().unwrap());
            expected = gf_mul(expected ^ x, h);
        }
        assert_eq!(pclmul.absorb(start, h, blocks), expected, "{count} blocks");
    }
}
