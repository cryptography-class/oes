use crate::modes::ghash::{Ghash, gf_mul};
use crate::modes::pclmul::Pclmul;

// ---- Ghash::new ----

/// A detection bug would only make GCM slower, so no other test would notice it.
#[test]
fn new_selects_pclmulqdq_exactly_when_the_processor_has_it() {
    let available = is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("sse2");
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
