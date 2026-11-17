use crate::modes::ghash::Ghash;

// ---- Ghash ----

/// Test case 2 of McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)",
/// Appendix B: the hash subkey `H`, a one-block ciphertext, and its GHASH.
#[test]
fn ghash_known_answer_gcm_specification_case_2() {
    let h = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e_u128.to_be_bytes();
    let ciphertext = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78_u128.to_be_bytes();
    let expected = 0xf38c_bb1a_d692_23dc_c345_7ae5_b6b0_f885_u128.to_be_bytes();

    let mut ghash = Ghash::new(&h);
    ghash.update(&ciphertext);
    assert_eq!(ghash.finish(0, 16), expected);
}
