use super::DesCipher;
use super::permutations::expand;
use super::tables::E_BOX_EXPANSION;
use crate::bits::permute;
use crate::ciphers::traits::{BlockCipher, KeyInit};

#[test]
fn des_encrypt_known_vector() {
    let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

    let plaintext = 0x0123456789ABCDEF_u64;
    let expected = 0x85E813540F0AB405_u64;

    let cipher = DesCipher::new(&key);

    let mut block = plaintext;
    cipher.encrypt_block(&mut block);

    assert_eq!(block, expected);
}

#[test]
fn des_decrypt_known_vector() {
    let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

    let ciphertext = 0x85E813540F0AB405_u64;
    let expected = 0x0123456789ABCDEF_u64;

    let cipher = DesCipher::new(&key);

    let mut block = ciphertext;
    cipher.decrypt_block(&mut block);

    assert_eq!(block, expected);
}

// ---- expand ----

// Both E and `expand` only move bits around, so each is linear over XOR: the
// output for any input is the XOR of the outputs for its set bits. Matching on
// zero and on every single-bit input therefore covers all 2^32 inputs.
#[test]
fn expand_matches_the_e_table_for_each_input_bit() {
    assert_eq!(expand(0), 0);
    for bit in 0..32 {
        let right = 1u32 << bit;
        let expected = permute(u64::from(right), &E_BOX_EXPANSION, 32);
        assert_eq!(expand(right), expected, "input bit {bit}");
    }
}
