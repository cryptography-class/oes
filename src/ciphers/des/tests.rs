use super::DesCipher;
use super::key_schedule::{generate_round_keys, pc1, pc2, split_round_key};
use super::permutations::{final_permutation, initial_permutation};
use super::round::mix_key;
use super::sp_tables::SP_TABLES;
use super::tables::{
    E_BOX_EXPANSION, FINAL_PERM, INITIAL_PERM, P_BOX_PERM, PC_1, PC_2, SBOX_1, SBOX_2, SBOX_3,
    SBOX_4, SBOX_5, SBOX_6, SBOX_7, SBOX_8,
};
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

// ---- generate_round_keys ----

// J. Orlin Grabbe, "The DES Algorithm Illustrated": key 133457799BBCDFF1 gives
// K1 = 000110 110000 001011 101111 111111 000111 000001 110010 and
// K16 = 110010 110011 110110 001011 000011 100001 011111 110101.
#[test]
fn generate_round_keys_known_answer_grabbe() {
    let keys = generate_round_keys(&[0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]);
    assert_eq!(keys[0], 0x1B02_EFFC_7072);
    assert_eq!(keys[15], 0xCB3D_8B0E_17F5);
}

// The permutation tests below rely on linearity. A permutation table and its fast
// version only move bits around, so each is linear over XOR: the output for any
// input is the XOR of the outputs for its set bits. Matching on zero and on every
// single-bit input therefore covers every possible input.

// ---- pc1 ----

#[test]
fn pc1_matches_the_pc1_table_for_each_input_bit() {
    assert_eq!(pc1(0), 0);
    for bit in 0..64 {
        let key = 1u64 << bit;
        assert_eq!(pc1(key), permute(key, &PC_1, 64), "input bit {bit}");
    }
}

// ---- pc2 ----

#[test]
fn pc2_matches_the_pc2_table_for_each_input_bit() {
    assert_eq!(pc2(0), 0);
    for bit in 0..56 {
        let cd = 1u64 << bit;
        assert_eq!(pc2(cd), permute(cd, &PC_2, 56), "input bit {bit}");
    }
}

// `pc2` multiplies, which only moves bits like a permutation as long as its
// additions never carry into the bits it keeps. A carry needs at least two set
// input bits, so every pair of bits is checked too.
#[test]
fn pc2_matches_the_pc2_table_for_each_pair_of_input_bits() {
    for high in 1..56 {
        for low in 0..high {
            let cd = (1u64 << high) | (1u64 << low);
            assert_eq!(
                pc2(cd),
                permute(cd, &PC_2, 56),
                "input bits {high} and {low}"
            );
        }
    }
}

// ---- initial_permutation ----

#[test]
fn initial_permutation_matches_the_ip_table_for_each_input_bit() {
    assert_eq!(initial_permutation(0), 0);
    for bit in 0..64 {
        let block = 1u64 << bit;
        let expected = permute(block, &INITIAL_PERM, 64);
        assert_eq!(initial_permutation(block), expected, "input bit {bit}");
    }
}

// ---- final_permutation ----

#[test]
fn final_permutation_matches_the_fp_table_for_each_input_bit() {
    assert_eq!(final_permutation(0), 0);
    for bit in 0..64 {
        let block = 1u64 << bit;
        let expected = permute(block, &FINAL_PERM, 64);
        assert_eq!(final_permutation(block), expected, "input bit {bit}");
    }
}

// ---- mix_key and split_round_key ----

/// Returns the eight 6-bit S-box inputs held in `mix_key`'s two words, S1's first.
fn groups_of_words([even, odd]: [u32; 2]) -> [u64; 8] {
    let byte = |word: u32, n: u32| u64::from((word >> (8 * n)) & 0x3F);
    [
        byte(even, 3),
        byte(odd, 3),
        byte(even, 2),
        byte(odd, 2),
        byte(even, 1),
        byte(odd, 1),
        byte(even, 0),
        byte(odd, 0),
    ]
}

/// Returns the eight 6-bit groups of a 48-bit value, the leftmost first.
fn groups_of_48_bits(value: u64) -> [u64; 8] {
    std::array::from_fn(|j| (value >> (42 - 6 * j)) & 0x3F)
}

// Both sides are linear in the half and the key together, so zero, every single
// bit of the half with a zero key, and every single bit of the key with a zero half
// cover all inputs.
#[test]
fn mix_key_matches_the_e_table_xor_the_round_key_for_each_input_bit() {
    let check = |right: u32, key: u64| {
        let expected = permute(u64::from(right), &E_BOX_EXPANSION, 32) ^ key;
        let mixed = mix_key(right, split_round_key(key));
        assert_eq!(
            groups_of_words(mixed),
            groups_of_48_bits(expected),
            "half {right:#010x}, key {key:#014x}"
        );
    };
    check(0, 0);
    for bit in 0..32 {
        check(1 << bit, 0);
    }
    for bit in 0..48 {
        check(0, 1 << bit);
    }
}

// ---- SP_TABLES ----

#[test]
fn sp_tables_match_each_s_box_followed_by_p() {
    let s_boxes = [
        &SBOX_1, &SBOX_2, &SBOX_3, &SBOX_4, &SBOX_5, &SBOX_6, &SBOX_7, &SBOX_8,
    ];
    for (i, (s_box, table)) in s_boxes.iter().zip(&SP_TABLES).enumerate() {
        for (x, &entry) in table.iter().enumerate() {
            let row = ((x >> 4) & 0b10) | (x & 1);
            let col = (x >> 1) & 0xF;
            let placed = s_box[row][col] << (28 - 4 * i);
            let expected = permute(placed, &P_BOX_PERM, 32) as u32;
            assert_eq!(entry, expected, "S{}, input {x:06b}", i + 1);
        }
    }
}
