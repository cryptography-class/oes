use super::errors::ModeError;
use super::{BlockMode, Cbc, Ctr, Ecb};
use crate::ciphers::des::DesCipher;
use crate::ciphers::traits::KeyInit;

// Tables B1 (ECB) and C1 (CBC) of FIPS 81, DES Modes of Operation.
const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
const IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
const PLAINTEXT: &[u8; 24] = b"Now is the time for all ";
const ECB_CIPHERTEXT: [u8; 24] = [
    0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15, //
    0x6A, 0x27, 0x17, 0x87, 0xAB, 0x88, 0x83, 0xF9, //
    0x89, 0x3D, 0x51, 0xEC, 0x4B, 0x56, 0x3B, 0x53,
];
const CBC_CIPHERTEXT: [u8; 24] = [
    0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C, //
    0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F, //
    0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6,
];

const BLOCK: usize = 8;

fn des() -> DesCipher {
    DesCipher::new(&KEY)
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(131) ^ (i >> 5)) as u8).collect()
}

// ---- Ecb ----

#[test]
fn ecb_known_answer_fips_81() {
    let ecb = Ecb::new(des());
    let mut data = *PLAINTEXT;
    ecb.encrypt(&mut data).unwrap();
    assert_eq!(data, ECB_CIPHERTEXT);
    ecb.decrypt(&mut data).unwrap();
    assert_eq!(&data, PLAINTEXT);
}

#[test]
fn ecb_roundtrips_empty_and_single_block_input() {
    for blocks in [0, 1] {
        let plaintext = sample(blocks * BLOCK);
        let ecb = Ecb::new(des());
        let mut buffer = plaintext.clone();
        ecb.encrypt(&mut buffer).unwrap();
        ecb.decrypt(&mut buffer).unwrap();
        assert_eq!(buffer, plaintext, "{blocks} blocks");
    }
}

#[test]
fn ecb_rejects_unaligned_input_and_keeps_the_data() {
    let expected = Err(ModeError::InvalidLength { len: 9, block_size: BLOCK });
    let ecb = Ecb::new(des());
    let mut data = [7; 9];
    assert_eq!(ecb.encrypt(&mut data), expected);
    assert_eq!(ecb.decrypt(&mut data), expected);
    assert_eq!(data, [7; 9]);
}

// ---- Cbc ----

#[test]
fn cbc_known_answer_fips_81() {
    let mut data = *PLAINTEXT;
    Cbc::new(des(), &IV).unwrap().encrypt(&mut data).unwrap();
    assert_eq!(data, CBC_CIPHERTEXT);
    Cbc::new(des(), &IV).unwrap().decrypt(&mut data).unwrap();
    assert_eq!(&data, PLAINTEXT);
}

#[test]
fn cbc_new_rejects_an_iv_that_is_not_one_block() {
    for len in [0, 7, 9, 16] {
        let result = Cbc::new(des(), &vec![0; len]);
        assert_eq!(
            result.err(),
            Some(ModeError::InvalidIvLength { len, expected: BLOCK }),
            "IV length {len}"
        );
    }
}

/// Splits at 0 and at the end also cover an empty call.
#[test]
fn cbc_encrypt_keeps_chaining_between_calls() {
    for split in [0, 1, 2, 3] {
        let mut cbc = Cbc::new(des(), &IV).unwrap();
        let mut buffer = *PLAINTEXT;
        let (first, second) = buffer.split_at_mut(split * BLOCK);
        cbc.encrypt(first).unwrap();
        cbc.encrypt(second).unwrap();
        assert_eq!(buffer, CBC_CIPHERTEXT, "split at {split}");
    }
}

/// Splits at 0 and at the end also cover an empty call.
#[test]
fn cbc_decrypt_keeps_chaining_between_calls() {
    for split in [0, 1, 2, 3] {
        let mut cbc = Cbc::new(des(), &IV).unwrap();
        let mut buffer = CBC_CIPHERTEXT;
        let (first, second) = buffer.split_at_mut(split * BLOCK);
        cbc.decrypt(first).unwrap();
        cbc.decrypt(second).unwrap();
        assert_eq!(&buffer, PLAINTEXT, "split at {split}");
    }
}

#[test]
fn cbc_rejects_unaligned_input_and_keeps_the_data_and_chain() {
    let expected = Err(ModeError::InvalidLength { len: 9, block_size: BLOCK });
    let mut cbc = Cbc::new(des(), &IV).unwrap();
    let mut data = [7; 9];
    assert_eq!(cbc.encrypt(&mut data), expected);
    assert_eq!(cbc.decrypt(&mut data), expected);
    assert_eq!(data, [7; 9]);

    let mut aligned = *PLAINTEXT;
    cbc.encrypt(&mut aligned).unwrap();
    assert_eq!(aligned, CBC_CIPHERTEXT);
}

// ---- Ctr ----

// SP 800-38A only has AES vectors for CTR, so this uses a DES one: with a zero
// plaintext, the first output block is the encrypted counter. The vector is from
// "The DES Algorithm Illustrated" by J. Orlin Grabbe.
#[test]
fn ctr_known_answer_des_block() {
    let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
    let counter = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let mut data = [0u8; 8];
    Ctr::new(DesCipher::new(&key), &counter).unwrap().apply_keystream(&mut data).unwrap();
    assert_eq!(data, [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05]);
}

/// The counter blocks are written out by hand, and the keystream comes from ECB,
/// so this doesn't depend on the code under test. The cases cover a carry between
/// bytes and the wrap at the block size. The last block is partial.
#[test]
fn ctr_matches_ecb_of_literal_counter_blocks() {
    let cases: [[[u8; 8]; 3]; 2] = [
        [
            [0, 0, 0, 0, 0, 0, 0, 0xFF],
            [0, 0, 0, 0, 0, 0, 1, 0x00],
            [0, 0, 0, 0, 0, 0, 1, 0x01],
        ],
        [
            [0xFF; 8],
            [0x00; 8],
            [0, 0, 0, 0, 0, 0, 0, 0x01],
        ],
    ];
    for counters in cases {
        let mut keystream = counters.concat();
        Ecb::new(des()).encrypt(&mut keystream).unwrap();
        let expected: Vec<u8> = PLAINTEXT[..20].iter().zip(&keystream).map(|(p, k)| p ^ k).collect();

        let mut data = PLAINTEXT[..20].to_vec();
        Ctr::new(des(), &counters[0]).unwrap().apply_keystream(&mut data).unwrap();
        assert_eq!(data, expected, "starting at {:02X?}", counters[0]);
    }
}

#[test]
fn ctr_gives_the_same_bytes_across_splits_and_restores_the_input() {
    for len in [0, 1, 7, 8, 9, 515] {
        let plaintext = sample(len);
        let mut expected = plaintext.clone();
        Ctr::new(des(), &IV).unwrap().apply_keystream(&mut expected).unwrap();

        for split in [0, BLOCK.min(len / BLOCK * BLOCK), len / BLOCK * BLOCK] {
            let mut ctr = Ctr::new(des(), &IV).unwrap();
            let mut buffer = plaintext.clone();
            let (first, second) = buffer.split_at_mut(split);
            ctr.apply_keystream(first).unwrap();
            ctr.apply_keystream(second).unwrap();
            assert_eq!(buffer, expected, "length {len}, split at {split}");

            let mut ctr = Ctr::new(des(), &IV).unwrap();
            ctr.apply_keystream(&mut buffer).unwrap();
            assert_eq!(buffer, plaintext, "length {len}, split at {split}");
        }
    }
}

#[test]
fn ctr_new_rejects_a_counter_that_is_not_one_block() {
    for len in [0, 7, 9, 16] {
        let result = Ctr::new(des(), &vec![0; len]);
        assert_eq!(
            result.err(),
            Some(ModeError::InvalidIvLength { len, expected: BLOCK }),
            "counter length {len}"
        );
    }
}

#[test]
fn ctr_rejects_data_after_a_partial_block_and_keeps_it() {
    let mut ctr = Ctr::new(des(), &IV).unwrap();
    ctr.apply_keystream(&mut [0; 9]).unwrap();
    assert_eq!(ctr.apply_keystream(&mut []), Ok(()));

    let mut data = [7; 8];
    assert_eq!(ctr.apply_keystream(&mut data), Err(ModeError::DataAfterPartialBlock));
    assert_eq!(data, [7; 8]);
}

// ---- BlockMode ----

fn check_block_mode(encryptor: &mut dyn BlockMode, decryptor: &mut dyn BlockMode, ciphertext: [u8; 24]) {
    assert_eq!(encryptor.block_size(), BLOCK);

    let mut data = *PLAINTEXT;
    encryptor.encrypt_blocks(&mut data).unwrap();
    assert_eq!(data, ciphertext);
    decryptor.decrypt_blocks(&mut data).unwrap();
    assert_eq!(&data, PLAINTEXT);
}

#[test]
fn block_mode_forwards_each_call_to_the_right_direction() {
    check_block_mode(&mut Ecb::new(des()), &mut Ecb::new(des()), ECB_CIPHERTEXT);
    check_block_mode(
        &mut Cbc::new(des(), &IV).unwrap(),
        &mut Cbc::new(des(), &IV).unwrap(),
        CBC_CIPHERTEXT,
    );
}
