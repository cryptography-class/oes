use super::key_schedule::{MAX_WORDS, expand_key};
use super::tables::{INV_SBOX, SBOX};
use super::{Aes128Cipher, Aes192Cipher, Aes256Cipher};
use crate::ciphers::traits::KeyInit;

#[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
mod aes_ni;

/// Parses hex digits, ignoring whitespace.
fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    digits
        .chunks_exact(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().unwrap()
}

// ---- tables ----

/// Multiplication modulo the AES polynomial, kept apart from the implementation
/// so the tables can be checked independently.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 == 1 {
            product ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    product
}

/// FIPS 197 section 5.1.1 defines the S-box as the GF(2^8) inverse followed by an
/// affine transformation, so the table can be recomputed from its definition.
#[test]
fn sbox_matches_its_definition() {
    for value in 0..=255u8 {
        let inverse = (1..=255u8).find(|&c| gf_mul(value, c) == 1).unwrap_or(0);
        let affine = inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63;
        assert_eq!(SBOX[value as usize], affine, "SBOX[{value:#04x}]");
    }
}

#[test]
fn inv_sbox_inverts_sbox() {
    for value in 0..=255u8 {
        assert_eq!(
            INV_SBOX[SBOX[value as usize] as usize], value,
            "value {value:#04x}"
        );
    }
}

// ---- expand_key ----

/// A key, its `Nr`, and some words of its schedule as `(index, word)`.
type ScheduleVector = (&'static str, usize, &'static [(usize, u32)]);

/// FIPS 197 Appendix A.1.
const SCHEDULE_128: ScheduleVector = (
    "2b7e151628aed2a6abf7158809cf4f3c",
    10,
    &[
        (0, 0x2b7e1516),
        (4, 0xa0fafe17),
        (40, 0xd014f9a8),
        (43, 0xb6630ca6),
    ],
);

/// FIPS 197 Appendix A.2.
const SCHEDULE_192: ScheduleVector = (
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    12,
    &[
        (5, 0x522c6b7b),
        (6, 0xfe0c91f7),
        (48, 0xe98ba06f),
        (51, 0x01002202),
    ],
);

/// FIPS 197 Appendix A.3, which also covers the extra SubWord of 256-bit keys.
const SCHEDULE_256: ScheduleVector = (
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    14,
    &[
        (8, 0x9ba35411),
        (12, 0xa8b09c1a),
        (56, 0xfe4890d1),
        (59, 0x706c631e),
    ],
);

/// Checks `Nr`, the listed words of the schedule, and that words past its end stay unused.
fn check_schedule<const N: usize>((key, rounds, expected): ScheduleVector) {
    let mut w = [0; MAX_WORDS];
    assert_eq!(expand_key(&array::<N>(key), &mut w), rounds, "key {key}");
    for &(i, word) in expected {
        assert_eq!(w[i], word, "key {key}, w[{i}]");
    }
    assert!(
        w[4 * (rounds + 1)..].iter().all(|&word| word == 0),
        "key {key}"
    );
}

#[test]
fn expand_key_known_answer_fips_197() {
    check_schedule::<16>(SCHEDULE_128);
    check_schedule::<24>(SCHEDULE_192);
    check_schedule::<32>(SCHEDULE_256);
}

// ---- encrypt_block and decrypt_block ----

/// FIPS 197 Appendix C: the same plaintext under each key size.
const PLAINTEXT: &str = "00112233445566778899aabbccddeeff";

fn check_block<C: KeyInit<K, Block = [u8; 16]>, const K: usize>(key: &str, ciphertext: &str) {
    let cipher = C::new(&array::<K>(key));
    let mut block = array::<16>(PLAINTEXT);
    cipher.encrypt_block(&mut block);
    assert_eq!(block, array::<16>(ciphertext), "key {key}");
    cipher.decrypt_block(&mut block);
    assert_eq!(block, array::<16>(PLAINTEXT), "key {key}");
}

/// FIPS 197 Appendices C.1, C.2 and C.3.
#[test]
fn encrypt_block_known_answer_fips_197() {
    check_block::<Aes128Cipher, 16>(
        "000102030405060708090a0b0c0d0e0f",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
    );
    check_block::<Aes192Cipher, 24>(
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "dda97ca4864cdfe06eaf70a0ec0d7191",
    );
    check_block::<Aes256Cipher, 32>(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089",
    );
}
