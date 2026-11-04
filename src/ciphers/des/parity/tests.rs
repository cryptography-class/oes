use super::{check_parity, first_bad_parity_byte, set_parity};
use crate::ciphers::des::cipher::DesCipher;
use crate::ciphers::traits::BlockCipher;

const KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

#[test]
fn textbook_key_has_valid_parity() {
    assert!(check_parity(&KEY));
    assert_eq!(first_bad_parity_byte(&KEY), None);
}

#[test]
fn flipping_any_single_bit_breaks_parity() {
    for byte in 0..8 {
        for bit in 0..8 {
            let mut key = KEY;
            key[byte] ^= 1 << bit;
            assert!(!check_parity(&key), "byte {byte} bit {bit}");
            assert_eq!(first_bad_parity_byte(&key), Some(byte));
        }
    }
}

#[test]
fn set_parity_restores_textbook_key_from_cleared_lsbs() {
    let mut key = KEY.map(|b| b & 0xFE);
    set_parity(&mut key);
    assert_eq!(key, KEY);
}

#[test]
fn set_parity_fixes_every_byte_value_and_only_touches_lsb() {
    for v in 0..=255u8 {
        let mut key = [v; 8];
        set_parity(&mut key);
        assert!(check_parity(&key), "value {v:#04x}");
        assert_eq!(key[0] & 0xFE, v & 0xFE, "value {v:#04x}");
    }
}

#[test]
fn set_parity_is_idempotent() {
    let mut key = [0xA5, 0x00, 0xFF, 0x01, 0x80, 0x7E, 0x42, 0x99];
    set_parity(&mut key);
    let once = key;
    set_parity(&mut key);
    assert_eq!(key, once);
}

#[test]
fn all_zero_key_becomes_all_0x01() {
    let mut key = [0u8; 8];
    set_parity(&mut key);
    assert_eq!(key, [0x01; 8]);
}

#[test]
fn des_ignores_parity_bits() {
    let mut other = KEY;
    for b in other.iter_mut() {
        *b ^= 0x01; // flip every parity bit
    }
    assert!(!check_parity(&other));

    let (a, b) = (DesCipher::new(&KEY), DesCipher::new(&other));
    let mut x = 0x0123_4567_89AB_CDEFu64;
    let mut y = x;
    a.encrypt_block(&mut x);
    b.encrypt_block(&mut y);
    assert_eq!(x, y);
    assert_eq!(x, 0x85E8_1354_0F0A_B405); // FIPS textbook vector
}
