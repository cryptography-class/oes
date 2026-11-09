use std::fs;

use super::Key;
use super::errors::KeyError;
use crate::ciphers::des::DesCipher;
use crate::ciphers::des::parity::check_parity;
use crate::ciphers::traits::{BlockCipher, KeyInit};
use crate::container::Algorithm;
use crate::stream::test_util::TempDir;

/// Every byte has odd parity. From J. Orlin Grabbe, "The DES Algorithm Illustrated".
const DES_KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

// ---- generate ----

#[test]
fn generate_gives_valid_parity_and_different_keys() {
    let first = Key::generate(Algorithm::Des).unwrap();
    for _ in 0..100 {
        let key = Key::generate(Algorithm::Des).unwrap();
        assert!(check_parity(key.as_array::<8>().unwrap()));
        assert_ne!(key.as_array::<8>().unwrap(), first.as_array::<8>().unwrap());
    }
}

// ---- load ----

#[test]
fn load_known_answer_grabbe() {
    let dir = TempDir::new("keys");
    let path = dir.path().join("des.key");
    fs::write(&path, DES_KEY).unwrap();

    let key = Key::load(Algorithm::Des, &path).unwrap();
    let mut block = 0x0123_4567_89AB_CDEFu64;
    DesCipher::new(key.as_array::<8>().unwrap()).encrypt_block(&mut block);
    assert_eq!(block, 0x85E8_1354_0F0A_B405);
}

#[test]
fn load_refuses_wrong_lengths() {
    let dir = TempDir::new("keys");
    let path = dir.path().join("bad.key");
    for len in [0, 7, 9, 16] {
        fs::write(&path, vec![0x13; len]).unwrap();
        let res = Key::load(Algorithm::Des, &path);
        assert!(
            matches!(res, Err(KeyError::InvalidLength { expected: 8, actual, .. }) if actual == len as u64),
            "length {len}: {res:?}"
        );
    }
}

#[test]
fn load_refuses_bad_parity_at_each_byte() {
    let dir = TempDir::new("keys");
    let path = dir.path().join("bad.key");
    for byte in 0..8 {
        let mut bytes = DES_KEY;
        bytes[byte] ^= 1;
        fs::write(&path, bytes).unwrap();
        let res = Key::load(Algorithm::Des, &path);
        assert!(
            matches!(res, Err(KeyError::BadParity { byte: b }) if b == byte),
            "byte {byte}: {res:?}"
        );
    }
}

// ---- save ----

#[test]
fn save_writes_raw_bytes_that_load_reads_back() {
    let dir = TempDir::new("keys");
    let path = dir.path().join("des.key");
    let key = Key::generate(Algorithm::Des).unwrap();
    key.save(&path, false).unwrap();

    assert_eq!(fs::read(&path).unwrap(), key.as_array::<8>().unwrap());
    let loaded = Key::load(Algorithm::Des, &path).unwrap();
    assert_eq!(
        loaded.as_array::<8>().unwrap(),
        key.as_array::<8>().unwrap()
    );
}

// ---- Debug and errors ----

#[test]
fn debug_and_errors_hide_key_bytes() {
    let dir = TempDir::new("keys");
    let path = dir.path().join("des.key");
    fs::write(&path, DES_KEY).unwrap();
    let key = Key::load(Algorithm::Des, &path).unwrap();
    assert_eq!(
        format!("{key:?}"),
        r#"Key { algorithm: Des, bytes: "<redacted>" }"#
    );

    let mut bad = DES_KEY;
    bad[0] ^= 1;
    fs::write(&path, bad).unwrap();
    let err = Key::load(Algorithm::Des, &path).unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid DES key: byte 0 fails the odd parity check (wrong or corrupted key)"
    );
}
