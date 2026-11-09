//! Compares our DES modes byte for byte with the RustCrypto crates `des`, `ecb`,
//! `cbc` and `ctr`, which are dev-dependencies used only as a reference.
//!
//! Each test checks that both sides produce the same ciphertext and that ours
//! decrypts the library's ciphertext back to the plaintext.

use des::cipher::KeyInit as _;
use des::cipher::block_padding::NoPadding;
use des::cipher::{BlockModeEncrypt, KeyIvInit, StreamCipher};
use oes::ciphers::des::DesCipher;
use oes::ciphers::traits::KeyInit;
use oes::modes::{Cbc, Ctr, Ecb};

/// Key from "The DES Algorithm Illustrated" by J. Orlin Grabbe.
const KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
const IV: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

/// Block-aligned lengths for ECB and CBC: empty, one block, many blocks.
const ALIGNED_LENS: [usize; 3] = [0, 8, 64 * 8];

/// Lengths for CTR, which takes any length: around one block, and unaligned.
const ANY_LENS: [usize; 6] = [0, 1, 7, 8, 9, 1000];

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

// ---- ecb ----

#[test]
fn ecb_matches_rustcrypto() {
    for len in ALIGNED_LENS {
        let pt = plaintext(len);

        let mut ours = pt.clone();
        Ecb::new(DesCipher::new(&KEY)).encrypt(&mut ours).unwrap();

        let mut theirs = pt.clone();
        ecb::Encryptor::<des::Des>::new(&KEY.into())
            .encrypt_padded::<NoPadding>(&mut theirs, len)
            .unwrap();
        assert_eq!(ours, theirs, "len {len}");

        Ecb::new(DesCipher::new(&KEY)).decrypt(&mut theirs).unwrap();
        assert_eq!(theirs, pt, "len {len}");
    }
}

// ---- cbc ----

#[test]
fn cbc_matches_rustcrypto() {
    for len in ALIGNED_LENS {
        let pt = plaintext(len);

        let mut ours = pt.clone();
        Cbc::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .encrypt(&mut ours)
            .unwrap();

        let mut theirs = pt.clone();
        cbc::Encryptor::<des::Des>::new(&KEY.into(), &IV.into())
            .encrypt_padded::<NoPadding>(&mut theirs, len)
            .unwrap();
        assert_eq!(ours, theirs, "len {len}");

        Cbc::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .decrypt(&mut theirs)
            .unwrap();
        assert_eq!(theirs, pt, "len {len}");
    }
}

// ---- ctr ----

/// RustCrypto's `Ctr64BE` treats the whole 8-byte block as one big-endian counter,
/// the same as our `Ctr` with DES.
#[test]
fn ctr_matches_rustcrypto() {
    for len in ANY_LENS {
        let pt = plaintext(len);

        let mut ours = pt.clone();
        Ctr::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .apply_keystream(&mut ours)
            .unwrap();

        let mut theirs = pt.clone();
        ctr::Ctr64BE::<des::Des>::new(&KEY.into(), &IV.into()).apply_keystream(&mut theirs);
        assert_eq!(ours, theirs, "len {len}");

        Ctr::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .apply_keystream(&mut theirs)
            .unwrap();
        assert_eq!(theirs, pt, "len {len}");
    }
}
