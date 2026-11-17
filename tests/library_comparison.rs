//! Compares the DES and AES-128 modes byte for byte with the RustCrypto crates
//! `des`, `aes`, `ecb`, `cbc`, `ctr` and `aes-gcm`, which are dev-dependencies used
//! only as a reference. AES-192 and AES-256 differ only in the key schedule, which the
//! FIPS 197 known answers already pin.
//!
//! Each test checks that both implementations produce the same ciphertext and that
//! the reference ciphertext decrypts back to the plaintext.

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::AeadInOut;
use des::cipher::KeyInit as _;
use des::cipher::block_padding::NoPadding;
use des::cipher::{BlockModeEncrypt, KeyIvInit, StreamCipher};
use oes::ciphers::aes::Aes128Cipher;
use oes::ciphers::des::DesCipher;
use oes::ciphers::traits::KeyInit;
use oes::modes::{Cbc, Ctr, Ecb, GcmDecryptor, GcmEncryptor};

/// Key from "The DES Algorithm Illustrated" by J. Orlin Grabbe.
const KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
const IV: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

/// Block-aligned lengths for ECB and CBC: empty, one block, and many blocks that
/// don't divide into whole groups of 4 or batches of 16.
const ALIGNED_LENS: [usize; 3] = [0, 8, 67 * 8];

/// Lengths for CTR, which takes any length: around one block, and unaligned.
const ANY_LENS: [usize; 6] = [0, 1, 7, 8, 9, 1000];

/// The AES-128 key of NIST SP 800-38A Appendix F.
const AES_KEY: [u8; 16] = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
];
const AES_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];

/// The AES counterpart of `ALIGNED_LENS`, in 16-byte blocks.
const AES_ALIGNED_LENS: [usize; 3] = [0, 16, 67 * 16];

/// The AES counterpart of `ANY_LENS`.
const AES_ANY_LENS: [usize; 6] = [0, 1, 15, 16, 17, 1000];

/// The nonce of test cases 3 and 4 in McGrew and Viega, "The Galois/Counter Mode
/// of Operation (GCM)", Appendix B.
const GCM_NONCE: [u8; 12] = [
    0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88,
];
const GCM_AAD: &[u8] = b"authenticated, not encrypted";

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

// ---- ecb ----

#[test]
fn ecb_matches_rustcrypto() {
    for len in ALIGNED_LENS {
        let pt = plaintext(len);

        let mut ciphertext = pt.clone();
        Ecb::new(DesCipher::new(&KEY))
            .encrypt(&mut ciphertext)
            .unwrap();

        let mut reference = pt.clone();
        ecb::Encryptor::<des::Des>::new(&KEY.into())
            .encrypt_padded::<NoPadding>(&mut reference, len)
            .unwrap();
        assert_eq!(ciphertext, reference, "len {len}");

        Ecb::new(DesCipher::new(&KEY))
            .decrypt(&mut reference)
            .unwrap();
        assert_eq!(reference, pt, "len {len}");
    }
}

// ---- cbc ----

#[test]
fn cbc_matches_rustcrypto() {
    for len in ALIGNED_LENS {
        let pt = plaintext(len);

        let mut ciphertext = pt.clone();
        Cbc::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .encrypt(&mut ciphertext)
            .unwrap();

        let mut reference = pt.clone();
        cbc::Encryptor::<des::Des>::new(&KEY.into(), &IV.into())
            .encrypt_padded::<NoPadding>(&mut reference, len)
            .unwrap();
        assert_eq!(ciphertext, reference, "len {len}");

        Cbc::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .decrypt(&mut reference)
            .unwrap();
        assert_eq!(reference, pt, "len {len}");
    }
}

// ---- ctr ----

/// RustCrypto's `Ctr64BE` treats the whole 8-byte block as one big-endian counter,
/// the same as `Ctr` with DES.
#[test]
fn ctr_matches_rustcrypto() {
    for len in ANY_LENS {
        let pt = plaintext(len);

        let mut ciphertext = pt.clone();
        Ctr::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .apply_keystream(&mut ciphertext)
            .unwrap();

        let mut reference = pt.clone();
        ctr::Ctr64BE::<des::Des>::new(&KEY.into(), &IV.into()).apply_keystream(&mut reference);
        assert_eq!(ciphertext, reference, "len {len}");

        Ctr::new(DesCipher::new(&KEY), &IV)
            .unwrap()
            .apply_keystream(&mut reference)
            .unwrap();
        assert_eq!(reference, pt, "len {len}");
    }
}

// ---- aes ecb ----

#[test]
fn aes_ecb_matches_rustcrypto() {
    for len in AES_ALIGNED_LENS {
        let pt = plaintext(len);

        let mut ciphertext = pt.clone();
        Ecb::new(Aes128Cipher::new(&AES_KEY))
            .encrypt(&mut ciphertext)
            .unwrap();

        let mut reference = pt.clone();
        ecb::Encryptor::<aes::Aes128>::new(&AES_KEY.into())
            .encrypt_padded::<NoPadding>(&mut reference, len)
            .unwrap();
        assert_eq!(ciphertext, reference, "len {len}");

        Ecb::new(Aes128Cipher::new(&AES_KEY))
            .decrypt(&mut reference)
            .unwrap();
        assert_eq!(reference, pt, "len {len}");
    }
}

// ---- aes cbc ----

#[test]
fn aes_cbc_matches_rustcrypto() {
    for len in AES_ALIGNED_LENS {
        let pt = plaintext(len);

        let mut ciphertext = pt.clone();
        Cbc::new(Aes128Cipher::new(&AES_KEY), &AES_IV)
            .unwrap()
            .encrypt(&mut ciphertext)
            .unwrap();

        let mut reference = pt.clone();
        cbc::Encryptor::<aes::Aes128>::new(&AES_KEY.into(), &AES_IV.into())
            .encrypt_padded::<NoPadding>(&mut reference, len)
            .unwrap();
        assert_eq!(ciphertext, reference, "len {len}");

        Cbc::new(Aes128Cipher::new(&AES_KEY), &AES_IV)
            .unwrap()
            .decrypt(&mut reference)
            .unwrap();
        assert_eq!(reference, pt, "len {len}");
    }
}

// ---- aes ctr ----

/// RustCrypto's `Ctr128BE` treats the whole 16-byte block as one big-endian
/// counter, the same as `Ctr` with AES.
#[test]
fn aes_ctr_matches_rustcrypto() {
    for len in AES_ANY_LENS {
        let pt = plaintext(len);

        let mut ciphertext = pt.clone();
        Ctr::new(Aes128Cipher::new(&AES_KEY), &AES_IV)
            .unwrap()
            .apply_keystream(&mut ciphertext)
            .unwrap();

        let mut reference = pt.clone();
        ctr::Ctr128BE::<aes::Aes128>::new(&AES_KEY.into(), &AES_IV.into())
            .apply_keystream(&mut reference);
        assert_eq!(ciphertext, reference, "len {len}");

        Ctr::new(Aes128Cipher::new(&AES_KEY), &AES_IV)
            .unwrap()
            .apply_keystream(&mut reference)
            .unwrap();
        assert_eq!(reference, pt, "len {len}");
    }
}

// ---- gcm ----

#[test]
fn aes_gcm_matches_rustcrypto() {
    for len in AES_ANY_LENS {
        let pt = plaintext(len);

        let mut ciphertext = pt.clone();
        let mut encryptor =
            GcmEncryptor::new(Aes128Cipher::new(&AES_KEY), &GCM_NONCE, GCM_AAD).unwrap();
        encryptor.update(&mut ciphertext).unwrap();
        let tag = encryptor.finish();

        let mut reference = pt.clone();
        let reference_tag = Aes128Gcm::new(&AES_KEY.into())
            .encrypt_inout_detached(&GCM_NONCE.into(), GCM_AAD, reference.as_mut_slice().into())
            .unwrap();
        assert_eq!(ciphertext, reference, "len {len}");
        assert_eq!(tag, reference_tag.as_slice(), "len {len}");

        let mut decryptor =
            GcmDecryptor::new(Aes128Cipher::new(&AES_KEY), &GCM_NONCE, GCM_AAD).unwrap();
        decryptor.update(&mut reference).unwrap();
        assert_eq!(decryptor.verify(&reference_tag.into()), Ok(()), "len {len}");
        assert_eq!(reference, pt, "len {len}");
    }
}
