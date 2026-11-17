use std::fs;
use std::io::Cursor;

use super::{BUF_SIZES, LENS, LimitedReader, READ_LIMITS, sample};
use crate::ciphers::aes::Aes128Cipher;
use crate::ciphers::traits::KeyInit;
use crate::modes::errors::ModeError;
use crate::modes::gcm::TAG_LEN;
use crate::modes::{GcmDecryptor, GcmEncryptor};
use crate::stream::errors::StreamError;
use crate::stream::test_util::TempDir;
use crate::stream::{AtomicFile, decrypt_gcm_stream, encrypt_gcm_stream};

const KEY: [u8; 16] = [0x2B; 16];
const NONCE: [u8; 12] = [0x5A; 12];
const AAD: &[u8] = b"header";

fn encryptor() -> GcmEncryptor<Aes128Cipher> {
    GcmEncryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD).unwrap()
}

fn decryptor() -> GcmDecryptor<Aes128Cipher> {
    GcmDecryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD).unwrap()
}

/// The ciphertext and tag of `data` from a single `update` call.
fn sealed(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut gcm = encryptor();
    gcm.update(&mut out).unwrap();
    out.extend_from_slice(&gcm.finish());
    out
}

fn opened(input: &[u8], buf_size: usize) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    decrypt_gcm_stream(decryptor(), &mut Cursor::new(input), &mut out, buf_size)?;
    Ok(out)
}

// ---- encrypt_gcm_stream ----

#[test]
fn encrypt_gcm_stream_matches_one_update_call_for_any_buffer_or_read_size() {
    for len in LENS {
        let data = sample(len);
        let expected = sealed(&data);

        for buf_size in BUF_SIZES {
            for limit in READ_LIMITS {
                let context = format!("len {len} buf_size {buf_size} limit {limit}");
                let mut reader = LimitedReader {
                    inner: Cursor::new(&data),
                    limit,
                };
                let mut out = Vec::new();
                let counts =
                    encrypt_gcm_stream(encryptor(), &mut reader, &mut out, buf_size).unwrap();

                assert_eq!(out, expected, "{context}");
                assert_eq!(counts.bytes_in, len as u64, "{context}");
                assert_eq!(counts.bytes_out, (len + TAG_LEN) as u64, "{context}");
            }
        }
    }
}

// ---- decrypt_gcm_stream ----

#[test]
fn decrypt_gcm_stream_restores_every_length_for_any_buffer_or_read_size() {
    for len in LENS {
        let data = sample(len);
        let input = sealed(&data);

        for buf_size in BUF_SIZES {
            for limit in READ_LIMITS {
                let context = format!("len {len} buf_size {buf_size} limit {limit}");
                let mut reader = LimitedReader {
                    inner: Cursor::new(&input),
                    limit,
                };
                let mut out = Vec::new();
                let counts =
                    decrypt_gcm_stream(decryptor(), &mut reader, &mut out, buf_size).unwrap();

                assert_eq!(out, data, "{context}");
                assert_eq!(counts.bytes_in, input.len() as u64, "{context}");
                assert_eq!(counts.bytes_out, len as u64, "{context}");
            }
        }
    }
}

#[test]
fn decrypt_gcm_stream_rejects_input_too_short_for_a_tag() {
    for len in [0, 1, TAG_LEN - 1] {
        let result = opened(&vec![0; len], 64);
        assert!(
            matches!(result, Err(StreamError::MissingTag { len: l }) if l == len as u64),
            "len {len}: {result:?}"
        );
    }
}

#[test]
fn decrypt_gcm_stream_rejects_changed_truncated_or_extended_input() {
    let input = sealed(&sample(70));
    let rejected = |result: Result<Vec<u8>, StreamError>| {
        matches!(
            result,
            Err(StreamError::Mode(ModeError::AuthenticationFailed))
        )
    };

    for byte in 0..input.len() {
        let mut changed = input.clone();
        changed[byte] ^= 0x40;
        assert!(rejected(opened(&changed, 32)), "byte {byte}");
    }
    assert!(rejected(opened(&input[..input.len() - 1], 32)), "truncated");
    let mut longer = input.clone();
    longer.push(0);
    assert!(rejected(opened(&longer, 32)), "extended");
}

#[test]
fn decrypt_gcm_stream_through_atomic_file_leaves_nothing_on_failure() {
    let dir = TempDir::new("gcm");
    let mut input = sealed(&sample(5000));
    let last = input.len() - 1;
    input[last] ^= 1; // Only the tag is wrong, so every block is written first.

    let mut file = AtomicFile::create(dir.path().join("out.bin"), false).unwrap();
    let result = decrypt_gcm_stream(decryptor(), &mut Cursor::new(&input), &mut file, 64);
    assert!(matches!(
        result,
        Err(StreamError::Mode(ModeError::AuthenticationFailed))
    ));

    let temp = dir.path().join(&dir.entries()[0]);
    assert_eq!(fs::metadata(temp).unwrap().len(), 5000);

    drop(file);
    assert!(dir.entries().is_empty());
}
