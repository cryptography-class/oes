use super::{CHUNK, PAR_BLOCKS, POOLS, in_pool, sample};
use crate::ciphers::aes::{Aes128Cipher, Aes192Cipher, Aes256Cipher};
use crate::ciphers::des::DesCipher;
use crate::ciphers::traits::KeyInit;
use crate::modes::errors::ModeError;
use crate::modes::gcm::{MAX_PLAINTEXT_LEN, TAG_LEN};
use crate::modes::{GcmDecryptor, GcmEncryptor};

const KEY: [u8; 16] = [0x2B; 16];
const NONCE: [u8; 12] = [0x5A; 12];
const AAD: &[u8] = b"authenticated, not encrypted";

/// Decodes hex digits, with `-` standing for an empty field.
fn hex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn seal(key: &[u8; 16], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut data = plaintext.to_vec();
    let mut gcm = GcmEncryptor::new(Aes128Cipher::new(key), nonce, aad).unwrap();
    gcm.update(&mut data).unwrap();
    (data, gcm.finish())
}

fn open(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, ModeError> {
    let mut data = ciphertext.to_vec();
    let mut gcm = GcmDecryptor::new(Aes128Cipher::new(key), nonce, aad)?;
    gcm.update(&mut data)?;
    gcm.verify(tag)?;
    Ok(data)
}

// ---- GcmEncryptor and GcmDecryptor ----

/// Checks one record of `gcm_vectors.txt` in both directions, or only its
/// rejection for a `fail` record.
fn check_record<C: KeyInit<K>, const K: usize>(fields: &[&str]) {
    let [kind, key, nonce, aad, plaintext, ciphertext, tag] = *fields else {
        panic!("malformed record: {fields:?}");
    };
    let key: [u8; K] = hex(key).try_into().unwrap();
    let tag: [u8; TAG_LEN] = hex(tag).try_into().unwrap();
    let (nonce, aad, ciphertext) = (hex(nonce), hex(aad), hex(ciphertext));

    let mut data = ciphertext.clone();
    let mut decryptor = GcmDecryptor::new(C::new(&key), &nonce, &aad).unwrap();
    decryptor.update(&mut data).unwrap();
    let verdict = decryptor.verify(&tag);
    if kind == "fail" {
        assert_eq!(verdict, Err(ModeError::AuthenticationFailed), "{fields:?}");
        return;
    }
    assert_eq!(verdict, Ok(()), "{fields:?}");
    assert_eq!(data, hex(plaintext), "{fields:?}");

    let mut encryptor = GcmEncryptor::new(C::new(&key), &nonce, &aad).unwrap();
    encryptor.update(&mut data).unwrap();
    assert_eq!(data, ciphertext, "{fields:?}");
    assert_eq!(encryptor.finish(), tag, "{fields:?}");
}

/// NIST CAVP GCM vectors; the exact source is at the head of the file.
#[test]
fn gcm_known_answer_nist_cavp() {
    let mut counts = [0usize; 3];
    for line in include_str!("gcm_vectors.txt").lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        match fields[1].len() {
            32 => {
                check_record::<Aes128Cipher, 16>(&fields);
                counts[0] += 1;
            }
            48 => {
                check_record::<Aes192Cipher, 24>(&fields);
                counts[1] += 1;
            }
            64 => {
                check_record::<Aes256Cipher, 32>(&fields);
                counts[2] += 1;
            }
            other => panic!("key of {other} hex digits"),
        }
    }
    for count in counts {
        assert!(count >= 25, "only {count} records for one key size");
    }
}

#[test]
fn gcm_new_rejects_a_nonce_that_is_not_96_bits() {
    for len in [0, 8, 11, 13, 16] {
        let expected = Some(ModeError::InvalidIvLength { len, expected: 12 });
        let nonce = vec![0; len];
        let encryptor = GcmEncryptor::new(Aes128Cipher::new(&KEY), &nonce, &[]);
        assert_eq!(encryptor.err(), expected, "len {len}");
        let decryptor = GcmDecryptor::new(Aes128Cipher::new(&KEY), &nonce, &[]);
        assert_eq!(decryptor.err(), expected, "len {len}");
    }
}

#[test]
fn gcm_new_rejects_a_64_bit_block_cipher() {
    let des = DesCipher::new(&[0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]);
    let result = GcmEncryptor::new(des, &NONCE, &[]);
    assert_eq!(
        result.err(),
        Some(ModeError::UnsupportedBlockSize { block_size: 8 })
    );
}

#[test]
fn gcm_update_gives_the_same_result_across_splits() {
    let plaintext = sample(1003);
    let (expected, expected_tag) = seal(&KEY, &NONCE, AAD, &plaintext);

    for size in [16, 32, 160, 992] {
        let mut data = plaintext.clone();
        let mut gcm = GcmEncryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD).unwrap();
        for chunk in data.chunks_mut(size) {
            gcm.update(chunk).unwrap();
        }
        assert_eq!(data, expected, "chunk {size}");
        assert_eq!(gcm.finish(), expected_tag, "chunk {size}");

        let mut gcm = GcmDecryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD).unwrap();
        for chunk in data.chunks_mut(size) {
            gcm.update(chunk).unwrap();
        }
        assert_eq!(gcm.verify(&expected_tag), Ok(()), "chunk {size}");
        assert_eq!(data, plaintext, "chunk {size}");
    }
}

#[test]
fn gcm_update_rejects_data_after_a_partial_block_and_keeps_it() {
    let mut gcm = GcmEncryptor::new(Aes128Cipher::new(&KEY), &NONCE, &[]).unwrap();
    gcm.update(&mut [0; 5]).unwrap();
    gcm.update(&mut []).unwrap();

    let mut more = [0u8; 16];
    assert_eq!(gcm.update(&mut more), Err(ModeError::DataAfterPartialBlock));
    assert_eq!(more, [0; 16]);
}

#[test]
fn gcm_update_enforces_the_limit_for_one_nonce() {
    let mut gcm = GcmEncryptor::new(Aes128Cipher::new(&KEY), &NONCE, &[]).unwrap();
    gcm.state.data_len = MAX_PLAINTEXT_LEN - 16;

    let mut last = [0u8; 16];
    gcm.update(&mut last).unwrap();
    assert_ne!(last, [0; 16], "the last allowed block is encrypted");

    let mut over = [0u8; 1];
    assert_eq!(
        gcm.update(&mut over),
        Err(ModeError::MessageTooLong {
            max: MAX_PLAINTEXT_LEN
        })
    );
    assert_eq!(over, [0; 1]);
}

#[test]
fn gcm_parallel_matches_sequential() {
    for blocks in PAR_BLOCKS {
        // A partial last block, so the parallel path also ends in one.
        let plaintext = sample(blocks * 16 + 7);
        let (expected, expected_tag) = seal(&KEY, &NONCE, AAD, &plaintext);

        for threads in POOLS {
            let context = format!("{blocks} blocks, {threads} threads");
            in_pool(threads, || {
                let mut data = plaintext.clone();
                let mut gcm = GcmEncryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD)
                    .unwrap()
                    .parallel(true);
                gcm.update(&mut data).unwrap();
                assert_eq!(data, expected, "{context}");
                assert_eq!(gcm.finish(), expected_tag, "{context}");

                let mut gcm = GcmDecryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD)
                    .unwrap()
                    .parallel(true);
                gcm.update(&mut data).unwrap();
                assert_eq!(gcm.verify(&expected_tag), Ok(()), "{context}");
                assert_eq!(data, plaintext, "{context}");
            });
        }
    }
}

/// Two parallel calls, each longer than a piece: the second has to start from the
/// counter and the hash that the pieces of the first left behind. The message ends in
/// a partial block.
#[test]
fn gcm_parallel_keeps_the_counter_and_hash_between_calls() {
    let plaintext = sample((2 * CHUNK + CHUNK / 2) * 16 + 7);
    let (expected, expected_tag) = seal(&KEY, &NONCE, AAD, &plaintext);
    let split = (CHUNK + 5) * 16;

    in_pool(2, || {
        let mut data = plaintext.clone();
        let mut gcm = GcmEncryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD)
            .unwrap()
            .parallel(true);
        let (first, second) = data.split_at_mut(split);
        gcm.update(first).unwrap();
        gcm.update(second).unwrap();
        assert_eq!(data, expected);
        assert_eq!(gcm.finish(), expected_tag);

        let mut gcm = GcmDecryptor::new(Aes128Cipher::new(&KEY), &NONCE, AAD)
            .unwrap()
            .parallel(true);
        let (first, second) = data.split_at_mut(split);
        gcm.update(first).unwrap();
        gcm.update(second).unwrap();
        assert_eq!(gcm.verify(&expected_tag), Ok(()));
        assert_eq!(data, plaintext);
    });
}

#[test]
fn gcm_verify_rejects_any_changed_input() {
    let plaintext = sample(100);
    let (ciphertext, tag) = seal(&KEY, &NONCE, AAD, &plaintext);
    let rejected: Result<Vec<u8>, ModeError> = Err(ModeError::AuthenticationFailed);

    let mut wrong_key = KEY;
    wrong_key[0] ^= 1;
    assert_eq!(
        open(&wrong_key, &NONCE, AAD, &ciphertext, &tag),
        rejected,
        "key"
    );

    for byte in 0..NONCE.len() {
        let mut nonce = NONCE;
        nonce[byte] ^= 1;
        assert_eq!(
            open(&KEY, &nonce, AAD, &ciphertext, &tag),
            rejected,
            "nonce byte {byte}"
        );
    }
    for byte in 0..TAG_LEN {
        let mut changed = tag;
        changed[byte] ^= 1;
        assert_eq!(
            open(&KEY, &NONCE, AAD, &ciphertext, &changed),
            rejected,
            "tag byte {byte}"
        );
    }
    for byte in 0..ciphertext.len() {
        let mut changed = ciphertext.clone();
        changed[byte] ^= 1;
        assert_eq!(
            open(&KEY, &NONCE, AAD, &changed, &tag),
            rejected,
            "ciphertext byte {byte}"
        );
    }
    for byte in 0..AAD.len() {
        let mut changed = AAD.to_vec();
        changed[byte] ^= 1;
        assert_eq!(
            open(&KEY, &NONCE, &changed, &ciphertext, &tag),
            rejected,
            "AAD byte {byte}"
        );
    }
    assert_eq!(
        open(&KEY, &NONCE, b"", &ciphertext, &tag),
        rejected,
        "missing AAD"
    );
    assert_eq!(
        open(&KEY, &NONCE, AAD, &ciphertext[..99], &tag),
        rejected,
        "truncated"
    );
}
