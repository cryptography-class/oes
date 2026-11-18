//! Checks the AES-NI engine against the FIPS 197 vectors and, block for block, against
//! the table-based implementation. Each test passes without checking anything on a
//! processor that lacks AES-NI.

use super::{SCHEDULE_128, SCHEDULE_192, SCHEDULE_256, ScheduleVector, array};
use crate::ciphers::aes::aes_ni::AesNiKeys;
use crate::ciphers::aes::key_schedule::{MAX_WORDS, expand_key};
use crate::ciphers::aes::round;

/// Keys with no structure in common: all zeros, all ones, and uneven bytes.
fn sample_keys<const N: usize>() -> [[u8; N]; 3] {
    [
        [0x00; N],
        [0xFF; N],
        std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5A),
    ]
}

/// Returns the hardware round keys for `key`, or `None` without AES-NI.
fn hardware_keys<const N: usize>(key: &[u8; N]) -> Option<AesNiKeys> {
    let mut keys = AesNiKeys::empty()?;
    keys.expand_key(key);
    Some(keys)
}

/// Returns word `i` of the schedule held in `keys`, as FIPS 197 writes it.
fn schedule_word(keys: &AesNiKeys, i: usize) -> u32 {
    let bytes = &keys.encrypt[i / 4][(i % 4) * 4..][..4];
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// ---- expand_key ----

fn check_schedule<const N: usize>((key, rounds, expected): ScheduleVector) {
    let Some(keys) = hardware_keys(&array::<N>(key)) else {
        return;
    };
    assert_eq!(keys.rounds, rounds, "key {key}");
    for &(i, word) in expected {
        assert_eq!(schedule_word(&keys, i), word, "key {key}, w[{i}]");
    }
}

#[test]
fn expand_key_known_answer_fips_197() {
    check_schedule::<16>(SCHEDULE_128);
    check_schedule::<24>(SCHEDULE_192);
    check_schedule::<32>(SCHEDULE_256);
}

fn check_matches_textbook_schedule<const N: usize>() {
    for key in sample_keys::<N>() {
        let Some(keys) = hardware_keys(&key) else {
            return;
        };
        let mut w = [0; MAX_WORDS];
        let rounds = expand_key(&key, &mut w);
        assert_eq!(keys.rounds, rounds, "key {key:02x?}");
        for (i, &word) in w.iter().enumerate().take(4 * (rounds + 1)) {
            assert_eq!(schedule_word(&keys, i), word, "key {key:02x?}, w[{i}]");
        }
    }
}

#[test]
fn expand_key_matches_textbook() {
    check_matches_textbook_schedule::<16>();
    check_matches_textbook_schedule::<24>();
    check_matches_textbook_schedule::<32>();
}

// ---- encrypt_block and decrypt_block ----

fn check_matches_textbook_blocks<const N: usize>() {
    for key in sample_keys::<N>() {
        let Some(keys) = hardware_keys(&key) else {
            return;
        };
        let mut w = [0; MAX_WORDS];
        let rounds = expand_key(&key, &mut w);

        for seed in 0..=255u8 {
            let block: [u8; 16] = std::array::from_fn(|i| seed.wrapping_mul(i as u8 + 1) ^ 0xA5);

            let (mut hardware, mut textbook) = (block, block);
            keys.encrypt_block(&mut hardware);
            round::encrypt(&mut textbook, &w, rounds);
            assert_eq!(hardware, textbook, "encrypt, key {key:02x?}, seed {seed}");

            let (mut hardware, mut textbook) = (block, block);
            keys.decrypt_block(&mut hardware);
            round::decrypt(&mut textbook, &w, rounds);
            assert_eq!(hardware, textbook, "decrypt, key {key:02x?}, seed {seed}");
        }
    }
}

#[test]
fn encrypt_block_matches_textbook() {
    check_matches_textbook_blocks::<16>();
    check_matches_textbook_blocks::<24>();
    check_matches_textbook_blocks::<32>();
}
