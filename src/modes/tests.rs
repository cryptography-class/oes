use super::blocks::PAR_CHUNK_BLOCKS;
use super::ctr::add;
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

/// One piece of parallel work, in blocks.
const CHUNK: usize = PAR_CHUNK_BLOCKS;

/// Thread counts for the parallel tests, including one thread and an odd count.
const POOLS: [usize; 3] = [1, 2, 3];

/// Lengths in blocks around the size of a piece: those of up to one piece stay on
/// the calling thread, and the last one ends in half a piece.
const PAR_BLOCKS: [usize; 6] = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + CHUNK / 2];

/// Runs `f` inside a Rayon pool of `threads` threads.
fn in_pool<R: Send>(threads: usize, f: impl FnOnce() -> R + Send) -> R {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
        .install(f)
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

#[test]
fn ecb_parallel_matches_sequential() {
    for blocks in PAR_BLOCKS {
        let plaintext = sample(blocks * BLOCK);
        let mut expected = plaintext.clone();
        Ecb::new(des()).encrypt(&mut expected).unwrap();

        for threads in POOLS {
            let ecb = Ecb::new(des()).parallel(true);
            let mut buffer = plaintext.clone();
            in_pool(threads, || ecb.encrypt(&mut buffer)).unwrap();
            assert_eq!(
                buffer, expected,
                "encrypt {blocks} blocks, {threads} threads"
            );
            in_pool(threads, || ecb.decrypt(&mut buffer)).unwrap();
            assert_eq!(
                buffer, plaintext,
                "decrypt {blocks} blocks, {threads} threads"
            );
        }
    }
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

#[test]
fn cbc_parallel_decrypt_matches_sequential() {
    for blocks in PAR_BLOCKS {
        let plaintext = sample(blocks * BLOCK);
        let mut ciphertext = plaintext.clone();
        Cbc::new(des(), &IV)
            .unwrap()
            .encrypt(&mut ciphertext)
            .unwrap();

        for threads in POOLS {
            let mut cbc = Cbc::new(des(), &IV).unwrap().parallel(true);
            let mut buffer = ciphertext.clone();
            in_pool(threads, || cbc.decrypt(&mut buffer)).unwrap();
            assert_eq!(buffer, plaintext, "{blocks} blocks, {threads} threads");
        }
    }
}

/// The stream layer decrypts one buffer at a time, so the chain has to carry over
/// from one parallel call to the next.
#[test]
fn cbc_parallel_decrypt_keeps_chaining_between_calls() {
    let plaintext = sample((3 * CHUNK + 1) * BLOCK);
    let mut ciphertext = plaintext.clone();
    Cbc::new(des(), &IV)
        .unwrap()
        .encrypt(&mut ciphertext)
        .unwrap();

    for split in [1, CHUNK, CHUNK + 1, 2 * CHUNK + 3] {
        let mut cbc = Cbc::new(des(), &IV).unwrap().parallel(true);
        let mut buffer = ciphertext.clone();
        let (first, second) = buffer.split_at_mut(split * BLOCK);
        in_pool(2, || {
            cbc.decrypt(first)?;
            cbc.decrypt(second)
        })
        .unwrap();
        assert_eq!(buffer, plaintext, "split at block {split}");
    }
}

#[test]
fn cbc_parallel_flag_leaves_encryption_unchanged() {
    let plaintext = sample(3 * CHUNK * BLOCK);
    let mut expected = plaintext.clone();
    Cbc::new(des(), &IV)
        .unwrap()
        .encrypt(&mut expected)
        .unwrap();

    let mut cbc = Cbc::new(des(), &IV).unwrap().parallel(true);
    let mut buffer = plaintext;
    in_pool(2, || cbc.encrypt(&mut buffer)).unwrap();
    assert_eq!(buffer, expected);
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

#[test]
fn ctr_parallel_matches_sequential() {
    // Whole blocks, then lengths that end in a partial block.
    let lengths = PAR_BLOCKS
        .map(|blocks| blocks * BLOCK)
        .into_iter()
        .chain([CHUNK * BLOCK + 3, (2 * CHUNK + 7) * BLOCK + 5]);
    for len in lengths {
        let plaintext = sample(len);
        let mut expected = plaintext.clone();
        Ctr::new(des(), &IV)
            .unwrap()
            .apply_keystream(&mut expected)
            .unwrap();

        for threads in POOLS {
            let mut ctr = Ctr::new(des(), &IV).unwrap().parallel(true);
            let mut buffer = plaintext.clone();
            in_pool(threads, || ctr.apply_keystream(&mut buffer)).unwrap();
            assert_eq!(buffer, expected, "length {len}, {threads} threads");
        }
    }
}

/// The second call has to start from the counter the parallel first call left.
/// A partial last block still ends the message.
#[test]
fn ctr_parallel_keeps_the_counter_between_calls() {
    let len = (3 * CHUNK + 2) * BLOCK + 3;
    let plaintext = sample(len);
    let mut expected = plaintext.clone();
    Ctr::new(des(), &IV)
        .unwrap()
        .apply_keystream(&mut expected)
        .unwrap();

    for split in [CHUNK + 5, 2 * CHUNK] {
        let mut ctr = Ctr::new(des(), &IV).unwrap().parallel(true);
        let mut buffer = plaintext.clone();
        let (first, second) = buffer.split_at_mut(split * BLOCK);
        in_pool(2, || {
            ctr.apply_keystream(first)?;
            ctr.apply_keystream(second)
        })
        .unwrap();
        assert_eq!(buffer, expected, "split at block {split}");
        assert_eq!(
            ctr.apply_keystream(&mut [0; 8]),
            Err(ModeError::DataAfterPartialBlock),
            "split at block {split}"
        );
    }
}

/// The counter wraps from `FF..FF` to zero in the middle of the second piece.
#[test]
fn ctr_parallel_counter_wraps_across_pieces() {
    let start = (u64::MAX - (CHUNK + CHUNK / 2) as u64 + 1).to_be_bytes();
    let plaintext = sample(3 * CHUNK * BLOCK);
    let mut expected = plaintext.clone();
    Ctr::new(des(), &start)
        .unwrap()
        .apply_keystream(&mut expected)
        .unwrap();

    let mut ctr = Ctr::new(des(), &start).unwrap().parallel(true);
    let mut buffer = plaintext;
    in_pool(3, || ctr.apply_keystream(&mut buffer)).unwrap();
    assert_eq!(buffer, expected);
}

#[test]
fn add_carries_and_wraps() {
    let cases: [([u8; 4], u64, [u8; 4]); 5] = [
        ([0, 0, 0, 0], 0, [0, 0, 0, 0]),
        ([0, 0, 0, 0xFE], 1, [0, 0, 0, 0xFF]),
        ([0, 0, 0xFF, 0xFF], 1, [0, 1, 0, 0]),
        ([0, 0, 0x12, 0x34], 0x0102, [0, 0, 0x13, 0x36]),
        ([0xFF, 0xFF, 0xFF, 0xF0], 0x1_0000_0020, [0, 0, 0, 0x10]),
    ];
    for (start, n, expected) in cases {
        let mut counter = start;
        add(&mut counter, n);
        assert_eq!(counter, expected, "{start:02X?} + {n:#x}");
    }
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
