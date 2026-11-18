//! Benchmarks of the AES cipher and its modes in memory, with no file I/O: the
//! time spent on cryptography alone. The RustCrypto crates `aes`, `ecb`, `cbc`,
//! `ctr` and `aes-gcm` are benchmarked alongside as the reference implementation,
//! under names prefixed with `rustcrypto-`, and they select their own backend. The other
//! lines use AES-NI on x86 and x86-64 processors that have it, and the table-based
//! implementation everywhere else. Building without the `aes-ni` feature selects the
//! table-based implementation for those lines only. In the `gcm` lines, GHASH uses
//! `PCLMULQDQ` when the processor has it, unless built without the `pclmulqdq` feature.
//!
//! Groups:
//! - `aes-block`: encryption and decryption of one block, and the key schedule,
//!   for each key size.
//! - `aes-mode-encrypt` and `aes-mode-decrypt`: AES-128 in ECB, CBC and CTR over
//!   each of the shared input sizes, in place on one buffer. GCM runs with AES-128
//!   and AES-256 (`gcm-256`), and is only in `aes-mode-encrypt`: decryption does the
//!   same work, and the in-place buffer would no longer match its tag after the
//!   first run.
//!
//! ECB is insecure and must not be used to protect real data.

#[expect(dead_code, reason = "the DES key and IV are for the other benchmarks")]
mod common;

use std::hint::black_box;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    StreamCipher,
};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use common::{SIZES, id, payload, set_size, size_group};
use criterion::measurement::WallTime;
use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use oes::ciphers::aes::{Aes128Cipher, Aes192Cipher, Aes256Cipher};
use oes::ciphers::traits::KeyInit;
use oes::modes::{Cbc, Ctr, Ecb, GcmEncryptor};

/// A fixed key and IV: the 256-bit key of NIST SP 800-38A Appendix F, whose first
/// 16 or 24 bytes key AES-128 and AES-192, and the IV from the same appendix.
/// Benchmarks never protect real data, so a constant key and a reused IV are
/// acceptable here and nowhere else.
const KEY: [u8; 32] = [
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4,
];
const IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];

/// The GCM nonce: the first 12 bytes of [`IV`], with the same caveat.
const NONCE: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
];

/// The block that the single-block benchmarks start from (FIPS 197 Appendix C).
const BLOCK: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

/// Returns the first `N` bytes of [`KEY`].
fn key<const N: usize>() -> [u8; N] {
    std::array::from_fn(|i| KEY[i])
}

/// Benchmarks encryption, decryption and the key schedule of one key size, named
/// `encrypt-<bits>`, `decrypt-<bits>` and `key-schedule-<bits>`.
fn bench_key_size<C: KeyInit<N, Block = [u8; 16]>, const N: usize>(
    group: &mut BenchmarkGroup<'_, WallTime>,
) {
    let bits = N * 8;
    let key = key::<N>();
    let cipher = C::new(&key);
    group.bench_function(format!("encrypt-{bits}"), |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK);
            cipher.encrypt_block(&mut block);
            block
        })
    });
    group.bench_function(format!("decrypt-{bits}"), |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK);
            cipher.decrypt_block(&mut block);
            block
        })
    });
    // Includes dropping the cipher, which wipes the key schedule.
    group.bench_function(format!("key-schedule-{bits}"), |b| {
        b.iter(|| C::new(black_box(&key)))
    });
}

fn aes_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-block");
    bench_key_size::<Aes128Cipher, 16>(&mut group);
    bench_key_size::<Aes192Cipher, 24>(&mut group);
    bench_key_size::<Aes256Cipher, 32>(&mut group);

    let reference = <aes::Aes128 as aes::cipher::KeyInit>::new(&key::<16>().into());
    group.bench_function("rustcrypto-encrypt-128", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK).into();
            reference.encrypt_block(&mut block);
            block
        })
    });
    group.bench_function("rustcrypto-decrypt-128", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK).into();
            reference.decrypt_block(&mut block);
            block
        })
    });

    group.finish();
}

/// Benchmarks `routine` on `buf` in place, with a new mode from `setup` for each
/// run.
///
/// Building the mode stays outside the timing, and so does making the input:
/// the buffer is encrypted or decrypted again on each run, which costs the same
/// every time.
fn bench_in_place<M>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    function: &str,
    label: &str,
    buf: &mut [u8],
    mut setup: impl FnMut() -> M,
    mut routine: impl FnMut(M, &mut [u8]),
) {
    group.bench_function(id(function, label), |b| {
        b.iter_batched(
            &mut setup,
            |mode| routine(mode, black_box(&mut *buf)),
            BatchSize::SmallInput,
        )
    });
}

fn aes_mode_encrypt(c: &mut Criterion) {
    let mut group = size_group(c, "aes-mode-encrypt");
    let key_256 = key::<32>();
    let key = key::<16>();
    for size in SIZES {
        let label = set_size(&mut group, size);
        let buf = &mut payload(size);

        bench_in_place(
            &mut group,
            "ecb",
            &label,
            buf,
            || Ecb::new(Aes128Cipher::new(&key)),
            |mode, data| mode.encrypt(data).unwrap(),
        );
        bench_in_place(
            &mut group,
            "cbc",
            &label,
            buf,
            || Cbc::new(Aes128Cipher::new(&key), &IV).unwrap(),
            |mut mode, data| mode.encrypt(data).unwrap(),
        );
        bench_in_place(
            &mut group,
            "ctr",
            &label,
            buf,
            || Ctr::new(Aes128Cipher::new(&key), &IV).unwrap(),
            |mut mode, data| mode.apply_keystream(data).unwrap(),
        );
        bench_in_place(
            &mut group,
            "gcm",
            &label,
            buf,
            || GcmEncryptor::new(Aes128Cipher::new(&key), &NONCE, &[]).unwrap(),
            |mut mode, data| {
                mode.update(data).unwrap();
                black_box(mode.finish());
            },
        );
        bench_in_place(
            &mut group,
            "gcm-256",
            &label,
            buf,
            || GcmEncryptor::new(Aes256Cipher::new(&key_256), &NONCE, &[]).unwrap(),
            |mut mode, data| {
                mode.update(data).unwrap();
                black_box(mode.finish());
            },
        );

        bench_in_place(
            &mut group,
            "rustcrypto-ecb",
            &label,
            buf,
            || <ecb::Encryptor<aes::Aes128> as aes::cipher::KeyInit>::new(&key.into()),
            |mode, data| {
                let len = data.len();
                mode.encrypt_padded::<NoPadding>(data, len).unwrap();
            },
        );
        bench_in_place(
            &mut group,
            "rustcrypto-cbc",
            &label,
            buf,
            || cbc::Encryptor::<aes::Aes128>::new(&key.into(), &IV.into()),
            |mode, data| {
                let len = data.len();
                mode.encrypt_padded::<NoPadding>(data, len).unwrap();
            },
        );
        bench_in_place(
            &mut group,
            "rustcrypto-ctr",
            &label,
            buf,
            || ctr::Ctr128BE::<aes::Aes128>::new(&key.into(), &IV.into()),
            |mut mode, data| mode.apply_keystream(data),
        );
        bench_in_place(
            &mut group,
            "rustcrypto-gcm",
            &label,
            buf,
            || <Aes128Gcm as aes_gcm::KeyInit>::new(&key.into()),
            |mode, data| {
                let tag = mode.encrypt_inout_detached(&NONCE.into(), &[], data.into());
                black_box(tag.unwrap());
            },
        );
        bench_in_place(
            &mut group,
            "rustcrypto-gcm-256",
            &label,
            buf,
            || <Aes256Gcm as aes_gcm::KeyInit>::new(&key_256.into()),
            |mode, data| {
                let tag = mode.encrypt_inout_detached(&NONCE.into(), &[], data.into());
                black_box(tag.unwrap());
            },
        );
    }
    group.finish();
}

fn aes_mode_decrypt(c: &mut Criterion) {
    let mut group = size_group(c, "aes-mode-decrypt");
    let key = key::<16>();
    for size in SIZES {
        let label = set_size(&mut group, size);
        let buf = &mut payload(size);

        bench_in_place(
            &mut group,
            "ecb",
            &label,
            buf,
            || Ecb::new(Aes128Cipher::new(&key)),
            |mode, data| mode.decrypt(data).unwrap(),
        );
        bench_in_place(
            &mut group,
            "cbc",
            &label,
            buf,
            || Cbc::new(Aes128Cipher::new(&key), &IV).unwrap(),
            |mut mode, data| mode.decrypt(data).unwrap(),
        );
        // CTR decryption is the same operation as encryption.
        bench_in_place(
            &mut group,
            "ctr",
            &label,
            buf,
            || Ctr::new(Aes128Cipher::new(&key), &IV).unwrap(),
            |mut mode, data| mode.apply_keystream(data).unwrap(),
        );

        bench_in_place(
            &mut group,
            "rustcrypto-ecb",
            &label,
            buf,
            || <ecb::Decryptor<aes::Aes128> as aes::cipher::KeyInit>::new(&key.into()),
            |mode, data| {
                mode.decrypt_padded::<NoPadding>(data).unwrap();
            },
        );
        bench_in_place(
            &mut group,
            "rustcrypto-cbc",
            &label,
            buf,
            || cbc::Decryptor::<aes::Aes128>::new(&key.into(), &IV.into()),
            |mode, data| {
                mode.decrypt_padded::<NoPadding>(data).unwrap();
            },
        );
        bench_in_place(
            &mut group,
            "rustcrypto-ctr",
            &label,
            buf,
            || ctr::Ctr128BE::<aes::Aes128>::new(&key.into(), &IV.into()),
            |mut mode, data| mode.apply_keystream(data),
        );
    }
    group.finish();
}

criterion_group!(benches, aes_block, aes_mode_encrypt, aes_mode_decrypt);
criterion_main!(benches);
