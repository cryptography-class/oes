//! Benchmarks of the DES cipher and its modes in memory, with no file I/O: the
//! time spent on cryptography alone. The RustCrypto crates `des`, `ecb`, `cbc` and
//! `ctr` are benchmarked alongside as the reference implementation, under names
//! prefixed with `rustcrypto-`.
//!
//! Groups:
//! - `des-block`: encryption and decryption of one block, and the key schedule.
//! - `mode-encrypt` and `mode-decrypt`: ECB, CBC and CTR over each of the shared
//!   input sizes, in place on one buffer.
//!
//! DES and ECB are insecure and must not be used to protect real data.

mod common;

use std::hint::black_box;

use common::{IV, KEY, SIZES, id, payload, set_size, size_group};
use criterion::measurement::WallTime;
use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use des::cipher::block_padding::NoPadding;
use des::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    StreamCipher,
};
use oes::ciphers::des::DesCipher;
use oes::ciphers::traits::{BlockCipher, KeyInit};
use oes::modes::{Cbc, Ctr, Ecb};

/// The block that the single-block benchmarks start from.
const BLOCK: u64 = 0x0123_4567_89AB_CDEF;

fn des_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("des-block");

    let cipher = DesCipher::new(&KEY);
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK);
            cipher.encrypt_block(&mut block);
            block
        })
    });
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK);
            cipher.decrypt_block(&mut block);
            block
        })
    });
    // Includes dropping the cipher, which wipes the round keys.
    group.bench_function("key-schedule", |b| {
        b.iter(|| DesCipher::new(black_box(&KEY)))
    });

    let reference = <des::Des as des::cipher::KeyInit>::new(&KEY.into());
    group.bench_function("rustcrypto-encrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK.to_be_bytes()).into();
            reference.encrypt_block(&mut block);
            block
        })
    });
    group.bench_function("rustcrypto-decrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK.to_be_bytes()).into();
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

fn mode_encrypt(c: &mut Criterion) {
    let mut group = size_group(c, "mode-encrypt");
    for size in SIZES {
        let label = set_size(&mut group, size);
        let buf = &mut payload(size);

        bench_in_place(
            &mut group,
            "ecb",
            &label,
            buf,
            || Ecb::new(DesCipher::new(&KEY)),
            |mode, data| mode.encrypt(data).unwrap(),
        );
        bench_in_place(
            &mut group,
            "cbc",
            &label,
            buf,
            || Cbc::new(DesCipher::new(&KEY), &IV).unwrap(),
            |mut mode, data| mode.encrypt(data).unwrap(),
        );
        bench_in_place(
            &mut group,
            "ctr",
            &label,
            buf,
            || Ctr::new(DesCipher::new(&KEY), &IV).unwrap(),
            |mut mode, data| mode.apply_keystream(data).unwrap(),
        );

        bench_in_place(
            &mut group,
            "rustcrypto-ecb",
            &label,
            buf,
            || <ecb::Encryptor<des::Des> as des::cipher::KeyInit>::new(&KEY.into()),
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
            || cbc::Encryptor::<des::Des>::new(&KEY.into(), &IV.into()),
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
            || ctr::Ctr64BE::<des::Des>::new(&KEY.into(), &IV.into()),
            |mut mode, data| mode.apply_keystream(data),
        );
    }
    group.finish();
}

fn mode_decrypt(c: &mut Criterion) {
    let mut group = size_group(c, "mode-decrypt");
    for size in SIZES {
        let label = set_size(&mut group, size);
        let buf = &mut payload(size);

        bench_in_place(
            &mut group,
            "ecb",
            &label,
            buf,
            || Ecb::new(DesCipher::new(&KEY)),
            |mode, data| mode.decrypt(data).unwrap(),
        );
        bench_in_place(
            &mut group,
            "cbc",
            &label,
            buf,
            || Cbc::new(DesCipher::new(&KEY), &IV).unwrap(),
            |mut mode, data| mode.decrypt(data).unwrap(),
        );
        // CTR decryption is the same operation as encryption.
        bench_in_place(
            &mut group,
            "ctr",
            &label,
            buf,
            || Ctr::new(DesCipher::new(&KEY), &IV).unwrap(),
            |mut mode, data| mode.apply_keystream(data).unwrap(),
        );

        bench_in_place(
            &mut group,
            "rustcrypto-ecb",
            &label,
            buf,
            || <ecb::Decryptor<des::Des> as des::cipher::KeyInit>::new(&KEY.into()),
            |mode, data| {
                mode.decrypt_padded::<NoPadding>(data).unwrap();
            },
        );
        bench_in_place(
            &mut group,
            "rustcrypto-cbc",
            &label,
            buf,
            || cbc::Decryptor::<des::Des>::new(&KEY.into(), &IV.into()),
            |mode, data| {
                mode.decrypt_padded::<NoPadding>(data).unwrap();
            },
        );
        bench_in_place(
            &mut group,
            "rustcrypto-ctr",
            &label,
            buf,
            || ctr::Ctr64BE::<des::Des>::new(&KEY.into(), &IV.into()),
            |mut mode, data| mode.apply_keystream(data),
        );
    }
    group.finish();
}

criterion_group!(benches, des_block, mode_encrypt, mode_decrypt);
criterion_main!(benches);
