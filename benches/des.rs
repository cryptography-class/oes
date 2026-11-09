//! Benchmarks of the DES cipher and its modes in memory, with no file I/O: the
//! time spent on cryptography alone. RustCrypto's `des`, `ecb`, `cbc` and `ctr`
//! run next to ours as the reference.
//!
//! Groups:
//! - `des-block`: one block encrypted and decrypted, and the key schedule. This is
//!   the baseline for DES optimizations.
//! - `mode-encrypt` and `mode-decrypt`: ECB, CBC and CTR over 1, 10 and 100 MiB,
//!   with one line per implementation on the summary chart.
//!
//! Run with `cargo bench --bench des`, or one group with a filter such as
//! `cargo bench --bench des -- mode-encrypt/cbc`. To keep a baseline and compare
//! against it later:
//!
//! ```text
//! cargo bench -- --save-baseline before-des-opt
//! cargo bench -- --baseline before-des-opt
//! ```
//!
//! The report is `target/criterion/report/index.html`. Each size group's page has
//! a line chart of time against input size and a throughput chart, and each
//! benchmark's page shows its distribution, overlaid with the baseline once one
//! exists.
//!
//! Windows throttles background processes, and a child process doesn't inherit
//! Above Normal priority from `start`. So for numbers worth keeping, build with
//! `cargo bench --no-run`, which prints the bench executable's path, and run that
//! executable from the repository root:
//!
//! ```text
//! start /abovenormal /wait /b target\release\deps\des-<hash>.exe --bench --save-baseline <name>
//! ```
//!
//! DES and ECB are here to be measured. They must not protect real data.

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

    let ours = DesCipher::new(&KEY);
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK);
            ours.encrypt_block(&mut block);
            block
        })
    });
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK);
            ours.decrypt_block(&mut block);
            block
        })
    });
    // Includes dropping the cipher, which wipes the round keys.
    group.bench_function("key-schedule", |b| {
        b.iter(|| DesCipher::new(black_box(&KEY)))
    });

    let theirs = <des::Des as des::cipher::KeyInit>::new(&KEY.into());
    group.bench_function("rustcrypto-encrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK.to_be_bytes()).into();
            theirs.encrypt_block(&mut block);
            block
        })
    });
    group.bench_function("rustcrypto-decrypt", |b| {
        b.iter(|| {
            let mut block = black_box(BLOCK.to_be_bytes()).into();
            theirs.decrypt_block(&mut block);
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
