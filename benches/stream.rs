//! Benchmarks of file encryption and decryption through the stream layer, and of
//! the file reads and writes it performs, without the cipher.
//!
//! Groups, over each of the shared input sizes with the default 1 MiB buffer
//! unless stated otherwise:
//! - `io`: `read` reads a file through the buffer and discards it, and `write`
//!   writes the bytes through [`AtomicFile`] and commits. This is the I/O time.
//! - `file-encrypt` and `file-decrypt`: ECB and CBC with PKCS#7, and CTR, from one
//!   file to another the same way the `oes` binary does it. This is the total
//!   time. The container header is not written, since at a few dozen bytes it has
//!   no measurable cost.
//! - `buffer-size`: CBC file encryption and decryption of a fixed 10 MiB file with
//!   buffers from 4 KiB to 8 MiB. The buffer size in KiB is the benchmark
//!   parameter, and no throughput is set.
//!
//! All files are in a temporary directory that is removed afterwards. Input reads
//! can be served from the operating system's file cache. Every output file is
//! synced to the drive on commit, as in the `oes` binary, so the write, file
//! encryption, file decryption and buffer-size timings include the sync.
//!
//! DES and ECB are insecure and must not be used to protect real data.

mod common;
#[path = "../src/stream/test_util.rs"]
#[allow(dead_code)]
mod test_util;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use common::{IV, KEY, SIZES, id, payload, set_size, size_group};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use oes::ciphers::des::DesCipher;
use oes::ciphers::traits::KeyInit;
use oes::modes::{Cbc, Ctr, Ecb};
use oes::padding::Padding;
use oes::stream::{
    AtomicFile, DEFAULT_BUFFER_SIZE, apply_ctr_stream, decrypt_stream, encrypt_stream,
};
use test_util::TempDir;

#[derive(Clone, Copy)]
enum Mode {
    Ecb,
    Cbc,
    Ctr,
}

const MODES: [Mode; 3] = [Mode::Ecb, Mode::Cbc, Mode::Ctr];

/// The file size of the `buffer-size` group.
const BUFFER_GROUP_FILE_SIZE: usize = 10 << 20;

/// The buffer sizes of the `buffer-size` group, from a small 4 KiB buffer to most
/// of the file.
const BUFFER_SIZES: [usize; 4] = [4 << 10, 64 << 10, 1 << 20, 8 << 20];

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Ecb => "ecb",
            Mode::Cbc => "cbc",
            Mode::Ctr => "ctr",
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// Encrypts or decrypts `input` into `output`, as the `oes` binary does: a new
/// mode, `File::open`, then an [`AtomicFile`] that is committed at the end.
fn crypt_file(mode: Mode, direction: Direction, input: &Path, output: &Path, buf_size: usize) {
    let mut reader = File::open(input).unwrap();
    let mut writer = AtomicFile::create(output, true).unwrap();
    let padding = Padding::Pkcs7;
    match (mode, direction) {
        (Mode::Ecb, Direction::Encrypt) => {
            let mut ecb = Ecb::new(DesCipher::new(&KEY));
            encrypt_stream(&mut ecb, padding, &mut reader, &mut writer, buf_size)
        }
        (Mode::Ecb, Direction::Decrypt) => {
            let mut ecb = Ecb::new(DesCipher::new(&KEY));
            decrypt_stream(&mut ecb, padding, &mut reader, &mut writer, buf_size)
        }
        (Mode::Cbc, Direction::Encrypt) => {
            let mut cbc = Cbc::new(DesCipher::new(&KEY), &IV).unwrap();
            encrypt_stream(&mut cbc, padding, &mut reader, &mut writer, buf_size)
        }
        (Mode::Cbc, Direction::Decrypt) => {
            let mut cbc = Cbc::new(DesCipher::new(&KEY), &IV).unwrap();
            decrypt_stream(&mut cbc, padding, &mut reader, &mut writer, buf_size)
        }
        (Mode::Ctr, _) => {
            let mut ctr = Ctr::new(DesCipher::new(&KEY), &IV).unwrap();
            apply_ctr_stream(&mut ctr, &mut reader, &mut writer, buf_size)
        }
    }
    .unwrap();
    writer.commit().unwrap();
}

fn io(c: &mut Criterion) {
    let mut group = size_group(c, "io");
    for size in SIZES {
        let label = set_size(&mut group, size);
        let dir = TempDir::new("bench-io");
        let input = dir.path().join("input");
        let output = dir.path().join("output");
        let data = payload(size);
        fs::write(&input, &data).unwrap();

        group.bench_function(id("read", &label), |b| {
            let mut buf = vec![0; DEFAULT_BUFFER_SIZE];
            b.iter(|| {
                let mut file = File::open(&input).unwrap();
                while file.read(&mut buf).unwrap() != 0 {}
            })
        });
        group.bench_function(id("write", &label), |b| {
            b.iter(|| {
                let mut file = AtomicFile::create(&output, true).unwrap();
                for chunk in data.chunks(DEFAULT_BUFFER_SIZE) {
                    file.write_all(chunk).unwrap();
                }
                file.commit().unwrap();
            })
        });
    }
    group.finish();
}

fn file_crypt(c: &mut Criterion, group_name: &str, direction: Direction) {
    let mut group = size_group(c, group_name);
    for size in SIZES {
        let label = set_size(&mut group, size);
        let dir = TempDir::new("bench-file");
        let plaintext = dir.path().join("plaintext");
        let output = dir.path().join("output");
        fs::write(&plaintext, payload(size)).unwrap();

        for mode in MODES {
            let input = match direction {
                Direction::Encrypt => plaintext.clone(),
                // Decryption needs a valid ciphertext, made once, outside the timing.
                Direction::Decrypt => {
                    let ciphertext = dir.path().join(mode.name());
                    crypt_file(
                        mode,
                        Direction::Encrypt,
                        &plaintext,
                        &ciphertext,
                        DEFAULT_BUFFER_SIZE,
                    );
                    ciphertext
                }
            };
            group.bench_function(id(mode.name(), &label), |b| {
                b.iter(|| crypt_file(mode, direction, &input, &output, DEFAULT_BUFFER_SIZE))
            });
        }
    }
    group.finish();
}

fn file_encrypt(c: &mut Criterion) {
    file_crypt(c, "file-encrypt", Direction::Encrypt);
}

fn file_decrypt(c: &mut Criterion) {
    file_crypt(c, "file-decrypt", Direction::Decrypt);
}

fn buffer_size(c: &mut Criterion) {
    // No throughput: it would place every point at the same file size, and the
    // chart needs the buffer size on its x axis instead.
    let mut group = size_group(c, "buffer-size");
    let dir = TempDir::new("bench-buffer");
    let plaintext = dir.path().join("plaintext");
    let ciphertext = dir.path().join("ciphertext");
    let output = dir.path().join("output");
    fs::write(&plaintext, payload(BUFFER_GROUP_FILE_SIZE)).unwrap();
    crypt_file(
        Mode::Cbc,
        Direction::Encrypt,
        &plaintext,
        &ciphertext,
        DEFAULT_BUFFER_SIZE,
    );

    for buf_size in BUFFER_SIZES {
        // A plain number in KiB, so that the chart can use it as the x value.
        let kib = buf_size >> 10;
        group.bench_function(BenchmarkId::new("cbc-encrypt", kib), |b| {
            b.iter(|| crypt_file(Mode::Cbc, Direction::Encrypt, &plaintext, &output, buf_size))
        });
        group.bench_function(BenchmarkId::new("cbc-decrypt", kib), |b| {
            b.iter(|| {
                crypt_file(
                    Mode::Cbc,
                    Direction::Decrypt,
                    &ciphertext,
                    &output,
                    buf_size,
                )
            })
        });
    }
    group.finish();
}

criterion_group!(benches, io, file_encrypt, file_decrypt, buffer_size);
criterion_main!(benches);
