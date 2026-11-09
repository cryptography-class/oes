use std::fs;
use std::io::{self, Cursor, ErrorKind, Read, Write};

use super::errors::StreamError;
use super::io_util::{aligned_capacity, read_full};
use super::test_util::TempDir;
use super::{AtomicFile, DEFAULT_BUFFER_SIZE, apply_ctr_stream, decrypt_stream, encrypt_stream};
use crate::ciphers::des::DesCipher;
use crate::ciphers::traits::KeyInit;
use crate::modes::errors::ModeError;
use crate::modes::{BlockMode, Cbc, Ctr, Ecb};
use crate::padding::errors::PaddingError;
use crate::padding::{Fill, Padding};

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
// FIPS 81 stops at the third block. The PKCS#7 padding block that follows was
// computed with OpenSSL 3.5 (`openssl enc -des-ecb` and `-des-cbc`, same key and
// IV), whose first three blocks match the FIPS 81 tables.
const ECB_PADDING_BLOCK: [u8; 8] = [0x08, 0x6F, 0x9A, 0x1D, 0x74, 0xC9, 0x4D, 0x4E];
const CBC_PADDING_BLOCK: [u8; 8] = [0x62, 0xC1, 0x6A, 0x27, 0xE4, 0xFC, 0xF2, 0x77];

const ALL_PADDINGS: [Padding; 4] = [
    Padding::Pkcs7,
    Padding::Pkcs5,
    Padding::AnsiX923(Fill::Zeros),
    Padding::AnsiX923(Fill::Random),
];
const LENS: [usize; 11] = [0, 1, 7, 8, 9, 16, 63, 64, 65, 256, 1025];
const BUF_SIZES: [usize; 6] = [0, 8, 9, 24, 64, 1000];
const READ_LIMITS: [usize; 3] = [1, 3, usize::MAX];

#[derive(Clone, Copy, Debug)]
enum Kind {
    Ecb,
    Cbc,
}
const KINDS: [Kind; 2] = [Kind::Ecb, Kind::Cbc];

fn des_mode(kind: Kind) -> Box<dyn BlockMode> {
    let cipher = DesCipher::new(&KEY);
    match kind {
        Kind::Ecb => Box::new(Ecb::new(cipher)),
        Kind::Cbc => Box::new(Cbc::new(cipher, &IV).unwrap()),
    }
}

fn des_ctr() -> Ctr<DesCipher> {
    Ctr::new(DesCipher::new(&KEY), &IV).unwrap()
}

/// The FIPS 81 ciphertexts followed by their padding blocks.
fn padded_known_answers() -> [(Kind, Vec<u8>); 2] {
    [
        (
            Kind::Ecb,
            [&ECB_CIPHERTEXT[..], &ECB_PADDING_BLOCK].concat(),
        ),
        (
            Kind::Cbc,
            [&CBC_CIPHERTEXT[..], &CBC_PADDING_BLOCK].concat(),
        ),
    ]
}

fn sample_byte(i: u64) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 3)) as u8
}

fn sample(len: usize) -> Vec<u8> {
    (0..len as u64).map(sample_byte).collect()
}

fn encrypted(kind: Kind, padding: Padding, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(
        &mut *des_mode(kind),
        padding,
        &mut Cursor::new(data),
        &mut out,
        64,
    )
    .unwrap();
    out
}

fn decrypted(kind: Kind, padding: Padding, data: &[u8]) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    decrypt_stream(
        &mut *des_mode(kind),
        padding,
        &mut Cursor::new(data),
        &mut out,
        16,
    )?;
    Ok(out)
}

/// Hands out at most `limit` bytes per call, as a real reader may.
struct LimitedReader<R> {
    inner: R,
    limit: usize,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.limit);
        self.inner.read(&mut buf[..n])
    }
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct MustNotRead;

impl Read for MustNotRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("the input must not be touched when the parameters are invalid");
    }
}

/// A stand-in mode with 16-byte blocks, to show nothing assumes the DES block size.
struct Xor16;

impl Xor16 {
    fn apply(data: &mut [u8]) -> Result<(), ModeError> {
        if !data.len().is_multiple_of(16) {
            return Err(ModeError::InvalidLength {
                len: data.len(),
                block_size: 16,
            });
        }
        data.iter_mut().for_each(|byte| *byte ^= 0x5A);
        Ok(())
    }
}

impl BlockMode for Xor16 {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        Self::apply(data)
    }

    fn decrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        Self::apply(data)
    }
}

// ---- read_full ----

#[test]
fn read_full_fills_the_buffer_across_short_reads() {
    let data = sample(10);
    let mut reader = LimitedReader {
        inner: Cursor::new(&data),
        limit: 1,
    };
    let mut buf = [0u8; 8];

    assert_eq!(read_full(&mut reader, &mut buf).unwrap(), 8);
    assert_eq!(buf, data[..8]);
    assert_eq!(read_full(&mut reader, &mut buf).unwrap(), 2);
    assert_eq!(read_full(&mut reader, &mut buf).unwrap(), 0);
}

#[test]
fn read_full_retries_an_interrupted_read() {
    struct InterruptedOnce(bool);

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                buf[0] = 7;
                return Ok(1);
            }
            self.0 = true;
            Err(ErrorKind::Interrupted.into())
        }
    }

    let mut buf = [0u8; 2];
    assert_eq!(read_full(&mut InterruptedOnce(false), &mut buf).unwrap(), 2);
    assert_eq!(buf, [7, 7]);
}

#[test]
fn read_full_returns_other_errors() {
    let err = read_full(&mut FailingReader, &mut [0u8; 8]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Other);
}

// ---- aligned_capacity ----

#[test]
fn aligned_capacity_rounds_down_with_a_minimum_of_one_block() {
    assert_eq!(aligned_capacity(0, 8), 8);
    assert_eq!(aligned_capacity(7, 8), 8);
    assert_eq!(aligned_capacity(8, 8), 8);
    assert_eq!(aligned_capacity(23, 8), 16);
    assert_eq!(aligned_capacity(40, 16), 32);
}

#[test]
fn aligned_capacity_caps_huge_sizes() {
    assert_eq!(aligned_capacity(usize::MAX, 8), 1 << 30);
    assert_eq!(aligned_capacity((1 << 30) + 8, 8), 1 << 30);
}

// ---- AtomicFile ----

#[test]
fn commit_publishes_the_file_and_leaves_no_temp_file() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");

    let mut file = AtomicFile::create(&target, false).unwrap();
    file.write_all(b"hello").unwrap();
    assert!(!target.exists(), "the target must not exist before commit");
    assert_eq!(
        dir.entries().len(),
        1,
        "the temp file sits next to the target"
    );
    file.commit().unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"hello");
    assert_eq!(dir.entries(), ["out.bin"]);
}

#[test]
fn drop_without_commit_leaves_nothing() {
    let dir = TempDir::new("atomic");

    let mut file = AtomicFile::create(dir.path().join("out.bin"), false).unwrap();
    file.write_all(b"partial").unwrap();
    drop(file);

    assert!(dir.entries().is_empty());
}

#[test]
fn drop_without_commit_keeps_the_old_target() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");
    fs::write(&target, b"old").unwrap();

    let mut file = AtomicFile::create(&target, true).unwrap();
    file.write_all(b"new, but never committed").unwrap();
    drop(file);

    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert_eq!(dir.entries(), ["out.bin"]);
}

#[test]
fn create_refuses_an_existing_target_unless_overwriting() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");
    fs::write(&target, b"old").unwrap();

    let err = AtomicFile::create(&target, false).err().unwrap();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&target).unwrap(), b"old");

    let mut file = AtomicFile::create(&target, true).unwrap();
    file.write_all(b"new").unwrap();
    file.commit().unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
}

#[test]
fn create_rejects_a_path_without_a_file_name() {
    // With `overwrite`, the existence check can't answer first.
    let err = AtomicFile::create("..", true).err().unwrap();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn commit_refuses_a_target_that_appeared_after_create() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");

    let file = AtomicFile::create(&target, false).unwrap();
    fs::write(&target, b"someone else's").unwrap();

    let err = file.commit().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&target).unwrap(), b"someone else's");
    assert_eq!(dir.entries(), ["out.bin"]);
}

#[cfg(unix)]
#[test]
fn create_private_gives_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new("atomic");
    let target = dir.path().join("secret.key");
    let mut file = AtomicFile::create_private(&target, false).unwrap();
    file.write_all(b"secret").unwrap();
    file.commit().unwrap();

    let mode = fs::metadata(&target).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

// ---- encrypt_stream ----

#[test]
fn encrypt_stream_known_answer_fips_81() {
    for (kind, ciphertext) in padded_known_answers() {
        assert_eq!(
            encrypted(kind, Padding::Pkcs7, PLAINTEXT),
            ciphertext,
            "{kind:?}"
        );
    }
}

#[test]
fn encrypt_stream_output_does_not_depend_on_buffer_or_read_sizes() {
    let padding = Padding::Pkcs7;
    for kind in KINDS {
        for len in LENS {
            let data = sample(len);
            let mut expected = data.clone();
            padding.pad(&mut expected, 8).unwrap();
            des_mode(kind).encrypt_blocks(&mut expected).unwrap();

            for buf_size in BUF_SIZES {
                for limit in READ_LIMITS {
                    let mut reader = LimitedReader {
                        inner: Cursor::new(&data),
                        limit,
                    };
                    let mut out = Vec::new();
                    encrypt_stream(
                        &mut *des_mode(kind),
                        padding,
                        &mut reader,
                        &mut out,
                        buf_size,
                    )
                    .unwrap();
                    assert_eq!(
                        out, expected,
                        "{kind:?} len {len} buf_size {buf_size} limit {limit}"
                    );
                }
            }
        }
    }
}

#[test]
fn encrypt_stream_reports_io_failures() {
    let mut mode = des_mode(Kind::Ecb);
    let result = encrypt_stream(
        &mut *mode,
        Padding::Pkcs7,
        &mut FailingReader,
        &mut Vec::new(),
        64,
    );
    assert!(matches!(result, Err(StreamError::Io(_))), "{result:?}");

    let mut input = Cursor::new(sample(100));
    let result = encrypt_stream(
        &mut *mode,
        Padding::Pkcs7,
        &mut input,
        &mut FailingWriter,
        64,
    );
    assert!(matches!(result, Err(StreamError::Io(_))), "{result:?}");
}

#[test]
fn encrypt_stream_rejects_pkcs5_on_other_block_sizes_before_reading() {
    let result = encrypt_stream(
        &mut Xor16,
        Padding::Pkcs5,
        &mut MustNotRead,
        &mut Vec::new(),
        64,
    );
    assert!(
        matches!(
            result,
            Err(StreamError::Padding(PaddingError::Pkcs5RequiresBlock8(16)))
        ),
        "{result:?}"
    );
}

// ---- decrypt_stream ----

#[test]
fn decrypt_stream_known_answer_fips_81() {
    for (kind, ciphertext) in padded_known_answers() {
        assert_eq!(
            decrypted(kind, Padding::Pkcs7, &ciphertext).unwrap(),
            PLAINTEXT,
            "{kind:?}"
        );
    }
}

#[test]
fn decrypt_stream_restores_every_mode_padding_length_and_buffer_size() {
    for kind in KINDS {
        for padding in ALL_PADDINGS {
            for len in LENS {
                for buf_size in BUF_SIZES {
                    let context = format!("{kind:?} {padding:?} len {len} buf_size {buf_size}");
                    let data = sample(len);

                    let mut ciphertext = Vec::new();
                    let counts = encrypt_stream(
                        &mut *des_mode(kind),
                        padding,
                        &mut Cursor::new(&data),
                        &mut ciphertext,
                        buf_size,
                    )
                    .unwrap();
                    assert_eq!(ciphertext.len(), (len / 8 + 1) * 8, "{context}");
                    assert_eq!(counts.bytes_in, len as u64, "{context}");
                    assert_eq!(counts.bytes_out, ciphertext.len() as u64, "{context}");

                    let mut plaintext = Vec::new();
                    let counts = decrypt_stream(
                        &mut *des_mode(kind),
                        padding,
                        &mut Cursor::new(&ciphertext),
                        &mut plaintext,
                        buf_size,
                    )
                    .unwrap();
                    assert_eq!(plaintext, data, "{context}");
                    assert_eq!(counts.bytes_in, ciphertext.len() as u64, "{context}");
                    assert_eq!(counts.bytes_out, len as u64, "{context}");
                }
            }
        }
    }
}

#[test]
fn decrypt_stream_handles_one_byte_reads() {
    let data = sample(300);
    for kind in KINDS {
        let ciphertext = encrypted(kind, Padding::Pkcs7, &data);
        let mut reader = LimitedReader {
            inner: Cursor::new(&ciphertext),
            limit: 1,
        };
        let mut out = Vec::new();
        decrypt_stream(
            &mut *des_mode(kind),
            Padding::Pkcs7,
            &mut reader,
            &mut out,
            40,
        )
        .unwrap();
        assert_eq!(out, data, "{kind:?}");
    }
}

#[test]
fn decrypt_stream_restores_16_byte_blocks() {
    for len in [0, 15, 16, 17, 100] {
        for buf_size in [0, 16, 40, 4096] {
            let data = sample(len);
            let mut ciphertext = Vec::new();
            encrypt_stream(
                &mut Xor16,
                Padding::Pkcs7,
                &mut Cursor::new(&data),
                &mut ciphertext,
                buf_size,
            )
            .unwrap();
            assert_eq!(
                ciphertext.len(),
                (len / 16 + 1) * 16,
                "len {len} buf_size {buf_size}"
            );

            let mut plaintext = Vec::new();
            decrypt_stream(
                &mut Xor16,
                Padding::Pkcs7,
                &mut Cursor::new(&ciphertext),
                &mut plaintext,
                buf_size,
            )
            .unwrap();
            assert_eq!(plaintext, data, "len {len} buf_size {buf_size}");
        }
    }
}

#[test]
fn decrypt_stream_rejects_truncated_and_empty_input() {
    let ciphertext = encrypted(Kind::Cbc, Padding::Pkcs7, &sample(100));
    for cut in [1, 3, 7] {
        let result = decrypted(
            Kind::Cbc,
            Padding::Pkcs7,
            &ciphertext[..ciphertext.len() - cut],
        );
        assert!(
            matches!(result, Err(StreamError::InvalidCiphertextLength { .. })),
            "cut {cut}: {result:?}"
        );
    }

    let result = decrypted(Kind::Cbc, Padding::Pkcs7, &[]);
    assert!(
        matches!(
            result,
            Err(StreamError::InvalidCiphertextLength {
                len: 0,
                block_size: 8
            })
        ),
        "{result:?}"
    );
}

#[test]
fn decrypt_stream_rejects_a_corrupted_last_block() {
    for kind in KINDS {
        let mut ciphertext = encrypted(kind, Padding::Pkcs7, &sample(100));
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let result = decrypted(kind, Padding::Pkcs7, &ciphertext);
        assert!(
            matches!(result, Err(StreamError::Padding(PaddingError::Invalid))),
            "{kind:?}: {result:?}"
        );
    }
}

#[test]
fn decrypt_stream_reports_a_wrong_key_as_invalid_padding() {
    let ciphertext = encrypted(Kind::Ecb, Padding::Pkcs7, &sample(100));
    let mut wrong_key = KEY;
    wrong_key[0] ^= 0x10;

    let mut mode = Ecb::new(DesCipher::new(&wrong_key));
    let mut input = Cursor::new(&ciphertext);
    let result = decrypt_stream(&mut mode, Padding::Pkcs7, &mut input, &mut Vec::new(), 64);
    assert!(
        matches!(result, Err(StreamError::Padding(PaddingError::Invalid))),
        "{result:?}"
    );
}

#[test]
fn decrypt_stream_rejects_pkcs5_on_other_block_sizes_before_reading() {
    let result = decrypt_stream(
        &mut Xor16,
        Padding::Pkcs5,
        &mut MustNotRead,
        &mut Vec::new(),
        64,
    );
    assert!(
        matches!(
            result,
            Err(StreamError::Padding(PaddingError::Pkcs5RequiresBlock8(16)))
        ),
        "{result:?}"
    );
}

#[test]
fn decrypt_stream_through_atomic_file_commits_on_success() {
    let dir = TempDir::new("stream");
    let target = dir.path().join("out.bin");
    let data = sample(5000);
    let ciphertext = encrypted(Kind::Cbc, Padding::Pkcs7, &data);

    let mut file = AtomicFile::create(&target, false).unwrap();
    let mut mode = des_mode(Kind::Cbc);
    decrypt_stream(
        &mut *mode,
        Padding::Pkcs7,
        &mut Cursor::new(&ciphertext),
        &mut file,
        64,
    )
    .unwrap();
    file.commit().unwrap();

    assert_eq!(fs::read(&target).unwrap(), data);
    assert_eq!(dir.entries(), ["out.bin"]);
}

#[test]
fn decrypt_stream_through_atomic_file_leaves_nothing_on_failure() {
    let dir = TempDir::new("stream");
    let mut ciphertext = encrypted(Kind::Cbc, Padding::Pkcs7, &sample(5000));
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;

    let mut file = AtomicFile::create(dir.path().join("out.bin"), false).unwrap();
    let mut mode = des_mode(Kind::Cbc);
    let result = decrypt_stream(
        &mut *mode,
        Padding::Pkcs7,
        &mut Cursor::new(&ciphertext),
        &mut file,
        64,
    );
    assert!(result.is_err());

    // Earlier chunks were fine, so plaintext did reach the temp file.
    let temp = dir.path().join(&dir.entries()[0]);
    assert!(fs::metadata(temp).unwrap().len() > 0);

    drop(file);
    assert!(dir.entries().is_empty());
}

// ---- apply_ctr_stream ----

// With a zero plaintext, the output is the encrypted counter. The DES vector is
// from "The DES Algorithm Illustrated" by J. Orlin Grabbe.
#[test]
fn apply_ctr_stream_known_answer_des_block() {
    let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
    let counter = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let mut mode = Ctr::new(DesCipher::new(&key), &counter).unwrap();
    let mut out = Vec::new();
    apply_ctr_stream(&mut mode, &mut Cursor::new([0u8; 8]), &mut out, 64).unwrap();
    assert_eq!(out, [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05]);
}

#[test]
fn apply_ctr_stream_matches_one_keystream_call_for_any_buffer_or_read_size() {
    for len in LENS {
        let data = sample(len);
        let mut expected = data.clone();
        des_ctr().apply_keystream(&mut expected).unwrap();

        for buf_size in BUF_SIZES {
            for limit in READ_LIMITS {
                let context = format!("len {len} buf_size {buf_size} limit {limit}");
                let mut reader = LimitedReader {
                    inner: Cursor::new(&data),
                    limit,
                };
                let mut out = Vec::new();
                let counts =
                    apply_ctr_stream(&mut des_ctr(), &mut reader, &mut out, buf_size).unwrap();

                assert_eq!(out, expected, "{context}");
                assert_eq!(counts.bytes_in, len as u64, "{context}");
                assert_eq!(counts.bytes_out, len as u64, "{context}");
            }
        }
    }
}

#[test]
fn apply_ctr_stream_restores_the_input_when_run_twice() {
    let data = sample(1025);

    let mut ciphertext = Vec::new();
    apply_ctr_stream(&mut des_ctr(), &mut Cursor::new(&data), &mut ciphertext, 64).unwrap();
    assert_ne!(ciphertext, data);

    let mut plaintext = Vec::new();
    apply_ctr_stream(
        &mut des_ctr(),
        &mut Cursor::new(&ciphertext),
        &mut plaintext,
        64,
    )
    .unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn apply_ctr_stream_reports_io_failures() {
    let result = apply_ctr_stream(&mut des_ctr(), &mut FailingReader, &mut Vec::new(), 64);
    assert!(matches!(result, Err(StreamError::Io(_))), "{result:?}");

    let mut input = Cursor::new(sample(100));
    let result = apply_ctr_stream(&mut des_ctr(), &mut input, &mut FailingWriter, 64);
    assert!(matches!(result, Err(StreamError::Io(_))), "{result:?}");
}

#[test]
fn apply_ctr_stream_rejects_a_mode_that_already_ended_its_message() {
    let mut mode = des_ctr();
    mode.apply_keystream(&mut [0u8; 3]).unwrap();

    let mut input = Cursor::new(sample(8));
    let result = apply_ctr_stream(&mut mode, &mut input, &mut Vec::new(), 64);
    assert!(
        matches!(
            result,
            Err(StreamError::Mode(ModeError::DataAfterPartialBlock))
        ),
        "{result:?}"
    );
}

// ---- large files ----

/// Produces `len` sample bytes without holding them in memory.
struct Generator {
    pos: u64,
    len: u64,
}

impl Read for Generator {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min((self.len - self.pos) as usize);
        for byte in &mut buf[..n] {
            *byte = sample_byte(self.pos);
            self.pos += 1;
        }
        Ok(n)
    }
}

/// Compares everything written to it with the sample bytes.
struct Verifier {
    pos: u64,
}

impl Write for Verifier {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &byte in buf {
            assert_eq!(byte, sample_byte(self.pos), "mismatch at byte {}", self.pos);
            self.pos += 1;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Slow in debug builds: `cargo test --release -- --ignored large_file`.
#[test]
#[ignore = "slow, run it in release mode"]
fn large_file_roundtrip_with_bounded_memory() {
    const LEN: u64 = 105_000_000;
    let dir = TempDir::new("large");
    let path = dir.path().join("big.enc");

    let mut file = AtomicFile::create(&path, false).unwrap();
    let counts = encrypt_stream(
        &mut *des_mode(Kind::Cbc),
        Padding::Pkcs7,
        &mut Generator { pos: 0, len: LEN },
        &mut file,
        DEFAULT_BUFFER_SIZE,
    )
    .unwrap();
    file.commit().unwrap();
    assert_eq!(counts.bytes_in, LEN);
    assert_eq!(fs::metadata(&path).unwrap().len(), (LEN / 8 + 1) * 8);

    let mut verifier = Verifier { pos: 0 };
    let counts = decrypt_stream(
        &mut *des_mode(Kind::Cbc),
        Padding::Pkcs7,
        &mut fs::File::open(&path).unwrap(),
        &mut verifier,
        DEFAULT_BUFFER_SIZE,
    )
    .unwrap();
    assert_eq!(counts.bytes_out, LEN);
    assert_eq!(verifier.pos, LEN);
}
