use std::io::{Cursor, Read};

use super::errors::ContainerError;
use super::{Algorithm, Header, ImageType, Mode};
use crate::padding::{Fill, Padding};

const IV: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const PADDINGS: [Padding; 4] = [
    Padding::Pkcs7,
    Padding::Pkcs5,
    Padding::AnsiX923(Fill::Zeros),
    Padding::AnsiX923(Fill::Random),
];

fn cbc_header() -> Header {
    Header {
        image_type: ImageType::Png,
        algorithm: Algorithm::Des,
        mode: Mode::Cbc,
        padding: Some(Padding::Pkcs7),
        iv: IV.to_vec(),
        original_len: 0x0102_0304_0506_0708,
    }
}

fn ecb_header() -> Header {
    Header {
        image_type: ImageType::Bmp,
        algorithm: Algorithm::Des,
        mode: Mode::Ecb,
        padding: Some(Padding::AnsiX923(Fill::Random)),
        iv: Vec::new(),
        original_len: 13,
    }
}

fn to_bytes(header: &Header) -> Vec<u8> {
    let mut bytes = Vec::new();
    header.write_to(&mut bytes).unwrap();
    bytes
}

// ---- write_to ----

#[test]
fn write_to_matches_documented_layout() {
    #[rustfmt::skip]
    let cbc = [
        b'O', b'E', b'S', b'C', // magic
        1,                      // version
        2,                      // PNG
        1,                      // DES
        2,                      // CBC
        1,                      // PKCS#7
        1, 2, 3, 4, 5, 6, 7, 8, // original length, big-endian
        1, 2, 3, 4, 5, 6, 7, 8, // IV
    ];
    assert_eq!(to_bytes(&cbc_header()), cbc);

    #[rustfmt::skip]
    let ecb = [
        b'O', b'E', b'S', b'C', 1,
        1,                      // BMP
        1,                      // DES
        1,                      // ECB
        4,                      // ANSI X9.23 random
        0, 0, 0, 0, 0, 0, 0, 13,
    ];
    assert_eq!(to_bytes(&ecb_header()), ecb);
}

#[test]
fn write_to_refuses_invalid_combinations() {
    let with = |change: fn(&mut Header)| {
        let mut header = cbc_header();
        change(&mut header);
        header
    };
    let cases = [
        ("ECB with an IV", with(|h| h.mode = Mode::Ecb)),
        ("ECB without padding", {
            let mut h = ecb_header();
            h.padding = None;
            h
        }),
        ("CBC without padding", with(|h| h.padding = None)),
        ("CBC with a short IV", with(|h| h.iv.truncate(7))),
        ("CBC with a long IV", with(|h| h.iv.push(9))),
        ("CTR with padding", with(|h| h.mode = Mode::Ctr)),
        (
            "CTR with a short IV",
            with(|h| {
                h.mode = Mode::Ctr;
                h.padding = None;
                h.iv.truncate(7);
            }),
        ),
    ];
    for (name, header) in cases {
        let mut out = Vec::new();
        let res = header.write_to(&mut out);
        assert!(
            matches!(res, Err(ContainerError::InvalidCombination(_))),
            "{name}: {res:?}"
        );
        assert!(out.is_empty(), "{name}: wrote {} bytes", out.len());
    }
}

// ---- read_from ----

#[test]
fn read_from_round_trips_every_valid_combination() {
    let image_types = [
        ImageType::Unknown,
        ImageType::Bmp,
        ImageType::Png,
        ImageType::Jpeg,
    ];
    let mut modes = vec![(Mode::Ctr, None)];
    for padding in PADDINGS {
        modes.push((Mode::Ecb, Some(padding)));
        modes.push((Mode::Cbc, Some(padding)));
    }
    for image_type in image_types {
        for &(mode, padding) in &modes {
            let iv = IV[..mode.iv_len(Algorithm::Des)].to_vec();
            let header = Header {
                image_type,
                algorithm: Algorithm::Des,
                mode,
                padding,
                iv,
                original_len: u64::MAX,
            };
            let mut bytes = to_bytes(&header);
            bytes.extend_from_slice(b"ciphertext");

            let mut reader = Cursor::new(bytes);
            let read = Header::read_from(&mut reader).unwrap();
            assert_eq!(read, header, "{image_type:?} {mode:?} {padding:?}");
            let mut rest = Vec::new();
            reader.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, b"ciphertext", "{image_type:?} {mode:?} {padding:?}");
        }
    }
}

#[test]
fn read_from_rejects_bad_magic() {
    for pos in 0..4 {
        let mut bytes = to_bytes(&cbc_header());
        bytes[pos] ^= 0x20;
        let res = Header::read_from(&mut bytes.as_slice());
        assert!(
            matches!(res, Err(ContainerError::BadMagic)),
            "byte {pos}: {res:?}"
        );
    }
}

#[test]
fn read_from_rejects_unknown_version() {
    for version in [0, 2, 255] {
        let mut bytes = to_bytes(&cbc_header());
        bytes[4] = version;
        let res = Header::read_from(&mut bytes.as_slice());
        assert!(
            matches!(res, Err(ContainerError::UnsupportedVersion(v)) if v == version),
            "version {version}: {res:?}"
        );
    }
}

#[test]
fn read_from_rejects_unknown_codes() {
    let cases = [
        (5, "image type", 4),
        (6, "algorithm", 0),
        (6, "algorithm", 2),
        (7, "mode", 0),
        (7, "mode", 4),
        (8, "padding", 5),
    ];
    for (pos, field, value) in cases {
        let mut bytes = to_bytes(&cbc_header());
        bytes[pos] = value;
        match Header::read_from(&mut bytes.as_slice()) {
            Err(ContainerError::UnknownCode { field: f, value: v }) => {
                assert_eq!((f, v), (field, value));
            }
            other => panic!("{field} {value}: {other:?}"),
        }
    }
}

#[test]
fn read_from_detects_every_truncation() {
    let bytes = to_bytes(&cbc_header());
    for len in 0..bytes.len() {
        let res = Header::read_from(&mut &bytes[..len]);
        assert!(
            matches!(res, Err(ContainerError::Truncated)),
            "length {len}: {res:?}"
        );
    }
}

#[test]
fn read_from_rejects_invalid_combination() {
    let mut header = cbc_header();
    header.mode = Mode::Ctr;
    header.padding = None;
    let mut bytes = to_bytes(&header);
    bytes[8] = 1; // PKCS#7 on a CTR header

    let res = Header::read_from(&mut bytes.as_slice());
    assert!(
        matches!(res, Err(ContainerError::InvalidCombination(_))),
        "{res:?}"
    );
}

// ---- from_signature ----

#[test]
fn from_signature_recognises_each_format() {
    let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let cases: [(&[u8], ImageType); 7] = [
        (&png, ImageType::Png),
        (&png[..7], ImageType::Unknown),
        (&[0xFF, 0xD8, 0xFF, 0xE0], ImageType::Jpeg),
        (&[0xFF, 0xD8], ImageType::Unknown),
        (b"BM\x36\x00", ImageType::Bmp),
        (b"GIF89a", ImageType::Unknown),
        (&[], ImageType::Unknown),
    ];
    for (prefix, expected) in cases {
        assert_eq!(
            ImageType::from_signature(prefix),
            expected,
            "prefix {prefix:02X?}"
        );
    }
}
