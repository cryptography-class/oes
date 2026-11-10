use super::common::{PADDINGS, iv_for};
use crate::container::errors::ContainerError;
use crate::container::{Algorithm, Mode};
use crate::padding::Padding;
use crate::pixels::{PixelError, PixelMeta, PixelParams};

/// DES CBC on a 5x3 image: 45 bytes of pixels, so a tail block.
fn des_cbc() -> PixelMeta {
    PixelMeta {
        params: PixelParams {
            algorithm: Algorithm::Des,
            mode: Mode::Cbc,
            padding: Padding::Pkcs7,
            iv: vec![1, 2, 3, 4, 5, 6, 7, 8],
        },
        width: 5,
        height: 3,
        tail_block: vec![0xAA; 8],
    }
}

fn to_bytes(meta: &PixelMeta) -> Result<Vec<u8>, PixelError> {
    let mut bytes = Vec::new();
    meta.write_to(&mut bytes)?;
    Ok(bytes)
}

// ---- PixelParams::validate ----

#[test]
fn validate_rejects_ctr_and_a_wrong_iv_length() {
    let mut params = des_cbc().params;
    params.mode = Mode::Ctr;
    assert!(matches!(params.validate(), Err(PixelError::Invalid(_))));

    let mut params = des_cbc().params;
    params.iv = vec![0; 16];
    assert!(matches!(
        params.validate(),
        Err(PixelError::Container(ContainerError::InvalidCombination(_)))
    ));
}

// ---- write_to ----

#[test]
fn layout_matches_documentation() {
    let bytes = to_bytes(&des_cbc()).unwrap();
    assert_eq!(bytes[..4], *b"OESP");
    // Version 1, DES, CBC, PKCS#7.
    assert_eq!(bytes[4..8], [1, 1, 2, 1]);
    assert_eq!(bytes[8..12], [0, 0, 0, 5]);
    assert_eq!(bytes[12..16], [0, 0, 0, 3]);
    assert_eq!(bytes[16..24], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(bytes[24..32], [0xAA; 8]);
    assert_eq!(bytes.len(), 32);
}

#[test]
fn write_to_refuses_invalid_metadata_and_writes_nothing() {
    let mut no_tail = des_cbc();
    no_tail.tail_block.clear();
    let mut zero_width = des_cbc();
    zero_width.width = 0;

    for meta in [no_tail, zero_width] {
        let mut bytes = Vec::new();
        assert!(matches!(
            meta.write_to(&mut bytes),
            Err(PixelError::Invalid(_))
        ));
        assert!(bytes.is_empty());
    }
}

// ---- read_from and from_bytes ----

#[test]
fn from_bytes_round_trips_every_mode_padding_and_size() {
    for mode in [Mode::Ecb, Mode::Cbc] {
        for padding in PADDINGS {
            // 3, 48 (aligned) and about 2^34 bytes of pixels.
            for (width, height) in [(1, 1), (4, 4), (u32::MAX, 3)] {
                let mut meta = PixelMeta {
                    params: PixelParams {
                        algorithm: Algorithm::Des,
                        mode,
                        padding,
                        iv: iv_for(mode),
                    },
                    width,
                    height,
                    tail_block: Vec::new(),
                };
                meta.tail_block = vec![0x5C; meta.expected_tail_len()];
                let bytes = to_bytes(&meta).unwrap();
                assert_eq!(
                    PixelMeta::from_bytes(&bytes).unwrap(),
                    meta,
                    "{mode:?}, {padding:?}, {width}x{height}"
                );
            }
        }
    }
}

#[test]
fn from_bytes_reports_every_truncation() {
    let bytes = to_bytes(&des_cbc()).unwrap();
    for cut in 0..bytes.len() {
        let result = PixelMeta::from_bytes(&bytes[..cut]);
        assert!(
            matches!(result, Err(PixelError::Truncated)),
            "cut {cut}: {result:?}"
        );
    }
}

#[test]
fn from_bytes_rejects_trailing_bytes() {
    let mut bytes = to_bytes(&des_cbc()).unwrap();
    bytes.push(0);
    assert!(matches!(
        PixelMeta::from_bytes(&bytes),
        Err(PixelError::Invalid(_))
    ));
}

#[test]
fn from_bytes_rejects_bad_magic_version_and_unknown_codes() {
    let good = to_bytes(&des_cbc()).unwrap();

    let mut bytes = good.clone();
    bytes[0] ^= 1;
    assert!(matches!(
        PixelMeta::from_bytes(&bytes),
        Err(PixelError::BadMagic)
    ));

    let mut bytes = good.clone();
    bytes[4] = 9;
    assert!(matches!(
        PixelMeta::from_bytes(&bytes),
        Err(PixelError::UnsupportedVersion(9))
    ));

    for (index, field) in [(5, "algorithm"), (6, "mode"), (7, "padding")] {
        let mut bytes = good.clone();
        bytes[index] = 99;
        let result = PixelMeta::from_bytes(&bytes);
        assert!(
            matches!(
                result,
                Err(PixelError::Container(ContainerError::UnknownCode { field: f, value: 99 })) if f == field
            ),
            "{field}: {result:?}"
        );
    }
}

#[test]
fn from_bytes_rejects_ctr_no_padding_and_inconsistent_sizes() {
    let good = to_bytes(&des_cbc()).unwrap();
    let with = |index: usize, value: &[u8]| {
        let mut bytes = good.clone();
        bytes[index..index + value.len()].copy_from_slice(value);
        PixelMeta::from_bytes(&bytes)
    };

    let cases = [
        ("CTR", with(6, &[3])),
        ("no padding", with(7, &[0])),
        // 8x3 pixels are 72 bytes, block-aligned, so the tail block is extra.
        ("aligned with a tail", with(8, &[0, 0, 0, 8])),
        ("zero width", with(8, &[0, 0, 0, 0])),
    ];
    for (name, result) in cases {
        assert!(
            matches!(result, Err(PixelError::Invalid(_))),
            "{name}: {result:?}"
        );
    }
}
