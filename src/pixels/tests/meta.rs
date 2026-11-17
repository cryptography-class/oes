use super::common::{NONCE, PADDINGS, iv_for};
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
            padding: Some(Padding::Pkcs7),
            iv: vec![1, 2, 3, 4, 5, 6, 7, 8],
        },
        width: 5,
        height: 3,
        tail_block: vec![0xAA; 8],
        tag: None,
    }
}

/// AES-128 GCM on a 4x4 image: no tail block, and a tag.
fn aes_gcm() -> PixelMeta {
    PixelMeta {
        params: PixelParams {
            algorithm: Algorithm::Aes128,
            mode: Mode::Gcm,
            padding: None,
            iv: NONCE.to_vec(),
        },
        width: 4,
        height: 4,
        tail_block: Vec::new(),
        tag: Some([0xCC; 16]),
    }
}

fn to_bytes(meta: &PixelMeta) -> Result<Vec<u8>, PixelError> {
    let mut bytes = Vec::new();
    meta.write_to(&mut bytes)?;
    Ok(bytes)
}

// ---- PixelParams::validate ----

#[test]
fn validate_rejects_a_wrong_iv_length_and_gcm_with_des() {
    let mut wrong_iv = des_cbc().params;
    wrong_iv.iv = vec![0; 16];
    // GCM needs a 16-byte block, and DES has 8-byte blocks.
    let mut des_gcm = aes_gcm().params;
    des_gcm.algorithm = Algorithm::Des;

    for (name, params) in [("wrong IV", wrong_iv), ("DES with GCM", des_gcm)] {
        let result = params.validate();
        assert!(
            matches!(
                result,
                Err(PixelError::Container(ContainerError::InvalidCombination(_)))
            ),
            "{name}: {result:?}"
        );
    }
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

    let bytes = to_bytes(&aes_gcm()).unwrap();
    // Version 1, AES-128, GCM, no padding.
    assert_eq!(bytes[4..8], [1, 2, 4, 0]);
    assert_eq!(bytes[8..16], [0, 0, 0, 4, 0, 0, 0, 4]);
    assert_eq!(bytes[16..28], [0x5A; 12]);
    assert_eq!(bytes[28..44], [0xCC; 16]);
    assert_eq!(bytes.len(), 44);
}

#[test]
fn write_to_refuses_invalid_metadata_and_writes_nothing() {
    let mut no_tail = des_cbc();
    no_tail.tail_block.clear();
    let mut zero_width = des_cbc();
    zero_width.width = 0;
    let mut cbc_with_tag = des_cbc();
    cbc_with_tag.tag = Some([0; 16]);
    let mut gcm_without_tag = aes_gcm();
    gcm_without_tag.tag = None;

    let cases = [
        ("no tail", no_tail),
        ("zero width", zero_width),
        ("CBC with a tag", cbc_with_tag),
        ("GCM without a tag", gcm_without_tag),
    ];
    for (name, meta) in cases {
        let mut bytes = Vec::new();
        assert!(
            matches!(meta.write_to(&mut bytes), Err(PixelError::Invalid(_))),
            "{name}"
        );
        assert!(bytes.is_empty(), "{name}");
    }
}

// ---- read_from and from_bytes ----

#[test]
fn from_bytes_round_trips_every_mode_padding_and_size() {
    for mode in [Mode::Ecb, Mode::Cbc, Mode::Ctr, Mode::Gcm] {
        let (algorithm, paddings, tag) = match mode {
            Mode::Ecb | Mode::Cbc => (Algorithm::Des, PADDINGS.map(Some).to_vec(), None),
            Mode::Ctr => (Algorithm::Des, vec![None], None),
            Mode::Gcm => (Algorithm::Aes128, vec![None], Some([0x3D; 16])),
        };
        for padding in paddings {
            // 3, 48 (aligned), about 2^35 and about 2^66 bytes of pixels; the last
            // overflows u64.
            for (width, height) in [(1, 1), (4, 4), (u32::MAX, 3), (u32::MAX, u32::MAX)] {
                let mut meta = PixelMeta {
                    params: PixelParams {
                        algorithm,
                        mode,
                        padding,
                        iv: iv_for(mode),
                    },
                    width,
                    height,
                    tail_block: Vec::new(),
                    tag,
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
    for meta in [des_cbc(), aes_gcm()] {
        let bytes = to_bytes(&meta).unwrap();
        for cut in 0..bytes.len() {
            let result = PixelMeta::from_bytes(&bytes[..cut]);
            assert!(
                matches!(result, Err(PixelError::Truncated)),
                "{:?}, cut {cut}: {result:?}",
                meta.params.mode
            );
        }
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
fn from_bytes_rejects_invalid_combinations_and_sizes() {
    let with = |meta: PixelMeta, index: usize, value: &[u8]| {
        let mut bytes = to_bytes(&meta).unwrap();
        bytes[index..index + value.len()].copy_from_slice(value);
        PixelMeta::from_bytes(&bytes)
    };

    let combinations = [
        ("CTR with padding", with(des_cbc(), 6, &[3])),
        ("CBC without padding", with(des_cbc(), 7, &[0])),
        ("DES with GCM", with(aes_gcm(), 5, &[1])),
    ];
    for (name, result) in combinations {
        assert!(
            matches!(
                result,
                Err(PixelError::Container(ContainerError::InvalidCombination(_)))
            ),
            "{name}: {result:?}"
        );
    }

    let sizes = [
        // 8x3 pixels are 72 bytes, block-aligned, so the tail block is extra.
        ("aligned with a tail", with(des_cbc(), 8, &[0, 0, 0, 8])),
        ("zero width", with(des_cbc(), 8, &[0, 0, 0, 0])),
    ];
    for (name, result) in sizes {
        assert!(
            matches!(result, Err(PixelError::Invalid(_))),
            "{name}: {result:?}"
        );
    }
}
