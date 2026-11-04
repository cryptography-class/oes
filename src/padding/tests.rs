use super::errors::PaddingError;
use super::{Fill, Padding};

const ALL: [Padding; 4] = [
    Padding::Pkcs7,
    Padding::Pkcs5,
    Padding::AnsiX923(Fill::Zeros),
    Padding::AnsiX923(Fill::Random),
];

fn block_sizes(p: Padding) -> &'static [usize] {
    if p == Padding::Pkcs5 { &[8] } else { &[8, 16] }
}

// ---- pad ----

#[test]
fn pad_roundtrips_every_length() {
    for p in ALL {
        for &bs in block_sizes(p) {
            for len in 0..=3 * bs {
                let orig: Vec<u8> = (0..len as u8).collect();
                let mut d = orig.clone();
                p.pad(&mut d, bs).unwrap();
                assert_eq!(d.len() % bs, 0, "{p:?}, block size {bs}, length {len}");
                assert!(d.len() > orig.len(), "must always add padding");
                let keep = p.unpad_len(&d, bs).unwrap();
                assert_eq!(&d[..keep], &orig[..], "{p:?}, block size {bs}, length {len}");
            }
        }
    }
}

#[test]
fn pad_aligned_input_gets_a_full_block() {
    for p in ALL {
        let mut d = vec![0xAA; 16];
        p.pad(&mut d, 8).unwrap();
        assert_eq!(d.len(), 24, "{p:?}");
        assert_eq!(d[23], 8, "{p:?}");
    }
}

// Known answer from Cryptopals, set 2, challenge 9.
#[test]
fn pad_known_answer_pkcs7() {
    let mut d = b"YELLOW SUBMARINE".to_vec();
    Padding::Pkcs7.pad(&mut d, 20).unwrap();
    assert_eq!(&d[16..], &[4, 4, 4, 4]);
}

#[test]
fn pad_x923_zero_fill_layout() {
    let mut d = vec![1, 2, 3];
    Padding::AnsiX923(Fill::Zeros).pad(&mut d, 8).unwrap();
    assert_eq!(d, [1, 2, 3, 0, 0, 0, 0, 5]);
}

#[test]
fn pad_pkcs5_rejects_block_sizes_other_than_8_and_keeps_the_data() {
    let mut d = vec![0u8; 3];
    assert_eq!(
        Padding::Pkcs5.pad(&mut d, 16),
        Err(PaddingError::Pkcs5RequiresBlock8(16))
    );
    assert_eq!(d, [0u8; 3]);
}

#[test]
fn pad_accepts_the_smallest_and_largest_block_sizes() {
    let mut d = vec![0xAA];
    Padding::Pkcs7.pad(&mut d, 1).unwrap();
    assert_eq!(d, [0xAA, 1]);

    let mut d = vec![];
    Padding::Pkcs7.pad(&mut d, 255).unwrap();
    assert_eq!(d, [255u8; 255]);
}

#[test]
fn pad_rejects_block_sizes_outside_1_to_255() {
    for bs in [0, 256] {
        assert_eq!(Padding::Pkcs7.pad(&mut vec![], bs), Err(PaddingError::InvalidBlockSize(bs)));
        assert_eq!(Padding::Pkcs7.unpad_len(&[1], bs), Err(PaddingError::InvalidBlockSize(bs)));
    }
}

// ---- pad_final ----

#[test]
fn pad_final_rejects_a_tail_as_long_as_the_block() {
    assert_eq!(
        Padding::Pkcs7.pad_final(&[0; 8], &mut [0; 8]),
        Err(PaddingError::InvalidLength { len: 8, block_size: 8 })
    );
}

#[test]
fn pad_final_rejects_an_empty_output_block() {
    assert_eq!(Padding::Pkcs7.pad_final(&[], &mut []), Err(PaddingError::InvalidBlockSize(0)));
}

// ---- unpad_block ----

#[test]
fn unpad_block_rejects_corrupted_padding() {
    let bad: [&[u8]; 5] = [
        &[1, 2, 3, 4, 5, 6, 7, 0],  // pad byte 0
        &[1, 2, 3, 4, 5, 6, 7, 9],  // pad byte > bs
        &[1, 2, 3, 4, 5, 3, 2, 3],  // inconsistent fill (PKCS)
        &[1, 2, 3, 4, 5, 6, 7, 2],  // fill byte != 2
        &[8, 8, 8, 8, 8, 8, 7, 8],  // one wrong byte in a full block
    ];
    for b in bad {
        assert_eq!(Padding::Pkcs7.unpad_block(b), Err(PaddingError::Invalid), "{b:?}");
    }
    // X9.23 with zero fill: non-zero fill byte
    let b = [1, 2, 3, 0, 9, 0, 0, 5];
    assert_eq!(
        Padding::AnsiX923(Fill::Zeros).unpad_block(&b),
        Err(PaddingError::Invalid)
    );
}

#[test]
fn unpad_block_with_random_fill_checks_only_the_length_byte() {
    let random = Padding::AnsiX923(Fill::Random);
    assert_eq!(random.unpad_block(&[1, 2, 3, 0xAB, 0xCD, 0x12, 0x34, 5]), Ok(3));
    assert_eq!(random.unpad_block(&[1, 2, 3, 0xAB, 0xCD, 0x12, 0x34, 0]), Err(PaddingError::Invalid));
    assert_eq!(random.unpad_block(&[1, 2, 3, 0xAB, 0xCD, 0x12, 0x34, 9]), Err(PaddingError::Invalid));
}

#[test]
fn unpad_block_rejects_an_empty_block() {
    assert_eq!(Padding::Pkcs7.unpad_block(&[]), Err(PaddingError::InvalidBlockSize(0)));
}

// ---- unpad_len ----

#[test]
fn unpad_len_rejects_bad_lengths() {
    assert!(Padding::Pkcs7.unpad_len(&[], 8).is_err());
    assert!(Padding::Pkcs7.unpad_len(&[0; 9], 8).is_err());
}
