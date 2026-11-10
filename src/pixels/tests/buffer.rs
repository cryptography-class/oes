use super::common::{KEY, PADDINGS, des_mode, sample};
use crate::container::Mode;
use crate::padding::Padding;
use crate::pixels::{PixelError, count_distinct_blocks, decrypt_buffer, encrypt_buffer};

// ---- encrypt_buffer ----

#[test]
fn encrypt_buffer_round_trips_and_keeps_the_length() {
    for len in 0..=17 {
        for padding in PADDINGS {
            for mode in [Mode::Ecb, Mode::Cbc] {
                let context = format!("len {len}, {padding:?}, {mode:?}");
                let data = sample(len);
                let mut buf = data.clone();
                let tail = encrypt_buffer(&mut *des_mode(mode, &KEY), padding, &mut buf).unwrap();

                assert_eq!(buf.len(), len, "{context}");
                assert_eq!(tail.len(), if len % 8 == 0 { 0 } else { 8 }, "{context}");
                if len >= 8 {
                    assert_ne!(buf[..8], data[..8], "{context}");
                }

                decrypt_buffer(&mut *des_mode(mode, &KEY), padding, &mut buf, &tail).unwrap();
                assert_eq!(buf, data, "{context}");
            }
        }
    }
}

#[test]
fn encrypt_buffer_puts_the_start_of_the_tail_block_in_the_image() {
    // Two whole blocks and 5 leftover bytes.
    let mut buf = sample(21);
    let tail = encrypt_buffer(&mut *des_mode(Mode::Cbc, &KEY), Padding::Pkcs7, &mut buf).unwrap();
    assert_eq!(buf[16..], tail[..5]);
}

#[test]
fn encrypt_buffer_repeats_blocks_in_ecb_and_not_in_cbc() {
    let flat = vec![0u8; 800];

    let mut ecb = flat.clone();
    encrypt_buffer(&mut *des_mode(Mode::Ecb, &KEY), Padding::Pkcs7, &mut ecb).unwrap();
    assert_eq!(count_distinct_blocks(&ecb, 8), (100, 1));

    let mut cbc = flat;
    encrypt_buffer(&mut *des_mode(Mode::Cbc, &KEY), Padding::Pkcs7, &mut cbc).unwrap();
    assert_eq!(count_distinct_blocks(&cbc, 8), (100, 100));
}

// ---- decrypt_buffer ----

#[test]
fn decrypt_buffer_rejects_a_changed_tail_block() {
    for mode in [Mode::Ecb, Mode::Cbc] {
        let mut buf = sample(45);
        let tail = encrypt_buffer(&mut *des_mode(mode, &KEY), Padding::Pkcs7, &mut buf).unwrap();

        // A byte the image also holds: the two copies disagree.
        let mut changed = tail.clone();
        changed[0] ^= 0xFF;
        let result = decrypt_buffer(
            &mut *des_mode(mode, &KEY),
            Padding::Pkcs7,
            &mut buf.clone(),
            &changed,
        );
        assert!(
            matches!(result, Err(PixelError::TailMismatch)),
            "{mode:?}: {result:?}"
        );

        // A byte only the metadata holds: the padding or the data length is wrong.
        let mut changed = tail;
        changed[7] ^= 0xFF;
        let result = decrypt_buffer(
            &mut *des_mode(mode, &KEY),
            Padding::Pkcs7,
            &mut buf,
            &changed,
        );
        assert!(
            matches!(
                result,
                Err(PixelError::TailMismatch | PixelError::Padding(_))
            ),
            "{mode:?}: {result:?}"
        );
    }
}

#[test]
fn decrypt_buffer_rejects_a_tail_block_of_the_wrong_length() {
    let mut buf = sample(45);
    let tail = encrypt_buffer(&mut *des_mode(Mode::Ecb, &KEY), Padding::Pkcs7, &mut buf).unwrap();

    for (len, wrong) in [(45, &tail[..7]), (45, &[][..]), (48, &tail[..])] {
        let mut data = sample(len);
        let result = decrypt_buffer(
            &mut *des_mode(Mode::Ecb, &KEY),
            Padding::Pkcs7,
            &mut data,
            wrong,
        );
        assert!(
            matches!(result, Err(PixelError::Invalid(_))),
            "buffer {len}, tail {}: {result:?}",
            wrong.len()
        );
    }
}

// ---- count_distinct_blocks ----

#[test]
fn count_distinct_blocks_ignores_leftover_bytes() {
    assert_eq!(
        count_distinct_blocks(&[1, 1, 2, 2, 1, 1, 3, 3, 9], 2),
        (4, 3)
    );
    assert_eq!(count_distinct_blocks(&[], 8), (0, 0));
}
