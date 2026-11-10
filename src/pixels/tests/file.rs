use std::path::{Path, PathBuf};

use image::{Rgb, RgbImage};

use super::common::{KEY, WRONG_KEY, des_mode, iv_for};
use crate::container::{Algorithm, Mode};
use crate::padding::Padding;
use crate::pixels::{
    PixelError, PixelMeta, PixelParams, decrypt_image_file, default_meta_path, encrypt_image_file,
    load_rgb,
};
use crate::stream::test_util::TempDir;

fn params(mode: Mode) -> PixelParams {
    PixelParams {
        algorithm: Algorithm::Des,
        mode,
        padding: Padding::Pkcs7,
        iv: iv_for(mode),
    }
}

/// A picture with no flat areas. At 5x3 it has 45 bytes of pixels, so a 5-byte
/// tail with DES; at 8x8 it is block-aligned.
fn picture(width: u32, height: u32) -> RgbImage {
    RgbImage::from_fn(width, height, |x, y| {
        Rgb([(x * 37) as u8, (y * 91) as u8, (x * y + 11) as u8])
    })
}

fn write_source(dir: &TempDir, image: &RgbImage) -> PathBuf {
    let path = dir.path().join("source.png");
    image.save(&path).unwrap();
    path
}

/// Encrypts `source` to `enc.png` with its default metadata path.
fn encrypt(dir: &TempDir, source: &Path, mode: Mode) -> (PathBuf, PixelMeta) {
    let output = dir.path().join("enc.png");
    let meta = encrypt_image_file(
        source,
        &output,
        &default_meta_path(&output),
        false,
        &mut *des_mode(mode, &KEY),
        params(mode),
    )
    .unwrap();
    (output, meta)
}

// ---- encrypt_image_file and decrypt_image_file ----

#[test]
fn encrypt_image_file_round_trips_png_and_bmp_in_ecb_and_cbc() {
    for (width, height) in [(5, 3), (8, 8)] {
        let original = picture(width, height);
        for mode in [Mode::Ecb, Mode::Cbc] {
            for extension in ["png", "bmp"] {
                let context = format!("{width}x{height}, {mode:?}, {extension}");
                let dir = TempDir::new("pixels-file");
                let source = write_source(&dir, &original);
                let encrypted = dir.path().join(format!("enc.{extension}"));
                let meta_path = default_meta_path(&encrypted);
                let restored = dir.path().join(format!("dec.{extension}"));

                encrypt_image_file(
                    &source,
                    &encrypted,
                    &meta_path,
                    false,
                    &mut *des_mode(mode, &KEY),
                    params(mode),
                )
                .unwrap();
                let encrypted_image = load_rgb(&encrypted).unwrap();
                assert_eq!(encrypted_image.dimensions(), (width, height), "{context}");
                assert_ne!(encrypted_image.as_raw(), original.as_raw(), "{context}");

                let meta = PixelMeta::read_file(&meta_path).unwrap();
                decrypt_image_file(
                    &encrypted,
                    &restored,
                    &meta,
                    false,
                    &mut *des_mode(mode, &KEY),
                )
                .unwrap();
                assert_eq!(
                    load_rgb(&restored).unwrap().as_raw(),
                    original.as_raw(),
                    "{context}"
                );
            }
        }
    }
}

#[test]
fn encrypt_image_file_keeps_existing_outputs_unless_overwrite_is_set() {
    let dir = TempDir::new("pixels-file");
    let source = write_source(&dir, &picture(5, 3));
    let output = dir.path().join("enc.png");
    let meta_path = default_meta_path(&output);
    std::fs::write(&meta_path, b"old").unwrap();

    let run = |overwrite| {
        encrypt_image_file(
            &source,
            &output,
            &meta_path,
            overwrite,
            &mut *des_mode(Mode::Ecb, &KEY),
            params(Mode::Ecb),
        )
    };

    assert!(matches!(run(false), Err(PixelError::Io(_))));
    assert!(
        !output.exists(),
        "an image was written without its metadata"
    );
    assert_eq!(std::fs::read(&meta_path).unwrap(), b"old");

    run(true).unwrap();
    assert!(PixelMeta::read_file(&meta_path).is_ok());
    assert!(output.exists());
}

#[test]
fn encrypt_image_file_rejects_invalid_requests_before_any_output() {
    let dir = TempDir::new("pixels-file");
    let source = write_source(&dir, &picture(5, 3));
    let not_image = dir.path().join("notes.png");
    std::fs::write(&not_image, b"not an image").unwrap();
    let png = dir.path().join("enc.png");
    let jpg = dir.path().join("enc.jpg");

    let cases = [
        ("same paths", &source, &png, &png),
        (
            "unsupported extension",
            &source,
            &jpg,
            &default_meta_path(&jpg),
        ),
        ("not an image", &not_image, &png, &default_meta_path(&png)),
    ];
    for (name, input, output, meta_path) in cases {
        let result = encrypt_image_file(
            input,
            output,
            meta_path,
            false,
            &mut *des_mode(Mode::Ecb, &KEY),
            params(Mode::Ecb),
        );
        assert!(
            matches!(result, Err(PixelError::Invalid(_) | PixelError::Image(_))),
            "{name}: {result:?}"
        );
    }
    assert_eq!(dir.entries(), ["notes.png", "source.png"]);
}

#[test]
fn decrypt_image_file_with_a_wrong_key_fails_without_output() {
    let dir = TempDir::new("pixels-file");
    let source = write_source(&dir, &picture(5, 3));
    let (encrypted, meta) = encrypt(&dir, &source, Mode::Cbc);

    let restored = dir.path().join("dec.png");
    let result = decrypt_image_file(
        &encrypted,
        &restored,
        &meta,
        false,
        &mut *des_mode(Mode::Cbc, &WRONG_KEY),
    );
    assert!(
        matches!(
            result,
            Err(PixelError::Padding(_) | PixelError::TailMismatch)
        ),
        "{result:?}"
    );
    assert!(!restored.exists());
}

#[test]
fn decrypt_image_file_rejects_an_image_of_another_size() {
    let dir = TempDir::new("pixels-file");
    let source = write_source(&dir, &picture(5, 3));
    let (_, meta) = encrypt(&dir, &source, Mode::Ecb);
    let other = dir.path().join("other.png");
    picture(6, 3).save(&other).unwrap();

    let restored = dir.path().join("dec.png");
    let result = decrypt_image_file(
        &other,
        &restored,
        &meta,
        false,
        &mut *des_mode(Mode::Ecb, &KEY),
    );
    assert!(matches!(
        result,
        Err(PixelError::DimensionMismatch {
            expected: (5, 3),
            actual: (6, 3)
        })
    ));
    assert!(!restored.exists());
}
