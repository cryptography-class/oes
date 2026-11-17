use std::path::{Path, PathBuf};

use image::{Rgb, RgbImage};

use super::common::{AES_KEY, KEY, WRONG_KEY, iv_for};
use crate::ciphers::aes::Aes128Cipher;
use crate::ciphers::des::DesCipher;
use crate::ciphers::traits::KeyInit;
use crate::container::{Algorithm, Mode};
use crate::modes::errors::ModeError;
use crate::padding::Padding;
use crate::pixels::{
    PixelError, PixelMeta, PixelParams, decrypt_image_file, default_meta_path, encrypt_image_file,
    load_rgb,
};
use crate::stream::test_util::TempDir;

/// Every mode, each with the cipher [`encrypt_with`] uses for it.
const MODES: [Mode; 4] = [Mode::Ecb, Mode::Cbc, Mode::Ctr, Mode::Gcm];

/// AES-128 for GCM, which needs 16-byte blocks, and DES for the other modes.
fn params(mode: Mode) -> PixelParams {
    let (algorithm, padding) = match mode {
        Mode::Ecb | Mode::Cbc => (Algorithm::Des, Some(Padding::Pkcs7)),
        Mode::Ctr => (Algorithm::Des, None),
        Mode::Gcm => (Algorithm::Aes128, None),
    };
    PixelParams {
        algorithm,
        mode,
        padding,
        iv: iv_for(mode),
    }
}

/// Encrypts with [`params`] and the cipher they name.
fn encrypt_with(
    mode: Mode,
    source: &Path,
    output: &Path,
    meta_path: &Path,
) -> Result<PixelMeta, PixelError> {
    match mode {
        Mode::Gcm => {
            let cipher = Aes128Cipher::new(&AES_KEY);
            encrypt_image_file(
                source,
                output,
                meta_path,
                false,
                cipher,
                params(mode),
                false,
            )
        }
        _ => {
            let cipher = DesCipher::new(&KEY);
            encrypt_image_file(
                source,
                output,
                meta_path,
                false,
                cipher,
                params(mode),
                false,
            )
        }
    }
}

/// Decrypts with the right key for the cipher `meta` names.
fn decrypt_with(input: &Path, output: &Path, meta: &PixelMeta) -> Result<(), PixelError> {
    match meta.params.algorithm {
        Algorithm::Aes128 => decrypt_image_file(
            input,
            output,
            meta,
            false,
            Aes128Cipher::new(&AES_KEY),
            false,
        ),
        _ => decrypt_image_file(input, output, meta, false, DesCipher::new(&KEY), false),
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
    let meta = encrypt_with(mode, source, &output, &default_meta_path(&output)).unwrap();
    (output, meta)
}

// ---- encrypt_image_file and decrypt_image_file ----

#[test]
fn encrypt_image_file_round_trips_png_and_bmp_in_every_mode() {
    for (width, height) in [(5, 3), (8, 8)] {
        let original = picture(width, height);
        for mode in MODES {
            for extension in ["png", "bmp"] {
                let context = format!("{width}x{height}, {mode:?}, {extension}");
                let dir = TempDir::new("pixels-file");
                let source = write_source(&dir, &original);
                let encrypted = dir.path().join(format!("enc.{extension}"));
                let meta_path = default_meta_path(&encrypted);
                let restored = dir.path().join(format!("dec.{extension}"));

                encrypt_with(mode, &source, &encrypted, &meta_path).unwrap();
                let encrypted_image = load_rgb(&encrypted).unwrap();
                assert_eq!(encrypted_image.dimensions(), (width, height), "{context}");
                assert_ne!(encrypted_image.as_raw(), original.as_raw(), "{context}");

                let meta = PixelMeta::read_file(&meta_path).unwrap();
                decrypt_with(&encrypted, &restored, &meta).unwrap();
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
            DesCipher::new(&KEY),
            params(Mode::Ecb),
            false,
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
            DesCipher::new(&KEY),
            params(Mode::Ecb),
            false,
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
        DesCipher::new(&WRONG_KEY),
        false,
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
    let result = decrypt_image_file(&other, &restored, &meta, false, DesCipher::new(&KEY), false);
    assert!(matches!(
        result,
        Err(PixelError::DimensionMismatch {
            expected: (5, 3),
            actual: (6, 3)
        })
    ));
    assert!(!restored.exists());
}

#[test]
fn decrypt_image_file_gcm_rejects_a_changed_pixel_without_output() {
    let dir = TempDir::new("pixels-file");
    let source = write_source(&dir, &picture(5, 3));
    let (encrypted, meta) = encrypt(&dir, &source, Mode::Gcm);
    let mut image = load_rgb(&encrypted).unwrap();
    image.get_pixel_mut(2, 1).0[0] ^= 1;
    image.save(&encrypted).unwrap();

    let restored = dir.path().join("dec.png");
    let result = decrypt_with(&encrypted, &restored, &meta);
    assert!(
        matches!(
            result,
            Err(PixelError::Mode(ModeError::AuthenticationFailed))
        ),
        "{result:?}"
    );
    assert!(!restored.exists());
}

#[test]
fn decrypt_image_file_gcm_rejects_swapped_dimensions_without_output() {
    let dir = TempDir::new("pixels-file");
    let source = write_source(&dir, &picture(4, 6));
    let (encrypted, mut meta) = encrypt(&dir, &source, Mode::Gcm);

    // The same pixel bytes as a 6x4 image, with the metadata to match: only the
    // AAD differs from what was encrypted.
    let pixels = load_rgb(&encrypted).unwrap().into_raw();
    let reshaped = dir.path().join("reshaped.png");
    RgbImage::from_raw(6, 4, pixels)
        .unwrap()
        .save(&reshaped)
        .unwrap();
    (meta.width, meta.height) = (6, 4);

    let restored = dir.path().join("dec.png");
    let result = decrypt_with(&reshaped, &restored, &meta);
    assert!(
        matches!(
            result,
            Err(PixelError::Mode(ModeError::AuthenticationFailed))
        ),
        "{result:?}"
    );
    assert!(!restored.exists());
}
