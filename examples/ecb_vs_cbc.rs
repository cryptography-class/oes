//! Encrypts the pixels of one image with DES in ECB and in CBC, and puts the
//! original and both results side by side in `comparison.png`.
//!
//! Arguments: an optional input image (PNG or BMP) and an optional output
//! directory, `demo_out` by default. Without an input image, a generated picture
//! with flat areas is used. The key is random, and is neither printed nor saved.

use std::error::Error;
use std::path::PathBuf;

use image::{Rgb, RgbImage, imageops};
use oes::ciphers::des::DesCipher;
use oes::ciphers::traits::KeyInit;
use oes::container::{Algorithm, Mode};
use oes::keys::Key;
use oes::modes::{BlockMode, Cbc, Ecb};
use oes::padding::Padding;
use oes::pixels::{
    PixelParams, count_distinct_blocks, default_meta_path, encrypt_image_file, load_rgb,
};
use oes::random::random_bytes;

/// Returns a picture with flat areas, where ECB's repeated blocks show.
fn generated_picture() -> RgbImage {
    RgbImage::from_fn(256, 256, |x, y| {
        let (dx, dy) = (x as i32 - 128, y as i32 - 128);
        let distance = dx * dx + dy * dy;
        if distance < 60 * 60 {
            Rgb([230, 60, 60])
        } else if distance < 90 * 90 {
            Rgb([250, 220, 60])
        } else if (x + y) % 64 < 12 {
            Rgb([40, 40, 40])
        } else {
            Rgb([60, 120, 220])
        }
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let input = args.next().map(PathBuf::from);
    let out_dir = args
        .next()
        .map_or_else(|| PathBuf::from("demo_out"), PathBuf::from);
    std::fs::create_dir_all(&out_dir)?;

    let original = match input {
        Some(path) => load_rgb(&path)?,
        None => generated_picture(),
    };
    let source = out_dir.join("original.png");
    original.save(&source)?;

    let key = Key::generate(Algorithm::Des)?;
    let (width, height) = original.dimensions();
    let mut comparison = RgbImage::new(width * 3, height);
    imageops::replace(&mut comparison, &original, 0, 0);

    for (column, (name, mode)) in [("ecb", Mode::Ecb), ("cbc", Mode::Cbc)]
        .into_iter()
        .enumerate()
    {
        let params = PixelParams {
            algorithm: Algorithm::Des,
            mode,
            padding: Padding::Pkcs7,
            iv: random_bytes(mode.iv_len(Algorithm::Des))?,
        };
        let cipher = DesCipher::new(key.as_array::<8>()?);
        let mut block_mode: Box<dyn BlockMode> = match mode {
            Mode::Cbc => Box::new(Cbc::new(cipher, &params.iv)?),
            _ => Box::new(Ecb::new(cipher)),
        };

        let output = out_dir.join(format!("original_{name}.png"));
        encrypt_image_file(
            &source,
            &output,
            &default_meta_path(&output),
            true,
            &mut *block_mode,
            params,
        )?;

        let encrypted = load_rgb(&output)?;
        let (total, distinct) = count_distinct_blocks(encrypted.as_raw(), 8);
        println!("{name}: {distinct} distinct blocks of {total}");
        let x = i64::from(width) * (column as i64 + 1);
        imageops::replace(&mut comparison, &encrypted, x, 0);
    }

    let comparison_path = out_dir.join("comparison.png");
    comparison.save(&comparison_path)?;
    println!("original | ECB | CBC: {}", comparison_path.display());
    Ok(())
}
