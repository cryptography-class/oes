//! The `pixel-encrypt` and `pixel-decrypt` commands.

use std::time::Instant;

use oes::ciphers::aes::{Aes128Cipher, Aes192Cipher, Aes256Cipher};
use oes::ciphers::des::DesCipher;
use oes::ciphers::traits::KeyInit;
use oes::container::{Algorithm, Mode};
use oes::keys::Key;
use oes::padding::Padding;
use oes::pixels::{
    PixelMeta, PixelParams, count_distinct_blocks, decrypt_image_file, default_meta_path,
    encrypt_image_file, load_rgb,
};
use oes::random::random_bytes;

use super::args::{PixelDecryptArgs, PixelEncryptArgs};
use super::commands::{CliResult, cipher_name, file_with_size, print_table, seconds};

pub(super) fn pixel_encrypt(args: &PixelEncryptArgs) -> CliResult<()> {
    let algorithm = Algorithm::from(args.algorithm);
    let mode = Mode::from(args.mode);
    if !matches!(mode, Mode::Ecb | Mode::Cbc) {
        return Err("pixel encryption supports ECB and CBC only".into());
    }
    let meta_path = args
        .meta
        .clone()
        .unwrap_or_else(|| default_meta_path(&args.output));
    let key = Key::load(algorithm, &args.key)?;
    let params = PixelParams {
        algorithm,
        mode,
        padding: Padding::from(args.padding),
        iv: random_bytes(mode.iv_len(algorithm))?,
    };

    let started = Instant::now();
    let (input, output, force) = (&args.input, &args.output, args.force);
    let meta = match algorithm {
        Algorithm::Des => {
            let cipher = DesCipher::new(key.as_array::<8>()?);
            encrypt_image_file(input, output, &meta_path, force, cipher, params)
        }
        Algorithm::Aes128 => {
            let cipher = Aes128Cipher::new(key.as_array::<16>()?);
            encrypt_image_file(input, output, &meta_path, force, cipher, params)
        }
        Algorithm::Aes192 => {
            let cipher = Aes192Cipher::new(key.as_array::<24>()?);
            encrypt_image_file(input, output, &meta_path, force, cipher, params)
        }
        Algorithm::Aes256 => {
            let cipher = Aes256Cipher::new(key.as_array::<32>()?);
            encrypt_image_file(input, output, &meta_path, force, cipher, params)
        }
    }?;
    let elapsed = started.elapsed();

    let encrypted = load_rgb(&args.output)?;
    let (total, distinct) = count_distinct_blocks(encrypted.as_raw(), algorithm.block_size());
    print_table(
        "pixel-encrypt",
        &[
            (
                "Input",
                format!("{} ({}x{})", args.input.display(), meta.width, meta.height),
            ),
            ("Output", file_with_size(&args.output)?),
            ("Metadata", file_with_size(&meta_path)?),
            (
                "Cipher",
                cipher_name(algorithm, mode, Some(meta.params.padding)),
            ),
            ("Blocks", format!("{distinct} distinct of {total}")),
            ("Time", seconds(elapsed)),
        ],
    );
    Ok(())
}

pub(super) fn pixel_decrypt(args: &PixelDecryptArgs) -> CliResult<()> {
    let meta_path = args
        .meta
        .clone()
        .unwrap_or_else(|| default_meta_path(&args.input));
    let meta = PixelMeta::read_file(&meta_path)?;
    let key = Key::load(meta.params.algorithm, &args.key)?;

    let started = Instant::now();
    let (input, output, force) = (&args.input, &args.output, args.force);
    match meta.params.algorithm {
        Algorithm::Des => {
            let cipher = DesCipher::new(key.as_array::<8>()?);
            decrypt_image_file(input, output, &meta, force, cipher)
        }
        Algorithm::Aes128 => {
            let cipher = Aes128Cipher::new(key.as_array::<16>()?);
            decrypt_image_file(input, output, &meta, force, cipher)
        }
        Algorithm::Aes192 => {
            let cipher = Aes192Cipher::new(key.as_array::<24>()?);
            decrypt_image_file(input, output, &meta, force, cipher)
        }
        Algorithm::Aes256 => {
            let cipher = Aes256Cipher::new(key.as_array::<32>()?);
            decrypt_image_file(input, output, &meta, force, cipher)
        }
    }?;
    let elapsed = started.elapsed();

    print_table(
        "pixel-decrypt",
        &[
            (
                "Input",
                format!("{} ({}x{})", args.input.display(), meta.width, meta.height),
            ),
            ("Output", file_with_size(&args.output)?),
            ("Metadata", meta_path.display().to_string()),
            (
                "Cipher",
                cipher_name(
                    meta.params.algorithm,
                    meta.params.mode,
                    Some(meta.params.padding),
                ),
            ),
            ("Time", seconds(elapsed)),
        ],
    );
    Ok(())
}
