//! End-to-end tests of the `oes` executable.

#[path = "../src/stream/test_util.rs"]
mod test_util;

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use test_util::TempDir;

/// Runs `oes` with `args` and returns its output.
fn oes<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_oes"))
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Every algorithm the program supports, as named on the command line.
const ALGORITHMS: [&str; 4] = ["des", "aes128", "aes192", "aes256"];

/// The modes `algorithm` supports: GCM needs AES.
fn modes_for(algorithm: &str) -> &'static [&'static str] {
    if algorithm == "des" {
        &["ecb", "cbc", "ctr"]
    } else {
        &["ecb", "cbc", "ctr", "gcm"]
    }
}

/// A temporary directory holding a freshly generated key for one algorithm.
struct Setup {
    dir: TempDir,
    algorithm: &'static str,
    key: PathBuf,
}

impl Setup {
    fn new(tag: &str, algorithm: &'static str) -> Self {
        let dir = TempDir::new(tag);
        let key = dir.path().join(format!("{algorithm}.key"));
        let args = [
            OsStr::new("keygen"),
            OsStr::new("-a"),
            OsStr::new(algorithm),
        ];
        let output = oes(args.into_iter().chain([OsStr::new("-o"), key.as_os_str()]));
        assert_success(&output, "keygen");
        Self {
            dir,
            algorithm,
            key,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn encrypt(&self, input: &Path, output: &Path, extra: &[&str]) -> Output {
        let mut args = vec![
            OsStr::new("encrypt"),
            OsStr::new("-i"),
            input.as_os_str(),
            OsStr::new("-o"),
            output.as_os_str(),
            OsStr::new("-k"),
            self.key.as_os_str(),
            OsStr::new("-a"),
            OsStr::new(self.algorithm),
        ];
        args.extend(extra.iter().map(OsStr::new));
        oes(args)
    }

    fn decrypt(&self, input: &Path, output: &Path, extra: &[&str]) -> Output {
        let mut args = vec![
            OsStr::new("decrypt"),
            OsStr::new("-i"),
            input.as_os_str(),
            OsStr::new("-o"),
            output.as_os_str(),
            OsStr::new("-k"),
            self.key.as_os_str(),
        ];
        args.extend(extra.iter().map(OsStr::new));
        oes(args)
    }
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

// ---- encrypt and decrypt ----

#[test]
fn round_trip_restores_every_algorithm_mode_and_length() {
    // 8 and 16 bytes are exactly one DES and one AES block.
    let cases: [(usize, &str); 5] = [
        (0, "65536"),
        (8, "65536"),
        (13, "65536"),
        (16, "65536"),
        (100, "16"),
    ];
    for algorithm in ALGORITHMS {
        let setup = Setup::new("cli", algorithm);
        for &mode in modes_for(algorithm) {
            for (len, buffer) in cases {
                let context = format!("{algorithm} {mode}, length {len}, buffer {buffer}");
                let (input, enc, restored) = (
                    setup.path("in.bin"),
                    setup.path("out.enc"),
                    setup.path("restored.bin"),
                );
                fs::write(&input, sample(len)).unwrap();

                let flags = ["-m", mode, "--buffer-size", buffer, "--force"];
                assert_success(&setup.encrypt(&input, &enc, &flags), &context);
                let flags = ["--buffer-size", buffer, "--force"];
                assert_success(&setup.decrypt(&enc, &restored, &flags), &context);
                assert_eq!(fs::read(&restored).unwrap(), sample(len), "{context}");
            }
        }
    }
}

/// Encrypting on several threads must give a container that one thread decrypts,
/// and the other way round. The input spans several pieces of parallel work.
#[test]
fn round_trip_works_across_thread_counts() {
    let len = 3 * 8192 + 5;
    for algorithm in ALGORITHMS {
        let setup = Setup::new("cli", algorithm);
        for &mode in modes_for(algorithm) {
            for (encrypt_threads, decrypt_threads) in [("4", "1"), ("1", "4")] {
                let context =
                    format!("{algorithm} {mode}, {encrypt_threads} threads to {decrypt_threads}");
                let (input, enc, restored) = (
                    setup.path("in.bin"),
                    setup.path("out.enc"),
                    setup.path("restored.bin"),
                );
                fs::write(&input, sample(len)).unwrap();

                let flags = [
                    "-m",
                    mode,
                    "--threads",
                    encrypt_threads,
                    "--verify",
                    "--force",
                ];
                assert_success(&setup.encrypt(&input, &enc, &flags), &context);
                let flags = ["--threads", decrypt_threads, "--force"];
                assert_success(&setup.decrypt(&enc, &restored, &flags), &context);
                assert_eq!(fs::read(&restored).unwrap(), sample(len), "{context}");
            }
        }
    }
}

#[test]
fn encrypt_draws_a_fresh_iv_each_time() {
    let setup = Setup::new("cli", "des");
    let input = setup.path("in.bin");
    fs::write(&input, sample(64)).unwrap();
    let (first, second) = (setup.path("1.enc"), setup.path("2.enc"));
    assert_success(&setup.encrypt(&input, &first, &["-m", "cbc"]), "first");
    assert_success(&setup.encrypt(&input, &second, &["-m", "cbc"]), "second");
    assert_ne!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
}

#[test]
fn encrypt_refuses_padding_with_ctr_and_gcm_with_des() {
    let setup = Setup::new("cli", "des");
    let input = setup.path("in.bin");
    fs::write(&input, sample(16)).unwrap();
    for flags in [["-m", "ctr", "-p", "pkcs7"].as_slice(), &["-m", "gcm"]] {
        let output = setup.encrypt(&input, &setup.path("out.enc"), flags);
        assert!(!output.status.success(), "{flags:?}");
        assert!(!setup.path("out.enc").exists(), "{flags:?}");
    }
}

#[test]
fn encrypt_with_verify_succeeds() {
    let setup = Setup::new("cli", "des");
    let input = setup.path("in.bin");
    fs::write(&input, sample(1000)).unwrap();
    let flags = ["-m", "cbc", "--verify", "--buffer-size", "64"];
    assert_success(
        &setup.encrypt(&input, &setup.path("out.enc"), &flags),
        "verify",
    );
}

#[test]
fn decrypt_of_a_truncated_container_fails_without_output() {
    let setup = Setup::new("cli", "des");
    let input = setup.path("in.bin");
    fs::write(&input, sample(100)).unwrap();
    // CBC fails on the ciphertext length, CTR on the length the header records.
    for mode in ["cbc", "ctr"] {
        let (enc, restored) = (setup.path("out.enc"), setup.path("restored.bin"));
        assert_success(&setup.encrypt(&input, &enc, &["-m", mode, "--force"]), mode);
        let mut bytes = fs::read(&enc).unwrap();
        bytes.truncate(bytes.len() - 3);
        fs::write(&enc, bytes).unwrap();

        let output = setup.decrypt(&enc, &restored, &[]);
        assert!(!output.status.success(), "mode {mode}");
        // Neither the output nor its temporary file is left behind.
        assert_eq!(
            setup.dir.entries(),
            ["des.key", "in.bin", "out.enc"],
            "mode {mode}"
        );
    }
}

#[test]
fn decrypt_of_a_changed_gcm_container_fails_without_output() {
    let setup = Setup::new("cli", "aes128");
    let input = setup.path("in.bin");
    fs::write(&input, sample(100)).unwrap();
    let (enc, restored) = (setup.path("out.enc"), setup.path("restored.bin"));
    assert_success(&setup.encrypt(&input, &enc, &["-m", "gcm"]), "encrypt");
    let original = fs::read(&enc).unwrap();

    // The image type in the header (still a valid code), the nonce, the
    // ciphertext and the tag.
    for position in [5, 20, 60, original.len() - 1] {
        let mut bytes = original.clone();
        bytes[position] ^= 1;
        fs::write(&enc, bytes).unwrap();

        let output = setup.decrypt(&enc, &restored, &[]);
        assert!(!output.status.success(), "byte {position}");
        assert_eq!(
            setup.dir.entries(),
            ["aes128.key", "in.bin", "out.enc"],
            "byte {position}"
        );
    }
}

// ---- pixel-encrypt and pixel-decrypt ----

#[test]
fn pixel_round_trip_restores_the_image_in_every_mode() {
    // 7x5 pixels are 105 bytes, so the last block is partial.
    let picture = image::RgbImage::from_fn(7, 5, |x, y| {
        image::Rgb([(x * 37) as u8, (y * 91) as u8, (x * y + 11) as u8])
    });
    for algorithm in ALGORITHMS {
        let setup = Setup::new("cli-pixels", algorithm);
        for &mode in modes_for(algorithm) {
            for extension in ["png", "bmp"] {
                let context = format!("{algorithm} {mode}, {extension}");
                let input = setup.path(&format!("in.{extension}"));
                let encrypted = setup.path(&format!("enc.{extension}"));
                let restored = setup.path(&format!("restored.{extension}"));
                picture.save(&input).unwrap();

                let mut args = vec![OsStr::new("pixel-encrypt"), OsStr::new("-i")];
                args.extend([input.as_os_str(), OsStr::new("-o"), encrypted.as_os_str()]);
                args.extend([OsStr::new("-k"), setup.key.as_os_str()]);
                args.extend(["-a", algorithm, "-m", mode, "--force"].map(OsStr::new));
                assert_success(&oes(args), &context);
                let encrypted_image = image::open(&encrypted).unwrap().to_rgb8();
                assert_eq!(encrypted_image.dimensions(), (7, 5), "{context}");
                assert_ne!(encrypted_image, picture, "{context}");

                let mut args = vec![OsStr::new("pixel-decrypt"), OsStr::new("-i")];
                args.extend([
                    encrypted.as_os_str(),
                    OsStr::new("-o"),
                    restored.as_os_str(),
                ]);
                args.extend([
                    OsStr::new("-k"),
                    setup.key.as_os_str(),
                    OsStr::new("--force"),
                ]);
                assert_success(&oes(args), &context);
                assert_eq!(
                    image::open(&restored).unwrap().to_rgb8(),
                    picture,
                    "{context}"
                );
            }
        }
    }
}

#[test]
fn pixel_encrypt_refuses_padding_with_ctr_and_gcm_with_des() {
    let setup = Setup::new("cli-pixels", "des");
    let input = setup.path("in.png");
    image::RgbImage::new(4, 4).save(&input).unwrap();
    let encrypted = setup.path("enc.png");
    for flags in [["-m", "ctr", "-p", "pkcs7"].as_slice(), &["-m", "gcm"]] {
        let mut args = vec![OsStr::new("pixel-encrypt"), OsStr::new("-i")];
        args.extend([input.as_os_str(), OsStr::new("-o"), encrypted.as_os_str()]);
        args.extend([OsStr::new("-k"), setup.key.as_os_str()]);
        args.extend(flags.iter().map(OsStr::new));
        assert!(!oes(args).status.success(), "{flags:?}");
        assert!(!encrypted.exists(), "{flags:?}");
        assert!(!setup.path("enc.png.pixmeta").exists(), "{flags:?}");
    }
}

/// `--threads` works on either side of the command name, and the pixel modes
/// give the same image on several threads. 128x64 pixels are more than 1024
/// blocks for both DES and AES, so the work splits into several pieces.
#[test]
fn pixel_round_trip_with_threads_before_and_after_the_command() {
    let picture = image::RgbImage::from_fn(128, 64, |x, y| {
        image::Rgb([(x * 37) as u8, (y * 91) as u8, (x * y + 11) as u8])
    });
    for algorithm in ["des", "aes128"] {
        let setup = Setup::new("cli-pixels", algorithm);
        let (input, encrypted, restored) = (
            setup.path("in.png"),
            setup.path("enc.png"),
            setup.path("restored.png"),
        );
        picture.save(&input).unwrap();
        for &mode in modes_for(algorithm) {
            let context = format!("{algorithm} {mode}");
            let mut args = ["--threads", "4", "pixel-encrypt", "-i"]
                .map(OsStr::new)
                .to_vec();
            args.extend([input.as_os_str(), OsStr::new("-o"), encrypted.as_os_str()]);
            args.extend([OsStr::new("-k"), setup.key.as_os_str()]);
            args.extend(["-a", algorithm, "-m", mode, "--force"].map(OsStr::new));
            assert_success(&oes(args), &context);

            let mut args = vec![OsStr::new("pixel-decrypt"), OsStr::new("-i")];
            args.extend([
                encrypted.as_os_str(),
                OsStr::new("-o"),
                restored.as_os_str(),
            ]);
            args.extend([OsStr::new("-k"), setup.key.as_os_str()]);
            args.extend(["--force", "--threads", "4"].map(OsStr::new));
            assert_success(&oes(args), &context);
            assert_eq!(
                image::open(&restored).unwrap().to_rgb8(),
                picture,
                "{context}"
            );
        }
    }
}
