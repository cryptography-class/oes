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
const ALGORITHMS: [&str; 1] = ["des"];

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
    let cases: [(usize, &str); 4] = [(0, "65536"), (8, "65536"), (13, "65536"), (100, "16")];
    for algorithm in ALGORITHMS {
        let setup = Setup::new("cli", algorithm);
        for mode in ["ecb", "cbc", "ctr"] {
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
        for mode in ["ecb", "cbc", "ctr"] {
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
fn encrypt_refuses_padding_with_ctr() {
    let setup = Setup::new("cli", "des");
    let input = setup.path("in.bin");
    fs::write(&input, sample(16)).unwrap();
    let output = setup.encrypt(
        &input,
        &setup.path("out.enc"),
        &["-m", "ctr", "-p", "pkcs7"],
    );
    assert!(!output.status.success());
    assert!(!setup.path("out.enc").exists());
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
