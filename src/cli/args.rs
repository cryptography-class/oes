use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use oes::container::{Algorithm, Mode};
use oes::padding::{Fill, Padding};
use oes::stream::{DEFAULT_BUFFER_SIZE, MAX_BUFFER_SIZE};

/// Encrypts and decrypts files with from-scratch block ciphers.
///
/// This is an educational program. DES and ECB are broken and must not be used
/// to protect real data.
#[derive(Parser)]
#[command(name = "oes", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate a random key and save it to a binary file.
    Keygen(KeygenArgs),
    /// Encrypt a file into a container.
    Encrypt(EncryptArgs),
    /// Restore the original file from a container.
    Decrypt(DecryptArgs),
}

#[derive(Args)]
pub struct KeygenArgs {
    /// Algorithm the key is for.
    #[arg(short, long, value_enum, default_value = "des")]
    pub algorithm: AlgorithmArg,
    /// Key file to create.
    #[arg(short, long)]
    pub output: PathBuf,
    /// Replace the output file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct EncryptArgs {
    /// File to encrypt.
    #[arg(short, long)]
    pub input: PathBuf,
    /// Container file to create.
    #[arg(short, long)]
    pub output: PathBuf,
    /// Binary key file, as created by keygen.
    #[arg(short, long)]
    pub key: PathBuf,
    /// Encryption algorithm.
    #[arg(short, long, value_enum, default_value = "des")]
    pub algorithm: AlgorithmArg,
    /// Mode of operation.
    #[arg(short, long, value_enum)]
    pub mode: ModeArg,
    /// Padding scheme for ECB and CBC [default: pkcs7]. Not allowed with CTR.
    #[arg(short, long, value_enum)]
    pub padding: Option<PaddingArg>,
    /// Size of the read and write buffer, in bytes.
    #[arg(long, default_value_t = DEFAULT_BUFFER_SIZE as u64,
          value_parser = clap::value_parser!(u64).range(1..=MAX_BUFFER_SIZE as u64))]
    pub buffer_size: u64,
    /// After encrypting, decrypt the result and compare it with the input.
    #[arg(long)]
    pub verify: bool,
    /// Replace the output file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct DecryptArgs {
    /// Container file to decrypt.
    #[arg(short, long)]
    pub input: PathBuf,
    /// File to restore.
    #[arg(short, long)]
    pub output: PathBuf,
    /// Binary key file used to encrypt.
    #[arg(short, long)]
    pub key: PathBuf,
    /// Size of the read and write buffer, in bytes.
    #[arg(long, default_value_t = DEFAULT_BUFFER_SIZE as u64,
          value_parser = clap::value_parser!(u64).range(1..=MAX_BUFFER_SIZE as u64))]
    pub buffer_size: u64,
    /// Replace the output file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum AlgorithmArg {
    /// DES, with a 56-bit key. Broken; for demonstration only.
    Des,
}

impl From<AlgorithmArg> for Algorithm {
    fn from(algorithm: AlgorithmArg) -> Self {
        match algorithm {
            AlgorithmArg::Des => Algorithm::Des,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ModeArg {
    /// Electronic codebook. Leaks patterns; for demonstration only.
    Ecb,
    /// Cipher block chaining.
    Cbc,
    /// Counter mode, with no padding.
    Ctr,
}

impl From<ModeArg> for Mode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Ecb => Mode::Ecb,
            ModeArg::Cbc => Mode::Cbc,
            ModeArg::Ctr => Mode::Ctr,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PaddingArg {
    /// PKCS#7.
    Pkcs7,
    /// PKCS#5.
    Pkcs5,
    /// ANSI X9.23 with zero fill.
    X923Zeros,
    /// ANSI X9.23 with random fill.
    X923Random,
}

impl From<PaddingArg> for Padding {
    fn from(padding: PaddingArg) -> Self {
        match padding {
            PaddingArg::Pkcs7 => Padding::Pkcs7,
            PaddingArg::Pkcs5 => Padding::Pkcs5,
            PaddingArg::X923Zeros => Padding::AnsiX923(Fill::Zeros),
            PaddingArg::X923Random => Padding::AnsiX923(Fill::Random),
        }
    }
}
