use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use oes::ciphers::des::DesCipher;
use oes::ciphers::traits::{BlockCipher, KeyInit};
use oes::container::{Algorithm, Header, ImageType, Mode};
use oes::keys::Key;
use oes::modes::{BlockMode, Cbc, Ctr, Ecb};
use oes::padding::{Fill, Padding};
use oes::random::random_bytes;
use oes::secret::wipe;
use oes::stream::{AtomicFile, ByteCounts, apply_ctr_stream, decrypt_stream, encrypt_stream};

use super::args::{Cli, Command, DecryptArgs, EncryptArgs, KeygenArgs};
use super::memory::peak_heap_bytes;

type CliResult<T> = Result<T, Box<dyn Error>>;

const MIB: f64 = 1024.0 * 1024.0;

/// Runs the parsed command.
pub fn run(cli: Cli) -> CliResult<()> {
    match cli.command {
        Command::Keygen(args) => keygen(&args),
        Command::Encrypt(args) => encrypt(&args),
        Command::Decrypt(args) => decrypt(&args),
    }
}

fn keygen(args: &KeygenArgs) -> CliResult<()> {
    let key = Key::generate(Algorithm::from(args.algorithm))?;
    key.save(&args.output, args.force)?;
    print_table(
        "keygen",
        &[
            ("Key file", args.output.display().to_string()),
            ("Algorithm", algorithm_name(key.algorithm()).to_string()),
            ("Length", format!("{} bytes", key.algorithm().key_len())),
        ],
    );
    Ok(())
}

fn encrypt(args: &EncryptArgs) -> CliResult<()> {
    let started = Instant::now();
    let algorithm = Algorithm::from(args.algorithm);
    let mode = Mode::from(args.mode);
    let padding = match (mode, args.padding) {
        (Mode::Ctr, Some(_)) => return Err("CTR mode takes no padding, so leave out -p".into()),
        (Mode::Ctr, None) => None,
        (_, padding) => Some(padding.map_or(Padding::Pkcs7, Padding::from)),
    };
    let buffer_size = args.buffer_size as usize;

    let mut input = File::open(&args.input).map_err(|e| with_path(&args.input, e))?;
    let original_len = input.metadata()?.len();
    let mut prefix = Vec::with_capacity(8);
    Read::take(&mut input, 8).read_to_end(&mut prefix)?;
    input.seek(SeekFrom::Start(0))?;

    let key = Key::load(algorithm, &args.key)?;
    let header = Header {
        image_type: ImageType::from_signature(&prefix),
        algorithm,
        mode,
        padding,
        iv: random_bytes(mode.iv_len(algorithm))?,
        original_len,
    };

    let mut output = AtomicFile::create(&args.output, args.force)?;
    header.write_to(&mut output)?;
    let counts = run_cipher(
        &header,
        &key,
        Direction::Encrypt,
        &mut input,
        &mut output,
        buffer_size,
    )?;
    if counts.bytes_in != original_len {
        return Err(format!(
            "{} changed while it was being encrypted",
            args.input.display()
        )
        .into());
    }
    output.commit()?;
    let elapsed = started.elapsed();

    if args.verify {
        verify(&args.output, &args.input, &key, buffer_size)?;
    }

    print_table(
        "encrypt",
        &[
            (
                "Input",
                format!(
                    "{} ({:?}, {original_len} bytes)",
                    args.input.display(),
                    header.image_type
                ),
            ),
            ("Output", file_with_size(&args.output)?),
            ("Cipher", cipher_name(&header)),
            ("Buffer", format!("{buffer_size} bytes")),
            ("Time", seconds(elapsed)),
            ("Throughput", throughput(original_len, elapsed)),
            ("Peak heap", mib(peak_heap_bytes() as u64)),
        ],
    );
    Ok(())
}

fn decrypt(args: &DecryptArgs) -> CliResult<()> {
    let started = Instant::now();
    let buffer_size = args.buffer_size as usize;

    let mut input = File::open(&args.input).map_err(|e| with_path(&args.input, e))?;
    let header = Header::read_from(&mut input)?;
    let key = Key::load(header.algorithm, &args.key)?;

    let mut output = AtomicFile::create(&args.output, args.force)?;
    decrypt_into(&header, &key, &mut input, &mut output, buffer_size)?;
    output.commit()?;
    let elapsed = started.elapsed();

    print_table(
        "decrypt",
        &[
            ("Input", file_with_size(&args.input)?),
            (
                "Output",
                format!(
                    "{} ({:?}, {} bytes)",
                    args.output.display(),
                    header.image_type,
                    header.original_len
                ),
            ),
            ("Cipher", cipher_name(&header)),
            ("Buffer", format!("{buffer_size} bytes")),
            ("Time", seconds(elapsed)),
            ("Throughput", throughput(header.original_len, elapsed)),
            ("Peak heap", mib(peak_heap_bytes() as u64)),
        ],
    );
    Ok(())
}

/// Which way data goes through the cipher.
#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// Builds the cipher named in `header` and streams the data through it.
///
/// This is the one place where an algorithm is connected: a new cipher adds an
/// arm here.
fn run_cipher<R: Read, W: Write>(
    header: &Header,
    key: &Key,
    direction: Direction,
    reader: &mut R,
    writer: &mut W,
    buffer_size: usize,
) -> CliResult<ByteCounts> {
    match header.algorithm {
        Algorithm::Des => run_mode(
            DesCipher::new(key.as_array::<8>()?),
            header,
            direction,
            reader,
            writer,
            buffer_size,
        ),
    }
}

/// Builds the mode named in `header` around `cipher` and streams the data
/// through it.
///
/// This is the one place where a mode is built, so options such as a thread
/// count belong here.
fn run_mode<C: BlockCipher, R: Read, W: Write>(
    cipher: C,
    header: &Header,
    direction: Direction,
    reader: &mut R,
    writer: &mut W,
    buffer_size: usize,
) -> CliResult<ByteCounts> {
    let counts = match header.mode {
        Mode::Ecb => run_padded(
            &mut Ecb::new(cipher),
            header,
            direction,
            reader,
            writer,
            buffer_size,
        )?,
        Mode::Cbc => run_padded(
            &mut Cbc::new(cipher, &header.iv)?,
            header,
            direction,
            reader,
            writer,
            buffer_size,
        )?,
        // CTR is its own inverse, so both directions are the same operation.
        Mode::Ctr => apply_ctr_stream(
            &mut Ctr::new(cipher, &header.iv)?,
            reader,
            writer,
            buffer_size,
        )?,
    };
    Ok(counts)
}

/// Streams the data through a padded mode (ECB or CBC).
fn run_padded<M: BlockMode, R: Read, W: Write>(
    mode: &mut M,
    header: &Header,
    direction: Direction,
    reader: &mut R,
    writer: &mut W,
    buffer_size: usize,
) -> CliResult<ByteCounts> {
    let padding = header.padding.ok_or("ECB and CBC need a padding scheme")?;
    let counts = match direction {
        Direction::Encrypt => encrypt_stream(mode, padding, reader, writer, buffer_size)?,
        Direction::Decrypt => decrypt_stream(mode, padding, reader, writer, buffer_size)?,
    };
    Ok(counts)
}

/// Decrypts the ciphertext after `header` into `writer`, and checks that the
/// output has the length the header records.
fn decrypt_into<R: Read, W: Write>(
    header: &Header,
    key: &Key,
    reader: &mut R,
    writer: &mut W,
    buffer_size: usize,
) -> CliResult<ByteCounts> {
    let counts = run_cipher(header, key, Direction::Decrypt, reader, writer, buffer_size)?;
    if counts.bytes_out != header.original_len {
        return Err(format!(
            "decrypted {} bytes, but the header records {} (truncated or corrupted file)",
            counts.bytes_out, header.original_len
        )
        .into());
    }
    Ok(counts)
}

/// Decrypts `container` and compares the result with `original`, without
/// writing anything to disk.
fn verify(container: &Path, original: &Path, key: &Key, buffer_size: usize) -> CliResult<()> {
    let mut input = File::open(container)?;
    let header = Header::read_from(&mut input)?;
    let mut writer = CompareWriter {
        original: File::open(original)?,
        position: 0,
        scratch: Vec::new(),
        mismatch: None,
    };

    let result = decrypt_into(&header, key, &mut input, &mut writer, buffer_size);
    if let Some(position) = writer.mismatch {
        return Err(format!(
            "verification failed: the decrypted data differs from {} at byte {position}",
            original.display()
        )
        .into());
    }
    result?;
    if writer.original.read(&mut [0u8; 1])? != 0 {
        return Err(format!(
            "verification failed: {} is longer than the decrypted data",
            original.display()
        )
        .into());
    }
    Ok(())
}

/// A writer that compares everything written to it with `original`, so a
/// decryption can be checked without storing it.
struct CompareWriter {
    original: File,
    /// How many bytes matched so far.
    position: u64,
    scratch: Vec<u8>,
    /// The position of the first difference, including the original ending early.
    mismatch: Option<u64>,
}

impl Write for CompareWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.scratch.resize(buf.len(), 0);
        let filled = read_up_to(&mut self.original, &mut self.scratch)?;
        let differs = buf
            .iter()
            .zip(&self.scratch[..filled])
            .position(|(a, b)| a != b);
        match differs {
            Some(i) => self.mismatch = Some(self.position + i as u64),
            None if filled < buf.len() => self.mismatch = Some(self.position + filled as u64),
            None => {
                self.position += buf.len() as u64;
                return Ok(buf.len());
            }
        }
        Err(io::Error::other(
            "the decrypted data differs from the original",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for CompareWriter {
    fn drop(&mut self) {
        wipe(&mut self.scratch);
    }
}

/// Reads until `buf` is full or the input ends, and returns the bytes read.
fn read_up_to(reader: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn with_path(path: &Path, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

fn print_table(title: &str, rows: &[(&str, String)]) {
    println!("{title}");
    for (name, value) in rows {
        println!("  {name:<11} {value}");
    }
}

fn file_with_size(path: &Path) -> CliResult<String> {
    let len = fs::metadata(path)?.len();
    Ok(format!("{} ({len} bytes)", path.display()))
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Des => "DES",
    }
}

fn cipher_name(header: &Header) -> String {
    let mode = match header.mode {
        Mode::Ecb => "ECB",
        Mode::Cbc => "CBC",
        Mode::Ctr => "CTR",
    };
    let padding = match header.padding {
        None => "no padding",
        Some(Padding::Pkcs7) => "PKCS#7",
        Some(Padding::Pkcs5) => "PKCS#5",
        Some(Padding::AnsiX923(Fill::Zeros)) => "ANSI X9.23 with zeros",
        Some(Padding::AnsiX923(Fill::Random)) => "ANSI X9.23 with random bytes",
    };
    format!("{} {mode}, {padding}", algorithm_name(header.algorithm))
}

fn seconds(elapsed: Duration) -> String {
    format!("{:.3} s", elapsed.as_secs_f64())
}

fn throughput(bytes: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64().max(1e-9);
    format!("{:.1} MiB/s", bytes as f64 / MIB / secs)
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / MIB)
}
