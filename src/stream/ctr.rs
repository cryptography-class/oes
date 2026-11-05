use std::io::{Read, Write};

use super::errors::StreamError;
use super::io_util::{ByteCounts, WipedBuf, aligned_capacity, read_full};
use crate::ciphers::traits::BlockCipher;
use crate::modes::Ctr;

/// Encrypts or decrypts everything from `reader` into `writer` in CTR mode.
///
/// The output has the same length as the input, and both directions are the same
/// operation. **A wrong key or starting counter gives wrong bytes with no error**,
/// because CTR has no padding or other check.
///
/// # Arguments
///
/// - `mode`: a new mode instance, built with its key and starting counter.
/// - `reader`, `writer`: the input and the output.
/// - `buf_size`: the memory to use, capped at [`MAX_BUFFER_SIZE`](super::MAX_BUFFER_SIZE)
///   and rounded down to whole blocks, with a minimum of one block.
///
/// # Errors
///
/// - [`StreamError::Io`] if reading or writing fails.
/// - [`StreamError::Mode`] if `mode` already finished a message that ended in a
///   partial block.
///
/// # Examples
///
/// ```
/// use std::io::Cursor;
///
/// use oes::ciphers::des::DesCipher;
/// use oes::ciphers::traits::KeyInit;
/// use oes::modes::Ctr;
/// use oes::stream::apply_ctr_stream;
///
/// // A real starting counter must be unique for the key.
/// let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
/// let counter = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
///
/// let mut ciphertext = Vec::new();
/// let mut mode = Ctr::new(DesCipher::new(&key), &counter).unwrap();
/// apply_ctr_stream(&mut mode, &mut Cursor::new(b"no padding"), &mut ciphertext, 64).unwrap();
/// assert_eq!(ciphertext.len(), 10);
///
/// let mut plaintext = Vec::new();
/// let mut mode = Ctr::new(DesCipher::new(&key), &counter).unwrap();
/// apply_ctr_stream(&mut mode, &mut Cursor::new(&ciphertext), &mut plaintext, 64).unwrap();
/// assert_eq!(plaintext, b"no padding");
/// ```
pub fn apply_ctr_stream<C, R, W>(
    mode: &mut Ctr<C>,
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<ByteCounts, StreamError>
where
    C: BlockCipher,
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let capacity = aligned_capacity(buf_size, C::BLOCK_SIZE);
    let mut buf = WipedBuf::new(capacity);
    let mut counts = ByteCounts::default();

    loop {
        // `read_full` is short only at the end of the input, so every chunk before
        // the last is whole blocks, as `Ctr` requires.
        let n = read_full(reader, &mut buf)?;
        counts.bytes_in += n as u64;

        mode.apply_keystream(&mut buf[..n])?;

        writer.write_all(&buf[..n])?;
        counts.bytes_out += n as u64;

        if n < capacity {
            break;
        }
    }

    writer.flush()?;
    Ok(counts)
}
