use std::io::{Read, Write};

use super::errors::StreamError;
use super::io_util::{ByteCounts, WipedBuf, aligned_capacity, read_full};
use crate::modes::BlockMode;
use crate::padding::Padding;

/// The default buffer size: 1 MiB.
pub const DEFAULT_BUFFER_SIZE: usize = 1 << 20;

/// Encrypts everything from `reader` into `writer` and adds padding at the end.
///
/// The output is always longer than the input, because block-aligned input gains a
/// full padding block.
///
/// # Arguments
///
/// - `mode`: a new mode instance, built with its key and IV.
/// - `padding`: the scheme to add, which decryption must match.
/// - `reader`, `writer`: the input and the output.
/// - `buf_size`: the memory to use, capped at [`MAX_BUFFER_SIZE`](super::MAX_BUFFER_SIZE)
///   and rounded down to whole blocks, with a minimum of one block.
///
/// # Errors
///
/// - [`StreamError::Padding`] if `padding` doesn't allow this block size, before
///   anything is read, or if random fill can't be generated.
/// - [`StreamError::Io`] if reading or writing fails.
/// - [`StreamError::Mode`] if the mode refuses the data.
///
/// # Examples
///
/// ```
/// use std::io::Cursor;
///
/// use oes::ciphers::des::DesCipher;
/// use oes::ciphers::traits::KeyInit;
/// use oes::modes::Cbc;
/// use oes::padding::Padding;
/// use oes::stream::{decrypt_stream, encrypt_stream};
///
/// // A real IV must be random for each message.
/// let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
/// let iv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
///
/// let mut ciphertext = Vec::new();
/// let mut mode = Cbc::new(DesCipher::new(&key), &iv).unwrap();
/// encrypt_stream(&mut mode, Padding::Pkcs7, &mut Cursor::new(b"hello"), &mut ciphertext, 64)
///     .unwrap();
/// assert_eq!(ciphertext.len(), 8);
///
/// let mut plaintext = Vec::new();
/// let mut mode = Cbc::new(DesCipher::new(&key), &iv).unwrap();
/// decrypt_stream(&mut mode, Padding::Pkcs7, &mut Cursor::new(&ciphertext), &mut plaintext, 64)
///     .unwrap();
/// assert_eq!(plaintext, b"hello");
/// ```
pub fn encrypt_stream<M, R, W>(
    mode: &mut M,
    padding: Padding,
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<ByteCounts, StreamError>
where
    M: BlockMode + ?Sized,
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let block_size = mode.block_size();
    padding.check_block_size(block_size)?;

    let capacity = aligned_capacity(buf_size, block_size);
    let mut buf = WipedBuf::new(capacity);
    let mut last = WipedBuf::new(block_size);
    let mut counts = ByteCounts::default();

    loop {
        let n = read_full(reader, &mut buf)?;
        counts.bytes_in += n as u64;

        let whole = n - n % block_size;
        if whole > 0 {
            mode.encrypt_blocks(&mut buf[..whole])?;

            writer.write_all(&buf[..whole])?;
            counts.bytes_out += whole as u64;
        }

        // A short read means the input ended. After an exactly full buffer the next
        // round reads 0 bytes and emits a full padding block, as aligned input needs.
        if n < capacity {
            padding.pad_final(&buf[whole..n], &mut last)?;

            mode.encrypt_blocks(&mut last)?;

            writer.write_all(&last)?;
            counts.bytes_out += block_size as u64;
            break;
        }
    }

    writer.flush()?;
    Ok(counts)
}

/// Decrypts everything from `reader` into `writer` and removes the padding.
///
/// The padding is in the last block, which is only known once the input ends. So the
/// final block of each full buffer stays encrypted and moves to the next round.
///
/// **On error, `writer` may already hold earlier plaintext.** Pass an
/// [`AtomicFile`](super::AtomicFile) and commit it only on `Ok`.
///
/// # Arguments
///
/// - `mode`: a new mode instance, built with the key and IV used to encrypt.
/// - `padding`: the scheme used to encrypt.
/// - `reader`, `writer`: the input and the output.
/// - `buf_size`: the memory to use, capped at [`MAX_BUFFER_SIZE`](super::MAX_BUFFER_SIZE)
///   and rounded down to whole blocks, with a minimum of one block. One
///   more block is added for the block held back.
///
/// # Errors
///
/// - [`StreamError::Padding`] if `padding` doesn't allow this block size, before
///   anything is read, or if the padding is wrong, which is also the usual result of
///   a wrong key.
/// - [`StreamError::InvalidCiphertextLength`] if the input is empty or not a whole
///   number of blocks.
/// - [`StreamError::Io`] if reading or writing fails.
/// - [`StreamError::Mode`] if the mode refuses the data.
pub fn decrypt_stream<M, R, W>(
    mode: &mut M,
    padding: Padding,
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<ByteCounts, StreamError>
where
    M: BlockMode + ?Sized,
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let block_size = mode.block_size();
    padding.check_block_size(block_size)?;

    let mut buf = WipedBuf::new(aligned_capacity(buf_size, block_size) + block_size);
    let mut counts = ByteCounts::default();
    let mut carried = 0; // 0 in the first round, then one block

    loop {
        let wanted = buf.len() - carried;
        let n = read_full(reader, &mut buf[carried..])?;
        counts.bytes_in += n as u64;
        let total = carried + n;

        if n < wanted {
            // The input ended, so the data held now finishes with the padded block.
            if total == 0 || !total.is_multiple_of(block_size) {
                return Err(StreamError::InvalidCiphertextLength {
                    len: counts.bytes_in,
                    block_size,
                });
            }

            mode.decrypt_blocks(&mut buf[..total])?;

            // Check the padding before writing anything from this last stretch.
            let last_block = total - block_size;
            let end = last_block + padding.unpad_block(&buf[last_block..total])?;

            writer.write_all(&buf[..end])?;
            counts.bytes_out += end as u64;
            break;
        }

        // The buffer is full, so more data may follow: decrypt all but the last
        // block, and keep that block encrypted for the next round.
        let process = total - block_size;

        mode.decrypt_blocks(&mut buf[..process])?;

        writer.write_all(&buf[..process])?;
        counts.bytes_out += process as u64;

        buf.copy_within(process..total, 0);
        carried = block_size;
    }

    writer.flush()?;
    Ok(counts)
}
