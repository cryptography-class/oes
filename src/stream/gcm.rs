use std::io::{Read, Write};

use super::errors::StreamError;
use super::io_util::{ByteCounts, WipedBuf, aligned_capacity, read_full};
use crate::ciphers::traits::BlockCipher;
use crate::modes::gcm::TAG_LEN;
use crate::modes::{GcmDecryptor, GcmEncryptor};

/// The GCM block size. Every chunk but the last must be a whole number of blocks.
const BLOCK_LEN: usize = 16;

/// Encrypts everything from `reader` into `writer` in GCM, and appends the
/// [`TAG_LEN`]-byte tag.
///
/// The output is the ciphertext, as long as the input, followed by the tag.
///
/// # Arguments
///
/// - `encryptor`: a new encryptor, built with its key, a fresh nonce and the AAD.
/// - `reader`, `writer`: the input and the output.
/// - `buf_size`: the memory to use, capped at [`MAX_BUFFER_SIZE`](super::MAX_BUFFER_SIZE)
///   and rounded down to whole blocks, with a minimum of one block.
///
/// # Errors
///
/// - [`StreamError::Io`] if reading or writing fails.
/// - [`StreamError::Mode`] if the input is longer than
///   [`MAX_PLAINTEXT_LEN`](crate::modes::gcm::MAX_PLAINTEXT_LEN).
///
/// # Examples
///
/// ```
/// use std::io::Cursor;
///
/// use oes::ciphers::aes::Aes128Cipher;
/// use oes::ciphers::traits::KeyInit;
/// use oes::modes::{GcmDecryptor, GcmEncryptor};
/// use oes::stream::{decrypt_gcm_stream, encrypt_gcm_stream};
///
/// // A real nonce must be unique for the key.
/// let key = [0x2B; 16];
/// let nonce = [0x5A; 12];
///
/// let mut sealed = Vec::new();
/// let encryptor = GcmEncryptor::new(Aes128Cipher::new(&key), &nonce, b"header").unwrap();
/// encrypt_gcm_stream(encryptor, &mut Cursor::new(b"any length"), &mut sealed, 64).unwrap();
/// assert_eq!(sealed.len(), 10 + 16);
///
/// let mut plaintext = Vec::new();
/// let decryptor = GcmDecryptor::new(Aes128Cipher::new(&key), &nonce, b"header").unwrap();
/// decrypt_gcm_stream(decryptor, &mut Cursor::new(&sealed), &mut plaintext, 64).unwrap();
/// assert_eq!(plaintext, b"any length");
/// ```
pub fn encrypt_gcm_stream<C, R, W>(
    mut encryptor: GcmEncryptor<C>,
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<ByteCounts, StreamError>
where
    C: BlockCipher,
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let capacity = aligned_capacity(buf_size, BLOCK_LEN);
    let mut buf = WipedBuf::new(capacity);
    let mut counts = ByteCounts::default();

    loop {
        // `read_full` is short only at the end of the input, so every chunk before
        // the last is whole blocks, as GCM requires.
        let n = read_full(reader, &mut buf)?;
        counts.bytes_in += n as u64;

        encryptor.update(&mut buf[..n])?;

        writer.write_all(&buf[..n])?;
        counts.bytes_out += n as u64;

        if n < capacity {
            break;
        }
    }

    writer.write_all(&encryptor.finish())?;
    counts.bytes_out += TAG_LEN as u64;
    writer.flush()?;
    Ok(counts)
}

/// Decrypts everything from `reader` into `writer` in GCM, and checks the tag at
/// the end of the input.
///
/// **Plaintext reaches `writer` before the tag can be checked**, because the input
/// may not fit in memory. After an error everything written must be discarded:
/// write through [`AtomicFile`](super::AtomicFile) and commit only on `Ok`.
///
/// The end of the input can only be recognised once it arrives, so the last
/// [`TAG_LEN`] bytes read are always held back as the possible tag.
///
/// # Arguments
///
/// As for [`encrypt_gcm_stream`], with a decryptor built with the same key, nonce
/// and AAD.
///
/// # Errors
///
/// - [`StreamError::Io`] if reading or writing fails.
/// - [`StreamError::MissingTag`] if the input is shorter than a tag.
/// - [`StreamError::Mode`] with
///   [`ModeError::AuthenticationFailed`](crate::modes::errors::ModeError::AuthenticationFailed)
///   if the key, nonce, AAD, ciphertext or tag is wrong, or with
///   [`ModeError::MessageTooLong`](crate::modes::errors::ModeError::MessageTooLong)
///   if the ciphertext is longer than one nonce allows.
pub fn decrypt_gcm_stream<C, R, W>(
    mut decryptor: GcmDecryptor<C>,
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<ByteCounts, StreamError>
where
    C: BlockCipher,
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let capacity = aligned_capacity(buf_size, BLOCK_LEN);
    // `capacity` bytes to decrypt, plus the possible tag after them.
    let mut buf = WipedBuf::new(capacity + TAG_LEN);
    let mut counts = ByteCounts::default();
    // Bytes kept from the previous round: none at first, then the possible tag.
    let mut carry = 0;

    let (end, tag) = loop {
        let n = read_full(reader, &mut buf[carry..])?;
        counts.bytes_in += n as u64;
        let total = carry + n;

        if total < buf.len() {
            // The input ended, so the tag is the last `TAG_LEN` bytes held.
            let end = total.checked_sub(TAG_LEN).ok_or(StreamError::MissingTag {
                len: counts.bytes_in,
            })?;
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&buf[end..total]);
            break (end, tag);
        }

        // The buffer is full, so more may follow: decrypt `capacity` bytes, a whole
        // number of blocks, and keep the rest in case it is the tag.
        decryptor.update(&mut buf[..capacity])?;
        writer.write_all(&buf[..capacity])?;
        counts.bytes_out += capacity as u64;

        buf.copy_within(capacity.., 0);
        carry = TAG_LEN;
    };

    decryptor.update(&mut buf[..end])?;
    writer.write_all(&buf[..end])?;
    counts.bytes_out += end as u64;
    writer.flush()?;

    decryptor.verify(&tag)?;
    Ok(counts)
}
