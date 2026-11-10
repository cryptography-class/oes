use std::collections::HashSet;

use super::errors::PixelError;
use crate::modes::BlockMode;
use crate::padding::Padding;

/// Encrypts `buf` in place without changing its length, and returns the tail
/// block, which is empty when `buf.len()` is a multiple of the block size.
///
/// Whole blocks are encrypted in place. The leftover bytes, fewer than one block,
/// are padded into one extra block and encrypted. That block is the tail block,
/// which belongs in the metadata file. Its first bytes also replace the leftover
/// bytes in `buf`, so the image keeps its size and its last pixels are encrypted
/// too.
///
/// # Errors
///
/// - [`PixelError::Padding`] if `padding` doesn't allow the mode's block size,
///   checked before anything is changed, or if random fill can't be generated.
/// - [`PixelError::Mode`] if the mode refuses its input.
pub fn encrypt_buffer(
    mode: &mut dyn BlockMode,
    padding: Padding,
    buf: &mut [u8],
) -> Result<Vec<u8>, PixelError> {
    let block_size = mode.block_size();
    let mut block = vec![0u8; block_size];
    // Fails early on a padding that doesn't fit the block size, such as PKCS#5
    // with 16-byte blocks.
    padding.pad_final(&[], &mut block)?;

    let full = buf.len() - buf.len() % block_size;
    let tail_len = buf.len() - full;
    mode.encrypt_blocks(&mut buf[..full])?;
    if tail_len == 0 {
        return Ok(Vec::new());
    }

    padding.pad_final(&buf[full..], &mut block)?;
    mode.encrypt_blocks(&mut block)?;
    buf[full..].copy_from_slice(&block[..tail_len]);
    Ok(block)
}

/// Reverses [`encrypt_buffer`] in place.
///
/// On error the content of `buf` is meaningless and must be discarded. ECB and
/// CBC can't tell a wrong key from the right one except through the padding of
/// the tail block, so a block-aligned buffer decrypts to noise without an error.
///
/// # Errors
///
/// - [`PixelError::Invalid`] if `tail_block` isn't one block long when `buf` has
///   leftover bytes, or isn't empty when it has none.
/// - [`PixelError::TailMismatch`] if the leftover bytes in `buf` differ from the
///   start of `tail_block`, or the decrypted tail holds a different number of
///   data bytes. Either means the image and the metadata don't belong together.
/// - [`PixelError::Padding`] if the tail block's padding is invalid, usually
///   because of a wrong key.
/// - [`PixelError::Mode`] if the mode refuses its input.
pub fn decrypt_buffer(
    mode: &mut dyn BlockMode,
    padding: Padding,
    buf: &mut [u8],
    tail_block: &[u8],
) -> Result<(), PixelError> {
    let block_size = mode.block_size();
    let full = buf.len() - buf.len() % block_size;
    let tail_len = buf.len() - full;

    let expected = if tail_len == 0 { 0 } else { block_size };
    if tail_block.len() != expected {
        return Err(PixelError::Invalid(
            "the tail block in the metadata doesn't fit the image size",
        ));
    }
    if tail_block[..tail_len] != buf[full..] {
        return Err(PixelError::TailMismatch);
    }

    mode.decrypt_blocks(&mut buf[..full])?;
    if tail_len > 0 {
        let mut block = tail_block.to_vec();
        mode.decrypt_blocks(&mut block)?;
        if padding.unpad_block(&block)? != tail_len {
            return Err(PixelError::TailMismatch);
        }
        buf[full..].copy_from_slice(&block[..tail_len]);
    }
    Ok(())
}

/// Returns `(total, distinct)`: how many whole blocks `data` holds, and how many
/// of them differ. Leftover bytes after the last whole block are ignored.
///
/// ECB leaves many repeated blocks in an image with flat areas, while CBC leaves
/// almost none.
///
/// # Panics
///
/// Panics if `block_size` is 0.
///
/// # Examples
///
/// ```
/// use oes::pixels::count_distinct_blocks;
///
/// assert_eq!(count_distinct_blocks(&[1, 1, 2, 2, 1, 1, 9], 2), (3, 2));
/// ```
pub fn count_distinct_blocks(data: &[u8], block_size: usize) -> (usize, usize) {
    let blocks = data.chunks_exact(block_size);
    let total = blocks.len();
    let distinct = blocks.collect::<HashSet<_>>().len();
    (total, distinct)
}
