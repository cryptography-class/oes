use crate::ciphers::traits::BlockCipher;
use crate::modes::errors::ModeError;

/// The largest block size supported, which sizes the buffers in the modes.
pub(super) const MAX_BLOCK_LEN: usize = 16;

/// Copies a one-block IV or counter into a buffer, in its first block-sized bytes.
pub(super) fn load_iv<C: BlockCipher>(iv: &[u8]) -> Result<[u8; MAX_BLOCK_LEN], ModeError> {
    const { assert!(C::BLOCK_SIZE <= MAX_BLOCK_LEN) };

    if iv.len() != C::BLOCK_SIZE {
        return Err(ModeError::InvalidIvLength {
            len: iv.len(),
            expected: C::BLOCK_SIZE,
        });
    }
    let mut buffer = [0u8; MAX_BLOCK_LEN];
    buffer[..C::BLOCK_SIZE].copy_from_slice(iv);
    Ok(buffer)
}

/// Rejects data that isn't a whole number of blocks.
#[inline]
pub(super) fn check_whole_blocks(len: usize, block_size: usize) -> Result<(), ModeError> {
    if !len.is_multiple_of(block_size) {
        return Err(ModeError::InvalidLength { len, block_size });
    }
    Ok(())
}

/// XORs `other` into `target`, stopping at the shorter one.
#[inline]
pub(super) fn xor_into(target: &mut [u8], other: &[u8]) {
    for (byte, other_byte) in target.iter_mut().zip(other) {
        *byte ^= other_byte;
    }
}
