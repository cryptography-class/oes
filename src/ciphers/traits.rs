/// One block of data in the form a cipher works on, such as `u64` for DES.
pub trait Block: Copy + Send {
    /// The block size in bytes.
    const SIZE: usize;

    /// XORs `other` into this block.
    fn xor_assign(&mut self, other: &Self);

    /// Reads a block from `bytes`.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` isn't exactly [`SIZE`](Self::SIZE) long.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Writes this block to `bytes`.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` isn't exactly [`SIZE`](Self::SIZE) long.
    fn write_bytes(self, bytes: &mut [u8]);
}

/// A block cipher with a `KEY_SIZE`-byte key, transforming one block at a time.
///
/// Implementations are `Sync` so that several threads can share one cipher.
pub trait BlockCipher<const KEY_SIZE: usize>: Sync {
    /// The block type this cipher works on.
    type Block: Block;

    /// The block size in bytes.
    const BLOCK_SIZE: usize;

    /// Builds a cipher from `key`, deriving its round keys.
    fn new(key: &[u8; KEY_SIZE]) -> Self
    where
        Self: Sized;

    /// Encrypts one block in place.
    fn encrypt_block(&self, block: &mut Self::Block);

    /// Decrypts one block in place.
    fn decrypt_block(&self, block: &mut Self::Block);
}
