/// One block of data in the form a cipher works on, such as `u64` for DES.
pub trait Block {
    /// The block size in bytes.
    const SIZE: usize;

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

/// A block cipher, transforming one block at a time.
///
/// Implementations are `Sync` so that several threads can share one cipher.
pub trait BlockCipher: Sync {
    /// The block type this cipher works on.
    type Block: Block;

    /// The block size in bytes.
    const BLOCK_SIZE: usize = Self::Block::SIZE;

    /// Encrypts one block in place.
    fn encrypt_block(&self, block: &mut Self::Block);

    /// Decrypts one block in place.
    fn decrypt_block(&self, block: &mut Self::Block);

    /// Encrypts one block held as bytes, in place.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` isn't exactly one block long.
    fn encrypt_bytes(&self, bytes: &mut [u8]) {
        let mut block = Self::Block::from_bytes(bytes);
        self.encrypt_block(&mut block);
        block.write_bytes(bytes);
    }

    /// Decrypts one block held as bytes, in place.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` isn't exactly one block long.
    fn decrypt_bytes(&self, bytes: &mut [u8]) {
        let mut block = Self::Block::from_bytes(bytes);
        self.decrypt_block(&mut block);
        block.write_bytes(bytes);
    }
}

/// A block cipher that can be built from a `KEY_SIZE`-byte key.
///
/// This is separate from [`BlockCipher`] so that code using a cipher doesn't have to
/// know its key size.
pub trait KeyInit<const KEY_SIZE: usize>: BlockCipher + Sized {
    /// Builds a cipher from `key`, deriving its round keys.
    fn new(key: &[u8; KEY_SIZE]) -> Self;
}
