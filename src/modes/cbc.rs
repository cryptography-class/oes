use crate::ciphers::traits::BlockCipher;
use crate::modes::blocks::{MAX_BLOCK_LEN, check_whole_blocks, load_iv, xor_into};
use crate::modes::errors::ModeError;

/// Cipher Block Chaining mode (NIST SP 800-38A section 6.2): each plaintext block
/// is XORed with the previous ciphertext block before it is encrypted.
///
/// The chaining state carries over between calls, so splitting the data into
/// several calls gives the same bytes as one call. Use a new instance for each
/// run. CBC doesn't authenticate the data.
///
/// # Examples
///
/// ```
/// use oes::ciphers::des::DesCipher;
/// use oes::ciphers::traits::KeyInit;
/// use oes::modes::Cbc;
///
/// // The first block of Table C1 in FIPS 81. A real IV must be random.
/// let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
/// let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
/// let mut data = *b"Now is t";
///
/// Cbc::new(DesCipher::new(&key), &iv).unwrap().encrypt(&mut data).unwrap();
/// assert_eq!(data, [0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C]);
///
/// Cbc::new(DesCipher::new(&key), &iv).unwrap().decrypt(&mut data).unwrap();
/// assert_eq!(&data, b"Now is t");
/// ```
pub struct Cbc<C: BlockCipher> {
    cipher: C,
    /// The previous ciphertext block, which starts out as the IV, in its first
    /// block-sized bytes.
    prev: [u8; MAX_BLOCK_LEN],
}

impl<C: BlockCipher> Cbc<C> {
    /// Builds the mode around `cipher`.
    ///
    /// When encrypting, `iv` must be unpredictable and never reused with the same
    /// key. Decrypting needs the same `iv` that encryption used.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidIvLength`] if `iv` isn't exactly one block long.
    pub fn new(cipher: C, iv: &[u8]) -> Result<Self, ModeError> {
        Ok(Self {
            cipher,
            prev: load_iv::<C>(iv)?,
        })
    }

    /// Encrypts `data` in place and continues the chain from the previous call.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidLength`] if `data` isn't a whole number of blocks, in
    /// which case it and the chaining state are left unchanged.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        let block_size = C::BLOCK_SIZE;
        check_whole_blocks(data.len(), block_size)?;

        let mut prev = &self.prev[..block_size];
        for block in data.chunks_exact_mut(block_size) {
            xor_into(block, prev);
            self.cipher.encrypt_bytes(block);
            prev = block;
        }
        if !data.is_empty() {
            self.prev[..block_size].copy_from_slice(&data[data.len() - block_size..]);
        }
        Ok(())
    }

    /// Decrypts `data` in place and continues the chain from the previous call.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidLength`] if `data` isn't a whole number of blocks, in
    /// which case it and the chaining state are left unchanged.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        let block_size = C::BLOCK_SIZE;
        check_whole_blocks(data.len(), block_size)?;
        if data.is_empty() {
            return Ok(());
        }

        let start = self.prev;
        self.prev[..block_size].copy_from_slice(&data[data.len() - block_size..]);

        // Runs from the last block to the first, so each block's previous ciphertext
        // is still in `data` and nothing has to be saved per block.
        let mut end = data.len();
        while end > block_size {
            let (before, block) = data[..end].split_at_mut(end - block_size);
            self.cipher.decrypt_bytes(block);
            xor_into(block, &before[before.len() - block_size..]);
            end -= block_size;
        }
        let first = &mut data[..block_size];
        self.cipher.decrypt_bytes(first);
        xor_into(first, &start[..block_size]);
        Ok(())
    }
}
