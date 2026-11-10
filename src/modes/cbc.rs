use rayon::prelude::*;

use crate::ciphers::traits::BlockCipher;
use crate::modes::blocks::{
    BATCH_BLOCKS, MAX_BLOCK_LEN, PAR_CHUNK_BLOCKS, check_whole_blocks, load_iv, xor_into,
};
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
    parallel: bool,
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
            parallel: false,
        })
    }

    /// Sets whether decryption splits its work between the threads of the current
    /// Rayon pool, which is the global pool unless the call runs inside
    /// `ThreadPool::install`.
    ///
    /// Encryption always runs on the calling thread, because each block needs the
    /// ciphertext of the block before it. The output is the same either way. Data
    /// of up to 1024 blocks always runs on the calling thread.
    pub fn parallel(mut self, on: bool) -> Self {
        self.parallel = on;
        self
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

        let chunk_len = PAR_CHUNK_BLOCKS * block_size;
        if self.parallel && data.len() > chunk_len {
            // Each piece starts from the last ciphertext block of the piece before
            // it, which has to be saved before another thread decrypts it.
            let starts: Vec<[u8; MAX_BLOCK_LEN]> = std::iter::once(start)
                .chain(data.chunks(chunk_len).map(|chunk| {
                    let mut block = [0u8; MAX_BLOCK_LEN];
                    block[..block_size].copy_from_slice(&chunk[chunk.len() - block_size..]);
                    block
                }))
                .collect();
            let cipher = &self.cipher;
            data.par_chunks_mut(chunk_len)
                .zip(starts.par_iter())
                .for_each(|(chunk, start)| decrypt_chain(cipher, chunk, &start[..block_size]));
            return Ok(());
        }

        decrypt_chain(&self.cipher, data, &start[..block_size]);
        Ok(())
    }
}

/// Decrypts the block-aligned `data` in place, chained from `start`, the ciphertext
/// block before it.
///
/// The blocks are decrypted [`BATCH_BLOCKS`] at a time. Each batch's ciphertext is
/// copied first, because decrypting in place overwrites the blocks that the XOR
/// step needs.
#[inline]
fn decrypt_chain<C: BlockCipher>(cipher: &C, data: &mut [u8], start: &[u8]) {
    let block_size = C::BLOCK_SIZE;
    let mut saved = [0u8; BATCH_BLOCKS * MAX_BLOCK_LEN];
    let mut prev = [0u8; MAX_BLOCK_LEN];
    prev[..block_size].copy_from_slice(start);

    for batch in data.chunks_mut(BATCH_BLOCKS * block_size) {
        let len = batch.len();
        let saved = &mut saved[..len];
        saved.copy_from_slice(batch);
        cipher.decrypt_blocks(batch);

        // Block 0 chains from the block before the batch, and every later block
        // from the saved ciphertext block just before it.
        xor_into(&mut batch[..block_size], &prev[..block_size]);
        xor_into(&mut batch[block_size..], &saved[..len - block_size]);
        prev[..block_size].copy_from_slice(&saved[len - block_size..]);
    }
}
