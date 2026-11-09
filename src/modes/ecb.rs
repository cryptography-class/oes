use rayon::prelude::*;

use crate::ciphers::traits::BlockCipher;
use crate::modes::blocks::{PAR_CHUNK_BLOCKS, check_whole_blocks};
use crate::modes::errors::ModeError;

/// Electronic Codebook mode (NIST SP 800-38A section 6.1): each block is
/// encrypted on its own.
///
/// **ECB must not protect real data.** Equal plaintext blocks give equal
/// ciphertext blocks, so patterns in the data stay visible.
///
/// # Examples
///
/// ```
/// use oes::ciphers::des::DesCipher;
/// use oes::ciphers::traits::KeyInit;
/// use oes::modes::Ecb;
///
/// // The first block of Table B1 in FIPS 81.
/// let cipher = DesCipher::new(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
/// let ecb = Ecb::new(cipher);
/// let mut data = *b"Now is t";
///
/// ecb.encrypt(&mut data).unwrap();
/// assert_eq!(data, [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15]);
///
/// ecb.decrypt(&mut data).unwrap();
/// assert_eq!(&data, b"Now is t");
/// ```
pub struct Ecb<C: BlockCipher> {
    cipher: C,
    parallel: bool,
}

impl<C: BlockCipher> Ecb<C> {
    /// Builds the mode around `cipher`.
    pub fn new(cipher: C) -> Self {
        Self {
            cipher,
            parallel: false,
        }
    }

    /// Sets whether to split the work between the threads of the current Rayon
    /// pool, which is the global pool unless the call runs inside
    /// `ThreadPool::install`.
    ///
    /// The output is the same either way. Data of up to 1024 blocks always runs on
    /// the calling thread.
    pub fn parallel(mut self, on: bool) -> Self {
        self.parallel = on;
        self
    }

    /// Encrypts `data` in place.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidLength`] if `data` isn't a whole number of blocks, in
    /// which case it is left unchanged.
    pub fn encrypt(&self, data: &mut [u8]) -> Result<(), ModeError> {
        check_whole_blocks(data.len(), C::BLOCK_SIZE)?;
        if self.parallel && data.len() > PAR_CHUNK_BLOCKS * C::BLOCK_SIZE {
            self.for_each_chunk(data, |cipher, block| cipher.encrypt_bytes(block));
            return Ok(());
        }

        for block in data.chunks_exact_mut(C::BLOCK_SIZE) {
            self.cipher.encrypt_bytes(block);
        }
        Ok(())
    }

    /// Decrypts `data` in place.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidLength`] if `data` isn't a whole number of blocks, in
    /// which case it is left unchanged.
    pub fn decrypt(&self, data: &mut [u8]) -> Result<(), ModeError> {
        check_whole_blocks(data.len(), C::BLOCK_SIZE)?;
        if self.parallel && data.len() > PAR_CHUNK_BLOCKS * C::BLOCK_SIZE {
            self.for_each_chunk(data, |cipher, block| cipher.decrypt_bytes(block));
            return Ok(());
        }

        for block in data.chunks_exact_mut(C::BLOCK_SIZE) {
            self.cipher.decrypt_bytes(block);
        }
        Ok(())
    }

    /// Runs `op` on every block of `data`, with the pieces of
    /// [`PAR_CHUNK_BLOCKS`] blocks spread over the current Rayon pool.
    fn for_each_chunk(&self, data: &mut [u8], op: impl Fn(&C, &mut [u8]) + Sync) {
        let cipher = &self.cipher;
        data.par_chunks_mut(PAR_CHUNK_BLOCKS * C::BLOCK_SIZE)
            .for_each(|chunk| {
                for block in chunk.chunks_exact_mut(C::BLOCK_SIZE) {
                    op(cipher, block);
                }
            });
    }
}
