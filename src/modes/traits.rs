use crate::ciphers::traits::BlockCipher;
use crate::modes::cbc::Cbc;
use crate::modes::ecb::Ecb;
use crate::modes::errors::ModeError;

/// A whole-block mode (ECB, CBC) with its cipher type erased, so one caller can
/// drive either of them.
///
/// Implementors transform whole blocks in place and keep any chaining state
/// between calls.
pub trait BlockMode {
    /// Returns the block size in bytes.
    fn block_size(&self) -> usize;

    /// Encrypts `data` in place.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidLength`] if `data` isn't a whole number of blocks.
    fn encrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError>;

    /// Decrypts `data` in place.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidLength`] if `data` isn't a whole number of blocks.
    fn decrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError>;
}

impl<C: BlockCipher> BlockMode for Ecb<C> {
    fn block_size(&self) -> usize {
        C::BLOCK_SIZE
    }

    fn encrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        self.encrypt(data)
    }

    fn decrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        self.decrypt(data)
    }
}

impl<C: BlockCipher> BlockMode for Cbc<C> {
    fn block_size(&self) -> usize {
        C::BLOCK_SIZE
    }

    fn encrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        self.encrypt(data)
    }

    fn decrypt_blocks(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        self.decrypt(data)
    }
}
