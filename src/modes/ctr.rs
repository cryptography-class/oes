use crate::ciphers::traits::BlockCipher;
use crate::modes::blocks::{MAX_BLOCK_LEN, load_iv, xor_into};
use crate::modes::errors::ModeError;

/// Counter mode (NIST SP 800-38A section 6.5): the cipher encrypts a sequence of
/// counter blocks, and the result is XORed with the data.
///
/// This needs no padding, and encryption and decryption are the same operation.
/// The whole block is one big-endian counter that wraps at the block size.
///
/// **A counter value must never repeat under one key**, because that reveals the
/// XOR of the two plaintexts. With the 64-bit blocks of DES, random starting
/// counters are only safe for few messages per key: the ranges they cover start to
/// overlap by around 2^32 messages, and sooner for long messages.
///
/// CTR doesn't authenticate the data: flipping a ciphertext bit flips the same
/// plaintext bit, with no error.
///
/// # Examples
///
/// ```
/// use oes::ciphers::des::DesCipher;
/// use oes::ciphers::traits::KeyInit;
/// use oes::modes::Ctr;
///
/// // A real starting counter must be unique for the key. A partial block is fine.
/// let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
/// let counter = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
/// let mut data = *b"no padding";
///
/// Ctr::new(DesCipher::new(&key), &counter).unwrap().apply_keystream(&mut data).unwrap();
/// assert_ne!(&data, b"no padding");
///
/// Ctr::new(DesCipher::new(&key), &counter).unwrap().apply_keystream(&mut data).unwrap();
/// assert_eq!(&data, b"no padding");
/// ```
pub struct Ctr<C: BlockCipher> {
    cipher: C,
    /// The counter for the next block, in its first block-sized bytes.
    counter: [u8; MAX_BLOCK_LEN],
    /// Whether the last chunk ended in a partial block, which ends the message.
    ended: bool,
}

impl<C: BlockCipher> Ctr<C> {
    /// Builds the mode around `cipher`.
    ///
    /// Decrypting needs the same `initial_counter` that encryption used.
    ///
    /// # Errors
    ///
    /// [`ModeError::InvalidIvLength`] if `initial_counter` isn't exactly one block long.
    pub fn new(cipher: C, initial_counter: &[u8]) -> Result<Self, ModeError> {
        Ok(Self {
            cipher,
            counter: load_iv::<C>(initial_counter)?,
            ended: false,
        })
    }

    /// Encrypts or decrypts `data` in place and continues from the previous call.
    ///
    /// Every chunk but the last of a message must be a whole number of blocks.
    ///
    /// # Errors
    ///
    /// [`ModeError::DataAfterPartialBlock`] if `data` isn't empty and an earlier chunk
    /// ended in a partial block, in which case `data` is left unchanged.
    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        if data.is_empty() {
            return Ok(());
        }
        if self.ended {
            return Err(ModeError::DataAfterPartialBlock);
        }

        let counter = &mut self.counter[..C::BLOCK_SIZE];
        let mut buffer = [0u8; MAX_BLOCK_LEN];
        let keystream = &mut buffer[..C::BLOCK_SIZE];

        // A partial last block uses the start of its keystream.
        for chunk in data.chunks_mut(C::BLOCK_SIZE) {
            keystream.copy_from_slice(counter);
            self.cipher.encrypt_bytes(keystream);
            xor_into(chunk, keystream);
            increment(counter);
        }

        self.ended = !data.len().is_multiple_of(C::BLOCK_SIZE);
        Ok(())
    }
}

/// Adds 1 to the big-endian `counter`, wrapping at its length.
fn increment(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
