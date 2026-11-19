//! Galois/Counter Mode (NIST SP 800-38D): the two directions and the sizes and
//! limits they share.

use super::blocks::{PAR_CHUNK_BLOCKS, xor_into};
use super::ctr::{Ctr, Order};
use super::errors::ModeError;
use super::ghash::{BLOCK_LEN, Ghash};
use crate::ciphers::traits::BlockCipher;
use crate::secret::wipe;

/// The nonce length, 96 bits: the length SP 800-38D recommends, and the only one
/// supported.
pub const NONCE_LEN: usize = 12;

/// The tag length, the full 128 bits.
pub const TAG_LEN: usize = 16;

/// The largest message for one nonce: 2^39 - 256 bits (SP 800-38D section
/// 5.2.1.1). Past it the 32-bit counter would wrap and reuse keystream.
pub const MAX_PLAINTEXT_LEN: u64 = (1 << 36) - 32;

/// `J0`, the counter block of the tag, ends in a counter of 1.
const TAG_COUNTER: u32 = 1;
/// The data starts at `inc32(J0)`.
const FIRST_DATA_COUNTER: u32 = 2;

/// Returns the block `nonce || counter`. For a 96-bit nonce, `J0` is this block
/// with a counter of 1 (SP 800-38D section 7.1, step 2).
fn counter_block(nonce: &[u8; NONCE_LEN], counter: u32) -> [u8; BLOCK_LEN] {
    let mut block = [0u8; BLOCK_LEN];
    block[..NONCE_LEN].copy_from_slice(nonce);
    block[NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    block
}

/// The state both directions share.
///
/// The counter step is [`Ctr`] started at `inc32(J0)`. GCM increments only the
/// last 32 bits of the counter block (GCTR, SP 800-38D section 6.5), while `Ctr`
/// increments the whole block. They agree because [`MAX_PLAINTEXT_LEN`] allows at
/// most 2^32 - 2 blocks, so counting from 2 never carries past the last 32 bits.
pub(super) struct GcmState<C: BlockCipher> {
    ctr: Ctr<C>,
    ghash: Ghash,
    /// `E(K, J0)`, XORed onto the hash to give the tag. Computed up front, because
    /// the cipher then moves into `ctr`.
    tag_mask: [u8; TAG_LEN],
    aad_len: u64,
    /// Bytes processed so far; visible to tests, which set it near the limit.
    pub(super) data_len: u64,
}

impl<C: BlockCipher> GcmState<C> {
    fn new(cipher: C, nonce: &[u8], aad: &[u8]) -> Result<Self, ModeError> {
        if C::BLOCK_SIZE != BLOCK_LEN {
            return Err(ModeError::UnsupportedBlockSize {
                block_size: C::BLOCK_SIZE,
            });
        }
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| ModeError::InvalidIvLength {
            len: nonce.len(),
            expected: NONCE_LEN,
        })?;

        // The hash subkey H is the encryption of the zero block.
        let mut h = [0u8; BLOCK_LEN];
        cipher.encrypt_bytes(&mut h);
        let mut ghash = Ghash::new(&h);
        wipe(&mut h);
        ghash.update(aad);

        let mut tag_mask = counter_block(nonce, TAG_COUNTER);
        cipher.encrypt_bytes(&mut tag_mask);

        Ok(Self {
            ctr: Ctr::new(cipher, &counter_block(nonce, FIRST_DATA_COUNTER))?,
            ghash,
            tag_mask,
            aad_len: aad.len() as u64,
            data_len: 0,
        })
    }

    /// Refuses data after a partial block, which only the end of a message may
    /// have, and data past [`MAX_PLAINTEXT_LEN`].
    fn check_len(&self, len: usize) -> Result<(), ModeError> {
        if len == 0 {
            return Ok(());
        }
        if !self.data_len.is_multiple_of(BLOCK_LEN as u64) {
            return Err(ModeError::DataAfterPartialBlock);
        }
        // `data_len` never exceeds the limit, so this can't underflow.
        if len as u64 > MAX_PLAINTEXT_LEN - self.data_len {
            return Err(ModeError::MessageTooLong {
                max: MAX_PLAINTEXT_LEN,
            });
        }
        Ok(())
    }

    /// Encrypts or decrypts `data` in place and adds its ciphertext to the hash: after
    /// the keystream when encrypting, before it when decrypting, as `order` says.
    ///
    /// When the counter step splits the data between threads, each piece is hashed on
    /// its own thread and the hashes are folded into the state in order.
    fn apply(&mut self, data: &mut [u8], order: Order) -> Result<(), ModeError> {
        self.check_len(data.len())?;
        let ghash = &self.ghash;
        let pieces = self.ctr.apply_in_pieces(data, order, |piece| ghash.partial(piece))?;
        match pieces {
            Some(mut partials) => {
                self.ghash.fold(&partials, PAR_CHUNK_BLOCKS, data.len());
                // With the ciphertext known, these values could give away `H`.
                wipe(&mut partials);
            }
            None => match order {
                Order::AfterKeystream => {
                    self.ctr.apply_keystream(data)?;
                    self.ghash.update(data);
                }
                Order::BeforeKeystream => {
                    self.ghash.update(data);
                    self.ctr.apply_keystream(data)?;
                }
            },
        }
        self.data_len += data.len() as u64;
        Ok(())
    }

    /// Returns `GHASH(...) ^ E(K, J0)`: SP 800-38D section 7.1, step 6.
    fn tag(&mut self) -> [u8; TAG_LEN] {
        let mut tag = self.ghash.finish(self.aad_len, self.data_len);
        xor_into(&mut tag, &self.tag_mask);
        tag
    }
}

impl<C: BlockCipher> Drop for GcmState<C> {
    fn drop(&mut self) {
        wipe(&mut self.tag_mask);
    }
}

/// Encrypts a message in Galois/Counter Mode (NIST SP 800-38D) and produces its
/// authentication tag.
///
/// GCM combines counter mode, for confidentiality, with GHASH over the AAD and the
/// ciphertext, for integrity. The AAD is authenticated but not encrypted. Only
/// 128-bit block ciphers (AES) and 96-bit nonces are supported.
///
/// **A nonce must never repeat under one key.** A repeat reveals the XOR of the two
/// plaintexts and allows forged tags. Random nonces are safe for up to 2^32
/// messages per key (SP 800-38D section 8.3).
///
/// [`finish`](Self::finish) takes the encryptor by value, so it can't go on with a
/// nonce that has been used.
///
/// # Examples
///
/// ```
/// use oes::ciphers::aes::Aes128Cipher;
/// use oes::ciphers::traits::KeyInit;
/// use oes::modes::{GcmDecryptor, GcmEncryptor};
///
/// // A real nonce must be unique for the key.
/// let key = [0x2B; 16];
/// let nonce = [0x5A; 12];
/// let mut data = *b"any length";
///
/// let mut encryptor = GcmEncryptor::new(Aes128Cipher::new(&key), &nonce, b"header").unwrap();
/// encryptor.update(&mut data).unwrap();
/// let tag = encryptor.finish();
///
/// let mut decryptor = GcmDecryptor::new(Aes128Cipher::new(&key), &nonce, b"header").unwrap();
/// decryptor.update(&mut data).unwrap();
/// decryptor.verify(&tag).unwrap();
/// assert_eq!(&data, b"any length");
/// ```
pub struct GcmEncryptor<C: BlockCipher> {
    pub(super) state: GcmState<C>,
}

impl<C: BlockCipher> GcmEncryptor<C> {
    /// Builds the mode around `cipher`, and authenticates `aad`, which decryption
    /// needs again.
    ///
    /// # Errors
    ///
    /// - [`ModeError::UnsupportedBlockSize`] if the cipher's block isn't 16 bytes.
    /// - [`ModeError::InvalidIvLength`] if `nonce` isn't [`NONCE_LEN`] bytes.
    pub fn new(cipher: C, nonce: &[u8], aad: &[u8]) -> Result<Self, ModeError> {
        Ok(Self {
            state: GcmState::new(cipher, nonce, aad)?,
        })
    }

    /// Sets whether to split the work between the threads of the current Rayon pool,
    /// in the pieces that [`Ctr::parallel`] uses. Each piece is hashed on the thread
    /// that applies its keystream, and the hashes are combined in order, so the output
    /// and the tag are the same either way.
    pub fn parallel(mut self, on: bool) -> Self {
        self.state.ctr.parallel = on;
        self
    }

    /// Encrypts `data` in place and continues from the previous call.
    ///
    /// Every chunk but the last of a message must be a whole number of blocks.
    ///
    /// # Errors
    ///
    /// [`ModeError::DataAfterPartialBlock`] if an earlier chunk ended in a partial
    /// block, or [`ModeError::MessageTooLong`] past [`MAX_PLAINTEXT_LEN`]. Either
    /// way `data` is left unchanged.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        self.state.apply(data, Order::AfterKeystream)
    }

    /// Ends the message and returns its authentication tag.
    pub fn finish(mut self) -> [u8; TAG_LEN] {
        self.state.tag()
    }
}

/// Decrypts a message in Galois/Counter Mode and checks its tag.
///
/// **The plaintext from [`update`](Self::update) is unauthenticated until
/// [`verify`](Self::verify) returns `Ok`**, and must not be released before then.
/// See [`GcmEncryptor`] for the mode itself and an example.
pub struct GcmDecryptor<C: BlockCipher> {
    state: GcmState<C>,
}

impl<C: BlockCipher> GcmDecryptor<C> {
    /// Builds the mode around `cipher`, with the nonce and AAD that encryption used.
    ///
    /// # Errors
    ///
    /// - [`ModeError::UnsupportedBlockSize`] if the cipher's block isn't 16 bytes.
    /// - [`ModeError::InvalidIvLength`] if `nonce` isn't [`NONCE_LEN`] bytes.
    pub fn new(cipher: C, nonce: &[u8], aad: &[u8]) -> Result<Self, ModeError> {
        Ok(Self {
            state: GcmState::new(cipher, nonce, aad)?,
        })
    }

    /// Sets whether to split the work between the threads of the current Rayon pool,
    /// in the pieces that [`Ctr::parallel`] uses. Each piece is hashed on the thread
    /// that applies its keystream, and the hashes are combined in order, so the output
    /// and the tag are the same either way.
    pub fn parallel(mut self, on: bool) -> Self {
        self.state.ctr.parallel = on;
        self
    }

    /// Decrypts `data` in place and continues from the previous call. The result
    /// is unauthenticated until [`verify`](Self::verify) succeeds.
    ///
    /// Every chunk but the last of a message must be a whole number of blocks.
    ///
    /// # Errors
    ///
    /// As for [`GcmEncryptor::update`], with `data` left unchanged.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), ModeError> {
        self.state.apply(data, Order::BeforeKeystream)
    }

    /// Ends the message and checks its tag.
    ///
    /// # Errors
    ///
    /// [`ModeError::AuthenticationFailed`] if the key, nonce, AAD, ciphertext or
    /// tag differs from what was encrypted. All plaintext from `update` must then
    /// be discarded.
    pub fn verify(mut self, tag: &[u8; TAG_LEN]) -> Result<(), ModeError> {
        if tags_match(&self.state.tag(), tag) {
            Ok(())
        } else {
            Err(ModeError::AuthenticationFailed)
        }
    }
}

/// Compares every byte, so the time taken doesn't show how many matched. An early
/// exit would let an attacker find a valid tag one byte at a time.
fn tags_match(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(difference) == 0
}
