#[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
use super::aes_ni::AesNiKeys;
use super::key_schedule::{self, MAX_WORDS};
use super::round;
use crate::ciphers::traits::{Block, BlockCipher, KeyInit};
use crate::secret::wipe;

/// An AES block: the 16 input bytes in their original order.
impl Block for [u8; 16] {
    const SIZE: usize = 16;

    #[inline(always)]
    fn from_bytes(bytes: &[u8]) -> Self {
        bytes.try_into().expect("Invalid block size")
    }

    #[inline(always)]
    fn write_bytes(self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self);
    }
}

/// The AES block cipher for a `KEY_SIZE` of 16, 24 or 32 bytes, holding the key
/// schedule derived from one key.
///
/// The key length sets the number of rounds `Nr`: 10, 12 or 14 (FIPS 197
/// section 5). Any other `KEY_SIZE` fails to compile. The key schedule is erased
/// from memory when the cipher is dropped.
///
/// With the `aes-ni` Cargo feature, which is on by default, the cipher runs on the
/// processor's AES instructions when it has them. These take the same time whatever
/// the key and the data. Otherwise it runs the table-based implementation, with the
/// same output, which doesn't run in constant time: SubBytes and the key schedule
/// look up the S-box at positions that depend on the key and the data, so on shared
/// hardware the timing of memory accesses can leak information about them.
///
/// # Examples
///
/// ```
/// use oes::ciphers::aes::Aes128Cipher;
/// use oes::ciphers::traits::{BlockCipher, KeyInit};
///
/// // FIPS 197 Appendix C.1.
/// let key: [u8; 16] = std::array::from_fn(|i| i as u8);
/// let cipher = Aes128Cipher::new(&key);
/// let plaintext: [u8; 16] = std::array::from_fn(|i| (i * 0x11) as u8);
/// let mut block = plaintext;
///
/// cipher.encrypt_block(&mut block);
/// assert_eq!(
///     block,
///     [
///         0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
///         0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
///     ]
/// );
///
/// cipher.decrypt_block(&mut block);
/// assert_eq!(block, plaintext);
/// ```
pub struct AesCipher<const KEY_SIZE: usize> {
    engine: Engine,
}

/// The implementation a cipher runs on, with the round keys in the form it needs.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the round keys would add a pointer to follow for every block"
)]
enum Engine {
    /// The table-based implementation.
    Textbook {
        /// The key schedule `w` of FIPS 197. Words past `4 * (Nr + 1)` stay unused.
        w: [u32; MAX_WORDS],
        /// `Nr`, the number of rounds.
        rounds: usize,
    },
    /// The processor's AES instructions.
    #[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
    AesNi(AesNiKeys),
}

impl Engine {
    /// Picks the fastest implementation this processor can run, with blank round keys.
    fn detect() -> Self {
        #[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
        if let Some(keys) = AesNiKeys::empty() {
            return Self::AesNi(keys);
        }
        Self::Textbook {
            w: [0; MAX_WORDS],
            rounds: 0,
        }
    }
}

/// AES with a 128-bit key.
pub type Aes128Cipher = AesCipher<16>;
/// AES with a 192-bit key.
pub type Aes192Cipher = AesCipher<24>;
/// AES with a 256-bit key.
pub type Aes256Cipher = AesCipher<32>;

impl<const KEY_SIZE: usize> Drop for AesCipher<KEY_SIZE> {
    fn drop(&mut self) {
        match &mut self.engine {
            Engine::Textbook { w, .. } => wipe(w),
            #[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
            Engine::AesNi(keys) => keys.wipe(),
        }
    }
}

impl<const KEY_SIZE: usize> KeyInit<KEY_SIZE> for AesCipher<KEY_SIZE> {
    fn new(key: &[u8; KEY_SIZE]) -> Self {
        const { assert!(KEY_SIZE == 16 || KEY_SIZE == 24 || KEY_SIZE == 32) };
        let mut cipher = Self {
            engine: Engine::detect(),
        };
        match &mut cipher.engine {
            Engine::Textbook { w, rounds } => *rounds = key_schedule::expand_key(key, w),
            #[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
            Engine::AesNi(keys) => keys.expand_key(key),
        }
        cipher
    }
}

impl<const KEY_SIZE: usize> BlockCipher for AesCipher<KEY_SIZE> {
    type Block = [u8; 16];

    #[inline]
    fn encrypt_block(&self, block: &mut Self::Block) {
        match &self.engine {
            Engine::Textbook { w, rounds } => round::encrypt(block, w, *rounds),
            #[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
            Engine::AesNi(keys) => keys.encrypt_block(block),
        }
    }

    #[inline]
    fn decrypt_block(&self, block: &mut Self::Block) {
        match &self.engine {
            Engine::Textbook { w, rounds } => round::decrypt(block, w, *rounds),
            #[cfg(all(feature = "aes-ni", any(target_arch = "x86", target_arch = "x86_64")))]
            Engine::AesNi(keys) => keys.decrypt_block(block),
        }
    }
}
