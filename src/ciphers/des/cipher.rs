use super::{key_schedule, round};
use crate::ciphers::traits::{Block, BlockCipher, KeyInit};
use crate::secret::wipe;

/// A DES block, stored big-endian so that the first byte holds specification bits 1 to 8.
impl Block for u64 {
    const SIZE: usize = 8;

    #[inline(always)]
    fn from_bytes(bytes: &[u8]) -> Self {
        u64::from_be_bytes(bytes.try_into().expect("Invalid block size"))
    }

    #[inline(always)]
    fn write_bytes(self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.to_be_bytes());
    }
}

/// The DES block cipher, holding the 16 round keys derived from one key.
///
/// **DES is broken and must not protect real data.**
///
/// `new` accepts any 8 bytes. It doesn't check the parity bits, and the key
/// schedule ignores them, so keys that differ only in those bits encrypt
/// identically. Use [`check_parity`](super::parity::check_parity) if the key's parity
/// matters. The round keys are erased from memory when the cipher is dropped.
///
/// It doesn't run in constant time. Each round looks up tables at positions that
/// depend on the key and the data, so on shared hardware the timing of memory
/// accesses can leak information about them.
///
/// # Examples
///
/// ```
/// use oes::ciphers::des::DesCipher;
/// use oes::ciphers::traits::{BlockCipher, KeyInit};
///
/// // Test vector from "The DES Algorithm Illustrated" by J. Orlin Grabbe.
/// let cipher = DesCipher::new(&[0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]);
/// let mut block = 0x0123_4567_89AB_CDEF_u64;
///
/// cipher.encrypt_block(&mut block);
/// assert_eq!(block, 0x85E8_1354_0F0A_B405);
///
/// cipher.decrypt_block(&mut block);
/// assert_eq!(block, 0x0123_4567_89AB_CDEF);
/// ```
pub struct DesCipher {
    /// The 16 round keys, in the order encryption uses them.
    encrypt_keys: [u64; 16],
    /// The same keys reversed, which is the order decryption uses them.
    decrypt_keys: [u64; 16],
}

impl Drop for DesCipher {
    fn drop(&mut self) {
        wipe(&mut self.encrypt_keys);
        wipe(&mut self.decrypt_keys);
    }
}

impl KeyInit<8> for DesCipher {
    fn new(key: &[u8; 8]) -> Self {
        let encrypt_keys = key_schedule::generate_round_keys(key);
        let mut decrypt_keys = encrypt_keys;
        decrypt_keys.reverse();
        Self {
            encrypt_keys,
            decrypt_keys,
        }
    }
}

impl BlockCipher for DesCipher {
    type Block = u64;

    #[inline]
    fn encrypt_block(&self, block: &mut Self::Block) {
        round::crypt(block, &self.encrypt_keys);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut Self::Block) {
        round::crypt(block, &self.decrypt_keys);
    }
}
