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
/// With the `interleave` Cargo feature, which is on by default,
/// [`encrypt_blocks`](BlockCipher::encrypt_blocks) and
/// [`decrypt_blocks`](BlockCipher::decrypt_blocks) run four blocks through the
/// rounds together. This is **experimental**: interleaving isn't part of FIPS 46-3,
/// though the output is the same as one block at a time. Without the feature, they
/// work one block at a time.
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
    /// The 16 round keys, in the order encryption uses them, each split into two
    /// words by `key_schedule::split_round_key`.
    encrypt_keys: [[u32; 2]; 16],
    /// The same keys reversed, which is the order decryption uses them.
    decrypt_keys: [[u32; 2]; 16],
}

impl Drop for DesCipher {
    fn drop(&mut self) {
        wipe(&mut self.encrypt_keys);
        wipe(&mut self.decrypt_keys);
    }
}

impl KeyInit<8> for DesCipher {
    fn new(key: &[u8; 8]) -> Self {
        let mut round_keys = key_schedule::generate_round_keys(key);
        let encrypt_keys = round_keys.map(key_schedule::split_round_key);
        wipe(&mut round_keys);

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
        round::crypt_n(std::array::from_mut(block), &self.encrypt_keys);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut Self::Block) {
        round::crypt_n(std::array::from_mut(block), &self.decrypt_keys);
    }

    /// Encrypts a whole number of blocks held as bytes, in place, each on its own.
    ///
    /// **Experimental:** runs [`LANES`] blocks through the rounds together,
    /// interleaved, and any blocks left over one at a time. Interleaving isn't part
    /// of FIPS 46-3, but each block goes through exactly the same steps, so the
    /// output is the same as encrypting the blocks one at a time.
    ///
    /// # Panics
    ///
    /// Panics if the length of `data` isn't a multiple of 8.
    #[cfg(feature = "interleave")]
    fn encrypt_blocks(&self, data: &mut [u8]) {
        crypt_bytes(data, &self.encrypt_keys);
    }

    /// Decrypts a whole number of blocks held as bytes, in place, each on its own.
    ///
    /// **Experimental:** interleaved as in
    /// [`encrypt_blocks`](Self::encrypt_blocks), with the same output as
    /// decrypting the blocks one at a time.
    ///
    /// # Panics
    ///
    /// Panics if the length of `data` isn't a multiple of 8.
    #[cfg(feature = "interleave")]
    fn decrypt_blocks(&self, data: &mut [u8]) {
        crypt_bytes(data, &self.decrypt_keys);
    }
}

/// The number of blocks that `encrypt_blocks` and `decrypt_blocks` interleave.
///
/// Going from 2 to 4 blocks cut the time per block by about 30% when measured,
/// while going on to 8 gained only a few percent and leaves up to 7 blocks of a
/// buffer to the one-at-a-time path.
#[cfg(feature = "interleave")]
const LANES: usize = 4;

/// Runs the whole-block `data` through the rounds with `round_keys`, [`LANES`]
/// blocks at a time, then any blocks left over one at a time.
#[cfg(feature = "interleave")]
fn crypt_bytes(data: &mut [u8], round_keys: &[[u32; 2]; 16]) {
    const SIZE: usize = <u64 as Block>::SIZE;
    assert!(
        data.len().is_multiple_of(SIZE),
        "data isn't a whole number of blocks"
    );

    let mut groups = data.chunks_exact_mut(LANES * SIZE);
    for group in &mut groups {
        let mut blocks: [u64; LANES] =
            std::array::from_fn(|j| u64::from_bytes(&group[j * SIZE..(j + 1) * SIZE]));
        round::crypt_n(&mut blocks, round_keys);
        for (bytes, block) in group.chunks_exact_mut(SIZE).zip(blocks) {
            block.write_bytes(bytes);
        }
    }

    // Fewer than LANES blocks are left here, possibly none.
    for bytes in groups.into_remainder().chunks_exact_mut(SIZE) {
        let mut block = u64::from_bytes(bytes);
        round::crypt_n(std::array::from_mut(&mut block), round_keys);
        block.write_bytes(bytes);
    }
}
