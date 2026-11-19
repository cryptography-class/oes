//! GHASH, the authentication half of GCM (NIST SP 800-38D sections 6.3 and 6.4).
//!
//! Blocks are elements of GF(2^128). In the notation of the standard, bit 0 of a
//! block is its leftmost bit, so loading the 16 bytes as a big-endian `u128` puts
//! bit `i` of the standard at bit `127 - i` of the integer.
//!
//! [`gf_mul`] is the textbook method, one shift and one conditional XOR per bit. With
//! the `pclmulqdq` Cargo feature, which is on by default, processors that have that
//! instruction multiply with it instead, with the same result. Table-based methods
//! aren't used, because their tables are indexed by secret data, which can leak through
//! the cache.

#[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
use super::pclmul::Pclmul;
use crate::secret::wipe;

pub(super) const BLOCK_LEN: usize = 16;

/// `R = 11100001 || 0^120`, the reduction constant of SP 800-38D section 6.3.
const R: u128 = 0xE1 << 120;

/// Returns all ones if the lowest bit of `bit` is set and all zeros otherwise. It
/// replaces an `if` on secret data, so the timing doesn't depend on it.
#[inline(always)]
fn mask(bit: u128) -> u128 {
    (bit & 1).wrapping_neg()
}

/// Returns `X * Y` in GF(2^128): SP 800-38D section 6.3, Algorithm 1.
pub(super) fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z = 0; // Z_0 = 0^128
    let mut v = y; // V_0 = Y

    // i runs over the bits of X from x_0, which is the highest bit of the integer.
    for i in (0..128).rev() {
        z ^= v & mask(x >> i);
        v = (v >> 1) ^ (R & mask(v));
    }
    z
}

/// Absorbs data as `Y_i = (Y_{i-1} ^ X_i) * H` for each block. The `PCLMULQDQ` path
/// works on four blocks per reduction, with the same result. Wiped on drop, because
/// the hash subkey `H` is enough to forge tags.
pub(super) struct Ghash {
    h: u128,
    y: u128,
    /// Set when the processor has `PCLMULQDQ`.
    #[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
    pub(super) pclmul: Option<Pclmul>,
}

impl Ghash {
    /// Starts a hash with the subkey `h`.
    pub(super) fn new(h: &[u8; BLOCK_LEN]) -> Self {
        Self {
            h: u128::from_be_bytes(*h),
            y: 0,
            #[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
            pclmul: Pclmul::detect(),
        }
    }

    /// Absorbs `data`, padding a partial last block with zeros. Only the last call
    /// for the AAD and the last call for the ciphertext may be partial.
    pub(super) fn update(&mut self, data: &[u8]) {
        let (blocks, rest) = data.split_at(data.len() - data.len() % BLOCK_LEN);
        self.absorb(blocks);
        if !rest.is_empty() {
            let mut last = [0u8; BLOCK_LEN];
            last[..rest.len()].copy_from_slice(rest);
            self.absorb(&last);
        }
    }

    /// Absorbs the final block `[len(A)]_64 || [len(C)]_64`, with both lengths in
    /// bits (SP 800-38D section 7.1, step 5), and returns the hash.
    pub(super) fn finish(&mut self, aad_bytes: u64, ciphertext_bytes: u64) -> [u8; BLOCK_LEN] {
        // Both lengths are below 2^61 bytes, so the bit counts fit in 64 bits.
        let lengths = (u128::from(aad_bytes * 8) << 64) | u128::from(ciphertext_bytes * 8);
        self.absorb(&lengths.to_be_bytes());
        self.y.to_be_bytes()
    }

    /// Absorbs each whole block of `blocks`.
    fn absorb(&mut self, blocks: &[u8]) {
        #[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
        if let Some(pclmul) = self.pclmul {
            self.y = pclmul.absorb(self.y, self.h, blocks);
            return;
        }
        for block in blocks.chunks_exact(BLOCK_LEN) {
            let mut bytes = [0u8; BLOCK_LEN];
            bytes.copy_from_slice(block);
            self.y = gf_mul(self.y ^ u128::from_be_bytes(bytes), self.h);
        }
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        wipe(std::slice::from_mut(&mut self.h));
        wipe(std::slice::from_mut(&mut self.y));
    }
}
