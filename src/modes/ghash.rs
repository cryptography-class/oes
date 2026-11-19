//! GHASH, the authentication half of GCM (NIST SP 800-38D sections 6.3 and 6.4).
//!
//! Blocks are elements of GF(2^128). In the notation of the standard, bit 0 of a
//! block is its leftmost bit, so loading the 16 bytes as a big-endian `u128` puts
//! bit `i` of the standard at bit `127 - i` of the integer.
//!
//! [`gf_mul`] is the textbook method, one shift and one conditional XOR per bit. With
//! the `pclmulqdq` Cargo feature, which is on by default, processors that have that
//! instruction multiply with it instead, with the same result. With the `vpclmulqdq`
//! feature on x86-64, processors that also have the 256-bit form of the instruction
//! absorb whole groups of 8 blocks with it first. Table-based methods aren't used,
//! because their tables are indexed by secret data, which can leak through the cache.
//!
//! The hash of a long message can be split: each piece is hashed on its own from zero,
//! and [`Ghash::fold`] adds the results in order with powers of `H`. GCM uses this to
//! hash pieces on the threads that encrypt them.

#[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
use super::pclmul::Pclmul;
#[cfg(all(feature = "vpclmulqdq", target_arch = "x86_64"))]
use super::vpclmul::Vpclmul;
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
    /// Set when the processor also has `VPCLMULQDQ`, which then takes whole groups of
    /// 8 blocks.
    #[cfg(all(feature = "vpclmulqdq", target_arch = "x86_64"))]
    pub(super) vpclmul: Option<Vpclmul>,
}

impl Ghash {
    /// Starts a hash with the subkey `h`.
    pub(super) fn new(h: &[u8; BLOCK_LEN]) -> Self {
        Self {
            h: u128::from_be_bytes(*h),
            y: 0,
            #[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
            pclmul: Pclmul::detect(),
            #[cfg(all(feature = "vpclmulqdq", target_arch = "x86_64"))]
            vpclmul: Vpclmul::detect(),
        }
    }

    /// Absorbs `data`, padding a partial last block with zeros. Only the last call
    /// for the AAD and the last call for the ciphertext may be partial.
    pub(super) fn update(&mut self, data: &[u8]) {
        self.y = self.hash_from(self.y, data);
    }

    /// Returns the hash of `data` alone, from `Y = 0`, padding a partial last block
    /// with zeros, without changing this hash. [`fold`](Self::fold) adds such hashes
    /// of consecutive pieces to it.
    pub(super) fn partial(&self, data: &[u8]) -> u128 {
        self.hash_from(0, data)
    }

    /// Adds the hashes of consecutive pieces of `len` bytes in all, each from
    /// [`partial`](Self::partial), with the same result as calling
    /// [`update`](Self::update) on the whole.
    ///
    /// Absorbing `m` blocks into `Y` gives `Y * H^m ^ P`, where `P` is the hash of those
    /// blocks alone: each step of `Y_i = (Y_{i-1} ^ X_i) * H` (SP 800-38D section 6.4)
    /// multiplies what came before by `H`. Every piece but the last is `piece_blocks`
    /// blocks long, and the last covers the rest of `len`, a partial block counting as
    /// one.
    pub(super) fn fold(&mut self, partials: &[u128], piece_blocks: usize, len: usize) {
        let Some((last, pieces)) = partials.split_last() else {
            return;
        };
        let full = self.power(piece_blocks as u64);
        for &partial in pieces {
            self.y = self.multiply(self.y, full) ^ partial;
        }
        let last_blocks = len.div_ceil(BLOCK_LEN) - pieces.len() * piece_blocks;
        self.y = self.multiply(self.y, self.power(last_blocks as u64)) ^ last;
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
        self.y = self.absorb_from(self.y, blocks);
    }

    /// Returns `y` after absorbing `data`, padding a partial last block with zeros.
    fn hash_from(&self, y: u128, data: &[u8]) -> u128 {
        let (blocks, rest) = data.split_at(data.len() - data.len() % BLOCK_LEN);
        let y = self.absorb_from(y, blocks);
        if rest.is_empty() {
            return y;
        }
        let mut last = [0u8; BLOCK_LEN];
        last[..rest.len()].copy_from_slice(rest);
        self.absorb_from(y, &last)
    }

    /// Returns `y` after absorbing each whole block of `blocks`.
    fn absorb_from(&self, y: u128, blocks: &[u8]) -> u128 {
        #[cfg(all(feature = "vpclmulqdq", target_arch = "x86_64"))]
        let (y, blocks) = match self.vpclmul {
            Some(vpclmul) => vpclmul.absorb_groups(y, self.h, blocks),
            None => (y, blocks),
        };
        #[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
        if let Some(pclmul) = self.pclmul {
            return pclmul.absorb(y, self.h, blocks);
        }
        let mut y = y;
        for block in blocks.chunks_exact(BLOCK_LEN) {
            let mut bytes = [0u8; BLOCK_LEN];
            bytes.copy_from_slice(block);
            y = gf_mul(y ^ u128::from_be_bytes(bytes), self.h);
        }
        y
    }

    /// Returns `a * b`, with `PCLMULQDQ` when the processor has it.
    fn multiply(&self, a: u128, b: u128) -> u128 {
        #[cfg(all(feature = "pclmulqdq", any(target_arch = "x86", target_arch = "x86_64")))]
        if let Some(pclmul) = self.pclmul {
            return pclmul.multiply(a, b);
        }
        gf_mul(a, b)
    }

    /// Returns `H^n`, by squaring. The field's 1 is bit 0 of the standard, which is the
    /// top bit of the integer.
    fn power(&self, mut n: u64) -> u128 {
        let mut result = 1 << 127;
        let mut square = self.h;
        while n > 0 {
            if n & 1 == 1 {
                result = self.multiply(result, square);
            }
            square = self.multiply(square, square);
            n >>= 1;
        }
        result
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        wipe(std::slice::from_mut(&mut self.h));
        wipe(std::slice::from_mut(&mut self.y));
    }
}
