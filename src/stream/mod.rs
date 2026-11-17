//! Encrypts and decrypts data of any size from a reader to a writer, holding only
//! one buffer in memory.
//!
//! The caller builds the mode with its key and IV, and these functions only move
//! bytes through it. The padded modes (ECB, CBC) use [`encrypt_stream`] and
//! [`decrypt_stream`], CTR uses [`apply_ctr_stream`], and GCM uses
//! [`encrypt_gcm_stream`] and [`decrypt_gcm_stream`].
//!
//! **Send decrypted output through [`AtomicFile`], and commit it only on success.**
//! Plaintext reaches the writer before the padding or the GCM tag at the end can
//! be checked, so a failed run may already have written part of it.
//!
//! Only GCM authenticates data. With the other modes, changed ciphertext usually
//! decrypts to wrong bytes without an error. **DES and ECB must not protect real
//! data.**

mod atomic;
mod ctr;
pub mod errors;
mod gcm;
mod io_util;
mod padded;

pub use atomic::AtomicFile;
pub use ctr::apply_ctr_stream;
pub use gcm::{decrypt_gcm_stream, encrypt_gcm_stream};
pub use io_util::{ByteCounts, MAX_BUFFER_SIZE};
pub use padded::{DEFAULT_BUFFER_SIZE, decrypt_stream, encrypt_stream};

#[cfg(test)]
pub(crate) mod test_util;
#[cfg(test)]
mod tests;
