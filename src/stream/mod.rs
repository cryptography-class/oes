//! Encrypts and decrypts data of any size from a reader to a writer, holding only
//! one buffer in memory.
//!
//! The caller builds the mode with its key and IV, and these functions only move
//! bytes through it. The padded modes (ECB, CBC) use [`encrypt_stream`] and
//! [`decrypt_stream`].
//!
//! **Send decrypted output through [`AtomicFile`], and commit it only on success.**
//! Plaintext reaches the writer before the padding at the end can be checked, so a
//! failed run may already have written part of it.
//!
//! None of these modes authenticates data: changed ciphertext usually decrypts to
//! wrong bytes without an error. **DES and ECB must not protect real data.**

mod atomic;
pub mod errors;
mod io_util;
mod padded;

pub use atomic::AtomicFile;
pub use io_util::ByteCounts;
pub use padded::{DEFAULT_BUFFER_SIZE, decrypt_stream, encrypt_stream};

#[cfg(test)]
mod test_util;
#[cfg(test)]
mod tests;
