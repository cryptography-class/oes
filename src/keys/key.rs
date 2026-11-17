use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use super::errors::KeyError;
use crate::ciphers::des::parity::{first_bad_parity_byte, set_parity};
use crate::ciphers::des::weak_keys::is_weak;
use crate::container::Algorithm;
use crate::random::random_bytes;
use crate::secret::wipe;
use crate::stream::AtomicFile;

/// A validated key for one algorithm, erased from memory when dropped.
///
/// Every way of getting a `Key` checks the length and, for DES, the parity of
/// each byte and that the key isn't weak or semi-weak. It has no `Clone`, and
/// `Debug` doesn't show the bytes.
pub struct Key {
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl Key {
    /// Generates a key with the operating system's secure random generator.
    /// DES keys get valid parity bits, and a weak or semi-weak DES key is drawn
    /// again (a chance of about 1 in 2^52). AES keys have no parity bits.
    ///
    /// # Errors
    ///
    /// [`KeyError::Io`] if the random generator is unavailable.
    pub fn generate(algorithm: Algorithm) -> Result<Self, KeyError> {
        loop {
            let mut key = Key {
                algorithm,
                bytes: random_bytes(algorithm.key_len())?,
            };
            match algorithm {
                Algorithm::Des => {
                    set_parity(key.as_array_mut::<8>()?);
                    if is_weak(key.as_array::<8>()?) {
                        continue; // Draw again; dropping `key` erases it.
                    }
                }
                Algorithm::Aes128 | Algorithm::Aes192 | Algorithm::Aes256 => {}
            }
            return Ok(key);
        }
    }

    /// Loads a key from a file holding exactly the raw key bytes.
    ///
    /// # Errors
    ///
    /// - [`KeyError::Io`] if the file can't be read; the message names the file.
    /// - [`KeyError::InvalidLength`] if the file size is wrong for `algorithm`.
    /// - [`KeyError::BadParity`] if a DES key byte has even parity.
    /// - [`KeyError::WeakKey`] if a DES key is weak or semi-weak. Parity is
    ///   checked first.
    pub fn load(algorithm: Algorithm, path: &Path) -> Result<Self, KeyError> {
        let with_path = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()));
        let mut file = File::open(path).map_err(with_path)?;

        // Check the size first, so a wrong path never reads a huge file into memory.
        let expected = algorithm.key_len();
        let actual = file.metadata().map_err(with_path)?.len();
        if actual != expected as u64 {
            return Err(KeyError::InvalidLength {
                algorithm,
                expected,
                actual,
            });
        }

        // Held in a `Key` from the start so that every error path erases it.
        let mut key = Key {
            algorithm,
            bytes: vec![0u8; expected],
        };
        file.read_exact(&mut key.bytes).map_err(with_path)?;
        key.validate()?;
        Ok(key)
    }

    /// Saves the raw key bytes to `path`. On Unix only the owner can read or
    /// write the file (mode `0o600`). Windows has no mode bits, so there the file
    /// takes the permissions of its directory.
    ///
    /// # Errors
    ///
    /// [`KeyError::Io`] if `path` exists and `overwrite` is false, or if writing
    /// fails. No file appears at `path` on failure.
    pub fn save(&self, path: &Path, overwrite: bool) -> Result<(), KeyError> {
        let mut file = AtomicFile::create_private(path, overwrite)?;
        file.write_all(&self.bytes)?;
        file.commit()?;
        Ok(())
    }

    /// Returns the algorithm this key is for.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the key as a fixed-size array, as `KeyInit::new` expects.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidLength`] if `N` isn't the key length.
    pub fn as_array<const N: usize>(&self) -> Result<&[u8; N], KeyError> {
        self.bytes
            .as_slice()
            .try_into()
            .map_err(|_| self.length_error())
    }

    fn as_array_mut<const N: usize>(&mut self) -> Result<&mut [u8; N], KeyError> {
        let error = self.length_error();
        self.bytes.as_mut_slice().try_into().map_err(|_| error)
    }

    fn length_error(&self) -> KeyError {
        KeyError::InvalidLength {
            algorithm: self.algorithm,
            expected: self.algorithm.key_len(),
            actual: self.bytes.len() as u64,
        }
    }

    /// Checks a DES key's parity, then that it isn't weak. AES keys always pass.
    fn validate(&self) -> Result<(), KeyError> {
        match self.algorithm {
            Algorithm::Des => {
                let bytes = self.as_array::<8>()?;
                if let Some(byte) = first_bad_parity_byte(bytes) {
                    return Err(KeyError::BadParity { byte });
                }
                if is_weak(bytes) {
                    return Err(KeyError::WeakKey);
                }
                Ok(())
            }
            Algorithm::Aes128 | Algorithm::Aes192 | Algorithm::Aes256 => Ok(()),
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}
