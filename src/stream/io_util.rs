use std::io::{self, ErrorKind, Read};
use std::ops::{Deref, DerefMut};

use crate::secret::wipe;

/// The bytes one run read and wrote.
#[derive(Clone, Copy, Debug, Default)]
pub struct ByteCounts {
    /// Bytes read from the input.
    pub bytes_in: u64,
    /// Bytes written to the output.
    pub bytes_out: u64,
}

/// A working buffer that is wiped when dropped, also on error paths, because it
/// holds plaintext.
pub(super) struct WipedBuf(Vec<u8>);

impl WipedBuf {
    /// Allocates `len` zero bytes.
    pub(super) fn new(len: usize) -> Self {
        Self(vec![0; len])
    }
}

impl Deref for WipedBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for WipedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for WipedBuf {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Reads until `buf` is full or the input ends, and returns the bytes read.
///
/// Only a count below `buf.len()` means the input ended. A single `read` may return
/// less at any time, so it can't be used to detect the end.
pub(super) fn read_full<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Rounds `buf_size` down to a whole number of blocks, with a minimum of one block.
pub(super) fn aligned_capacity(buf_size: usize, block_size: usize) -> usize {
    (buf_size / block_size).max(1) * block_size
}
