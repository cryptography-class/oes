//! Moves data from a reader to a writer, holding only one buffer in memory.
//!
//! [`AtomicFile`] is the output to use for files: its data only appears under the
//! real name once it is committed, so a failed run leaves nothing behind.

mod atomic;

pub use atomic::AtomicFile;

#[cfg(test)]
mod test_util;
#[cfg(test)]
mod tests;
