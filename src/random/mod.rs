//! Secure random bytes from the operating system, for keys and IVs.

mod bytes;

pub use bytes::random_bytes;

#[cfg(test)]
mod tests;
