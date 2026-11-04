//! Best-effort erasure of secret values from memory.

mod wipe;

pub use wipe::wipe;

#[cfg(test)]
mod tests;
