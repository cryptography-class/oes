use std::io;

/// Returns `n` bytes from the operating system's cryptographically secure generator.
///
/// # Errors
///
/// Returns an [`io::Error`] if the generator is unavailable.
pub fn random_bytes(n: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; n];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| io::Error::other(format!("random generator failed: {e}")))?;
    Ok(bytes)
}
