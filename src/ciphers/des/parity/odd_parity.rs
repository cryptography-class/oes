/// Returns `true` if every byte of `key` has odd parity.
pub fn check_parity(key: &[u8; 8]) -> bool {
    first_bad_parity_byte(key).is_none()
}

/// Returns the index of the first byte with even parity, if any, for error messages.
pub fn first_bad_parity_byte(key: &[u8; 8]) -> Option<usize> {
    key.iter().position(|b| b.count_ones() % 2 == 0)
}

/// Rewrites the lowest bit of every byte so that byte has odd parity.
/// The upper 7 bits of each byte are left untouched.
///
/// # Examples
///
/// ```
/// use oes::ciphers::des::parity::{check_parity, set_parity};
///
/// let mut key = [0u8; 8];
/// assert!(!check_parity(&key));
///
/// set_parity(&mut key);
/// assert_eq!(key, [1u8; 8]);
/// assert!(check_parity(&key));
/// ```
pub fn set_parity(key: &mut [u8; 8]) {
    for byte in key.iter_mut() {
        let high7 = *byte & 0xFE;
        // Even number of ones in the upper 7 bits -> parity bit must be 1
        let parity_bit = (high7.count_ones() % 2 == 0) as u8;
        *byte = high7 | parity_bit
    }
}
