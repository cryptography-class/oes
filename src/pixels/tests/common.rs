use crate::ciphers::des::DesCipher;
use crate::ciphers::traits::KeyInit;
use crate::container::Mode;
use crate::modes::{BlockMode, Cbc, Ecb};
use crate::padding::{Fill, Padding};

pub const KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
/// `KEY` with one bit of its last byte changed, keeping odd parity.
pub const WRONG_KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xE0];
pub const IV: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];

pub const PADDINGS: [Padding; 4] = [
    Padding::Pkcs7,
    Padding::Pkcs5,
    Padding::AnsiX923(Fill::Zeros),
    Padding::AnsiX923(Fill::Random),
];

/// Returns the IV a mode takes: `IV` for CBC, none for ECB.
pub fn iv_for(mode: Mode) -> Vec<u8> {
    match mode {
        Mode::Cbc => IV.to_vec(),
        _ => Vec::new(),
    }
}

/// Builds a DES mode with `key`, using `IV` for CBC.
pub fn des_mode(mode: Mode, key: &[u8; 8]) -> Box<dyn BlockMode> {
    let cipher = DesCipher::new(key);
    match mode {
        Mode::Ecb => Box::new(Ecb::new(cipher)),
        Mode::Cbc => Box::new(Cbc::new(cipher, &IV).unwrap()),
        Mode::Ctr => panic!("pixel tests use ECB and CBC only"),
    }
}

/// Returns `len` bytes with no repeating 8-byte block.
pub fn sample(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(53) ^ (i >> 2)) as u8)
        .collect()
}
