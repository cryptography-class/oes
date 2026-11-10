use crate::ciphers::traits::BlockCipher;

/// A toy cipher that keeps the default multi-block methods: it rotates each block
/// left by one byte and flips the bits of its last byte.
struct Toy;

impl BlockCipher for Toy {
    type Block = u64;

    fn encrypt_block(&self, block: &mut u64) {
        *block = block.rotate_left(8) ^ 0xFF;
    }

    fn decrypt_block(&self, block: &mut u64) {
        *block = (*block ^ 0xFF).rotate_right(8);
    }
}

// ---- encrypt_blocks and decrypt_blocks ----

#[test]
fn encrypt_blocks_default_applies_encrypt_bytes_to_each_block() {
    let plaintext: Vec<u8> = (0..24).collect();
    let expected = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF, //
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xF7, //
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xEF,
    ];

    let mut data = plaintext.clone();
    Toy.encrypt_blocks(&mut data);
    assert_eq!(data, expected);

    Toy.decrypt_blocks(&mut data);
    assert_eq!(data, plaintext);
}

#[test]
#[should_panic(expected = "whole number of blocks")]
fn encrypt_blocks_panics_on_a_partial_block() {
    Toy.encrypt_blocks(&mut [0; 12]);
}

#[test]
#[should_panic(expected = "whole number of blocks")]
fn decrypt_blocks_panics_on_a_partial_block() {
    Toy.decrypt_blocks(&mut [0; 12]);
}
