use super::DesCipher;
use crate::ciphers::traits::BlockCipher;

#[test]
fn des_encrypt_known_vector() {
    let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

    let plaintext = 0x0123456789ABCDEF_u64;
    let expected = 0x85E813540F0AB405_u64;

    let cipher = DesCipher::new(&key);

    let mut block = plaintext;
    cipher.encrypt_block(&mut block);

    assert_eq!(block, expected);
}

#[test]
fn des_decrypt_known_vector() {
    let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];

    let ciphertext = 0x85E813540F0AB405_u64;
    let expected = 0x0123456789ABCDEF_u64;

    let cipher = DesCipher::new(&key);

    let mut block = ciphertext;
    cipher.decrypt_block(&mut block);

    assert_eq!(block, expected);
}
