use super::wipe;

#[test]
fn wipe_clears_every_element() {
    let mut bytes = [0xAAu8; 32];
    wipe(&mut bytes);
    assert_eq!(bytes, [0u8; 32]);

    let mut words = [u64::MAX; 16];
    wipe(&mut words);
    assert_eq!(words, [0u64; 16]);

    wipe::<u8>(&mut []);
}
