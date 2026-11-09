use super::random_bytes;

// ---- random_bytes ----

#[test]
fn random_bytes_returns_the_requested_length_and_differs_between_calls() {
    assert!(random_bytes(0).unwrap().is_empty());
    let (a, b) = (random_bytes(16).unwrap(), random_bytes(16).unwrap());
    assert_eq!(a.len(), 16);
    assert_ne!(a, b);
}
