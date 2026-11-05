use std::fs;
use std::io::{ErrorKind, Write};

use super::AtomicFile;
use super::test_util::TempDir;

// ---- AtomicFile ----

#[test]
fn commit_publishes_the_file_and_leaves_no_temp_file() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");

    let mut file = AtomicFile::create(&target, false).unwrap();
    file.write_all(b"hello").unwrap();
    assert!(!target.exists(), "the target must not exist before commit");
    assert_eq!(
        dir.entries().len(),
        1,
        "the temp file sits next to the target"
    );
    file.commit().unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"hello");
    assert_eq!(dir.entries(), ["out.bin"]);
}

#[test]
fn drop_without_commit_leaves_nothing() {
    let dir = TempDir::new("atomic");

    let mut file = AtomicFile::create(dir.path().join("out.bin"), false).unwrap();
    file.write_all(b"partial").unwrap();
    drop(file);

    assert!(dir.entries().is_empty());
}

#[test]
fn drop_without_commit_keeps_the_old_target() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");
    fs::write(&target, b"old").unwrap();

    let mut file = AtomicFile::create(&target, true).unwrap();
    file.write_all(b"new, but never committed").unwrap();
    drop(file);

    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert_eq!(dir.entries(), ["out.bin"]);
}

#[test]
fn create_refuses_an_existing_target_unless_overwriting() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");
    fs::write(&target, b"old").unwrap();

    let err = AtomicFile::create(&target, false).err().unwrap();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&target).unwrap(), b"old");

    let mut file = AtomicFile::create(&target, true).unwrap();
    file.write_all(b"new").unwrap();
    file.commit().unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
}

#[test]
fn create_rejects_a_path_without_a_file_name() {
    // With `overwrite`, the existence check can't answer first.
    let err = AtomicFile::create("..", true).err().unwrap();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn commit_refuses_a_target_that_appeared_after_create() {
    let dir = TempDir::new("atomic");
    let target = dir.path().join("out.bin");

    let file = AtomicFile::create(&target, false).unwrap();
    fs::write(&target, b"someone else's").unwrap();

    let err = file.commit().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&target).unwrap(), b"someone else's");
    assert_eq!(dir.entries(), ["out.bin"]);
}
