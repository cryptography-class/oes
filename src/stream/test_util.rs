use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A scratch directory for tests that deletes itself when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates a new empty directory whose name includes `tag`.
    ///
    /// A directory left by an earlier, killed run is skipped rather than reused.
    pub fn new(tag: &str) -> Self {
        loop {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("oes-test-{tag}-{}-{n}", process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => panic!("can't create {}: {e}", path.display()),
            }
        }
    }

    /// Returns the path of the directory.
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Returns the sorted names of everything in the directory, including hidden files.
    pub fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
