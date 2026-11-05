use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

/// An output file that only appears under its real name after [`commit`](Self::commit).
///
/// Data goes to a hidden temporary file in the same directory, so the final rename
/// stays on one filesystem. Dropping the value without committing, after an error or
/// a panic, deletes the temporary file and leaves the target as it was.
pub struct AtomicFile {
    /// `None` only once the file has been closed for the rename or on drop.
    file: Option<File>,
    tmp: PathBuf,
    target: PathBuf,
    overwrite: bool,
    committed: bool,
}

impl AtomicFile {
    /// Creates the temporary file for `target`.
    ///
    /// # Arguments
    ///
    /// - `target`: where the data appears after [`commit`](Self::commit).
    /// - `overwrite`: whether an existing `target` may be replaced.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::AlreadyExists`] if `target` exists and `overwrite` is false.
    /// - [`ErrorKind::InvalidInput`] if `target` has no file name.
    /// - Any error from the random source or from creating the temporary file.
    pub fn create(target: impl Into<PathBuf>, overwrite: bool) -> io::Result<Self> {
        let target = target.into();
        if !overwrite && target.exists() {
            return Err(already_exists(&target));
        }

        let name = target.file_name().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "output path has no file name")
        })?;
        let dir = match target.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };

        let mut random = [0u8; 6];
        getrandom::getrandom(&mut random)
            .map_err(|e| io::Error::other(format!("random generator failed: {e}")))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dir.join(format!(".{}.{suffix}.tmp", name.to_string_lossy()));

        let file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        Ok(Self {
            file: Some(file),
            tmp,
            target,
            overwrite,
            committed: false,
        })
    }

    /// Flushes the data to disk and moves the temporary file onto the target.
    ///
    /// Without `overwrite`, the target is published with a hard link, which fails if
    /// the target exists, even one created a moment earlier by another process. On
    /// filesystems without hard links, such as FAT, it falls back to a check and a
    /// rename, which leaves a short window for that race.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::AlreadyExists`] if the target appeared after
    ///   [`create`](Self::create) and `overwrite` is false.
    /// - Any error from syncing, linking or renaming.
    ///
    /// The temporary file is deleted on every error.
    pub fn commit(mut self) -> io::Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all()?;
            // Dropping `file` here closes it, which Windows requires before a rename.
        }
        if self.overwrite {
            fs::rename(&self.tmp, &self.target)?;
        } else {
            publish_new(&self.tmp, &self.target)?;
        }
        self.committed = true;
        Ok(())
    }

    fn file_mut(&mut self) -> &mut File {
        // `commit` and `drop` are the only places that take the file, and nothing
        // can write after either of them.
        self.file.as_mut().expect("file is open until commit")
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file_mut().flush()
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// Moves `tmp` to `target`, failing if `target` exists.
fn publish_new(tmp: &Path, target: &Path) -> io::Result<()> {
    match fs::hard_link(tmp, target) {
        Ok(()) => {
            // The target is complete now, so a temp file that can't be removed
            // shouldn't turn the run into a failure.
            let _ = fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(already_exists(target)),
        // No hard links on this filesystem, or another problem that the rename
        // will report again.
        Err(_) => {
            if target.exists() {
                return Err(already_exists(target));
            }
            fs::rename(tmp, target)
        }
    }
}

fn already_exists(path: &Path) -> io::Error {
    io::Error::new(
        ErrorKind::AlreadyExists,
        format!("{} already exists", path.display()),
    )
}
