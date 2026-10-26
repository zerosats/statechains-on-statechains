//! Locked private wallet-operation files, with bounded reads and durable writes.
use anyhow::{Result, ensure};
use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zark_protocol::{
    local::ProcessLock,
    storage::{atomic_write, sync_observed},
};
use zeroize::Zeroizing;

pub(crate) struct OperationFile {
    directory: PathBuf,
    file: &'static str,
    _lock: ProcessLock,
}
impl OperationFile {
    pub fn create(directory: &Path, file: &'static str) -> Result<Self> {
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        check_directory(directory)?;
        let lock = ProcessLock::acquire(&directory.join("operation.lock"))?;
        check_file(&fs::symlink_metadata(directory.join("operation.lock"))?)?;
        Ok(Self {
            directory: directory.into(),
            file,
            _lock: lock,
        })
    }
    pub fn open(
        directory: &Path,
        file: &'static str,
        limit: usize,
    ) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        check_directory(directory)?;
        check_file(&fs::symlink_metadata(directory.join("operation.lock"))?)?;
        let lock = ProcessLock::acquire(&directory.join("operation.lock"))?;
        let mut handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(file))?;
        check_file(&handle.metadata()?)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut handle)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= limit, "private wallet operation size");
        sync_observed(&handle, directory)?;
        Ok((
            Self {
                directory: directory.into(),
                file,
                _lock: lock,
            },
            bytes,
        ))
    }
    pub fn save(&self, bytes: &[u8], limit: usize) -> Result<()> {
        ensure!(bytes.len() <= limit, "private wallet operation size");
        atomic_write(&self.directory.join(self.file), bytes)
    }
}
fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions or mutable state accessible here.
    unsafe { libc::geteuid() }
}
fn check_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == uid() && m.mode() & 0o777 == 0o700,
        "private wallet directory permissions or owner"
    );
    Ok(())
}
fn check_file(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file() && m.uid() == uid() && m.nlink() == 1 && m.mode() & 0o777 == 0o600,
        "private wallet file permissions or owner"
    );
    Ok(())
}
