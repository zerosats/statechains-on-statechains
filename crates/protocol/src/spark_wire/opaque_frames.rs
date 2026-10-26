//! Bounded, private, content-addressed MPC frames. Caller holds its journal lock
//! across slot freezing and transitions. Frame bytes themselves are opaque.
use crate::{
    hash,
    spark_lineage::Digest,
    storage::{atomic_write, sync_observed},
    timing::{Phase, Span},
};
use anyhow::{Result, ensure};
use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
/// Frame bytes with their content address, computed here exactly once so that
/// callers can check an expected digest and store without hashing again.
pub struct HashedFrame<'a> {
    bytes: &'a [u8],
    digest: Digest,
}
impl<'a> HashedFrame<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        let _timing = Span::new(Phase::OpaqueFrameHash);
        Self {
            bytes,
            digest: hash(&[bytes]),
        }
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
}
pub struct FrameStore {
    directory: PathBuf,
    max: usize,
}
impl FrameStore {
    pub fn open(directory: &Path, max: usize) -> Result<Self> {
        ensure!((1..=512 * 1024 * 1024).contains(&max), "opaque frame bound");
        if !directory.exists() {
            fs::DirBuilder::new().mode(0o700).create(directory)?;
            fs::File::open(
                directory
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("frame parent"))?,
            )?
            .sync_all()?;
        }
        let m = fs::symlink_metadata(directory)?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.mode() & 0o777 == 0o700
                && m.uid() == unsafe { libc::geteuid() },
            "opaque frame directory permissions/type"
        );
        Ok(Self {
            directory: directory.into(),
            max,
        })
    }
    fn read_file(&self, path: &Path, max: usize) -> Result<Vec<u8>> {
        let _timing = Span::new(Phase::OpaqueFrameRead);
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let m = f.metadata()?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o777 == 0o600
                && m.len() <= max as u64,
            "opaque frame file permissions/type/size"
        );
        sync_observed(&f, &self.directory)?;
        let mut bytes = Vec::new();
        f.take(max as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= max, "opaque frame grew");
        Ok(bytes)
    }
    pub fn read(&self, digest: &Digest) -> Result<Vec<u8>> {
        let bytes = self.read_file(&self.directory.join(hex::encode(digest)), self.max)?;
        ensure!(
            !bytes.is_empty() && HashedFrame::new(&bytes).digest == *digest,
            "opaque frame hash mismatch"
        );
        Ok(bytes)
    }
    pub fn write(&self, bytes: &[u8]) -> Result<Digest> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= self.max,
            "opaque frame size"
        );
        let frame = HashedFrame::new(bytes);
        self.store(&frame)?;
        Ok(frame.digest)
    }
    pub fn store(&self, frame: &HashedFrame) -> Result<()> {
        ensure!(
            !frame.bytes.is_empty() && frame.bytes.len() <= self.max,
            "opaque frame size"
        );
        let path = self.directory.join(hex::encode(frame.digest));
        if path.exists() {
            // The trusted bytes hash to this file name, so exact byte equality
            // also proves the existing file's content address.
            ensure!(
                self.read_file(&path, self.max)? == frame.bytes,
                "opaque frame collision"
            );
        } else {
            let _timing = Span::new(Phase::OpaqueFrameWrite);
            atomic_write(&path, frame.bytes)?;
        }
        Ok(())
    }
    fn slot(&self, label: &str) -> Result<PathBuf> {
        ensure!(
            !label.is_empty()
                && label.len() <= 160
                && label.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "opaque frame slot name"
        );
        Ok(self.directory.join(format!("slot-{label}")))
    }
    pub fn check_slot(&self, label: &str, digest: &Digest) -> Result<()> {
        ensure!(
            self.read_file(&self.slot(label)?, 32)? == digest,
            "opaque MPC input was frozen differently"
        );
        Ok(())
    }
    pub fn freeze_slot(&self, label: &str, digest: &Digest) -> Result<()> {
        let path = self.slot(label)?;
        if !path.exists() {
            atomic_write(&path, digest)?;
        }
        self.check_slot(label, digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn store() -> Result<FrameStore> {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../work/opaque-frame-tests");
        fs::create_dir_all(&parent)?;
        FrameStore::open(&parent.join(hex::encode(crate::random32())), 64)
    }

    #[test]
    fn existing_frames_must_equal_their_content_address() -> Result<()> {
        let frames = store()?;
        let digest = frames.write(b"first frame")?;
        assert_eq!(digest, hash(&[b"first frame"]));
        assert_eq!(frames.write(b"first frame")?, digest);
        frames.store(&HashedFrame::new(b"first frame"))?;
        assert_eq!(frames.read(&digest)?, b"first frame");
        assert!(frames.write(&[]).is_err() && frames.write(&[1; 65]).is_err());

        // Replace the content under the same name, keeping private permissions.
        let path = frames.directory.join(hex::encode(digest));
        fs::write(&path, b"other frame")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(frames.write(b"first frame").is_err());
        assert!(frames.store(&HashedFrame::new(b"first frame")).is_err());
        assert!(frames.read(&digest).is_err());
        Ok(())
    }
}
