//! Pinned proof artifacts shared by the Spark relation verifiers.
//!
//! A verified relation is not a completed ownership certificate or permission to
//! sign. Registry pins and expected statements come from authenticated local
//! configuration/state, never a proof.
use crate::handoff::Digest;
use std::path::PathBuf;

/// Exact pinned BB5.2 ZK UltraHonk proof shape qualified by the protocol suite.
pub const PROOF_BYTES: usize = 458 * 32;

/// This checksum must be obtained through the authenticated deployment process.
/// A proof-supplied checksum does not authenticate its own executable or key.
pub struct ArtifactPin {
    pub path: PathBuf,
    pub sha256: Digest,
}
