//! Shared exit helpers: garbled-circuit identity signing, phase timing and
//! completion checks for the share-release exit.
use super::*;
use crate::joint_identity::JointIdentityJournal;
#[path = "exit/identity.rs"]
mod identity;
#[path = "exit/material.rs"]
mod material;
#[path = "exit/report.rs"]
mod report;

pub(super) fn sign_identity(
    engine: &Engine,
    wallet: &mut JointIdentityJournal,
    digest: [u8; 32],
) -> Result<Vec<u8>> {
    identity::sign(engine, wallet, digest)
}

pub(super) fn timed<T>(phase: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    report::timed(phase, run)
}

pub(super) fn verify_completion(
    before: &Value,
    after: &Value,
    received: &Value,
    receiver: &[u8],
    recipient: &Value,
) -> Result<()> {
    material::verify_completion(before, after, received, receiver, recipient)
}
