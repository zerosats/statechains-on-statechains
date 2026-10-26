//! Startup and per-request rollback guard: a forward-only record of the newest
//! published floor, kept beside the checkpoint and outside the database.
//!
//! The checkpoint alone catches a database restored without its checkpoint,
//! but it is rewritten in place, so a database restored together with its own
//! checkpoint opens cleanly. With share release, such a state would release a
//! former owner's still-valid share to that owner, so the witness only moves
//! forward and the engine refuses any floor behind it. Signer backups
//! must exclude this file. A missing witness is created silently only for a
//! fresh store (sequence 0); otherwise the engine refuses to open until the
//! operator explicitly initialises it, trusting the current state as newest.
use super::Floor;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zark_protocol::{spark_lineage::Digest, storage::atomic_write};

const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    version: u32,
    database: Digest,
    sequence: u64,
    root: Digest,
}

pub(in crate::engine::spark) fn path(checkpoint: &Path) -> PathBuf {
    checkpoint.with_extension("witness")
}

fn read(path: &Path) -> Result<Option<Witness>> {
    if !path.exists() {
        return Ok(None);
    }
    ensure!(
        fs::metadata(path)?.len() < 4096,
        "Spark rollback witness size"
    );
    let witness: Witness = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(witness.version == VERSION, "Spark rollback witness version");
    Ok(Some(witness))
}

/// Refuses a floor behind the witness; otherwise moves the witness up to it.
/// Called under the checkpoint lock before any reply is released.
pub(super) fn advance(checkpoint: &Path, floor: &Floor) -> Result<()> {
    let path = path(checkpoint);
    if let Some(witness) = read(&path)? {
        ensure!(
            witness.database == floor.database,
            "Spark database differs from its rollback witness; service refused"
        );
        ensure!(
            witness.sequence < floor.sequence
                || (witness.sequence == floor.sequence && witness.root == floor.root),
            "Spark state is behind its rollback witness (restored or rolled back); service refused"
        );
        if witness.sequence == floor.sequence {
            return Ok(());
        }
    } else {
        // A restored snapshot or a new host has state but no witness; serving
        // it could release a former owner's share.
        ensure!(
            floor.sequence == 0,
            "Spark rollback witness missing for existing state; service refused until the operator explicitly initialises it"
        );
    }
    write(&path, floor)
}

/// The operator's explicit decision to trust the current, published state as
/// the newest. An existing witness is kept and still checked by `advance`.
pub(super) fn initialise(checkpoint: &Path, floor: &Floor) -> Result<()> {
    let path = path(checkpoint);
    if path.exists() {
        return Ok(());
    }
    write(&path, floor)
}

fn write(path: &Path, floor: &Floor) -> Result<()> {
    atomic_write(
        path,
        &serde_json::to_vec(&Witness {
            version: VERSION,
            database: floor.database,
            sequence: floor.sequence,
            root: floor.root,
        })?,
    )
}
