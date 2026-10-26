//! Fresh Spark store with exact replay and an independently retained checkpoint.
mod checkpoint;
mod witness;
use super::{Policy, Request, state::Coin};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};
#[cfg(test)]
pub(super) use witness::path as witness_path;
use zark_protocol::{hash, random32, spark_lineage::Digest};
use zeroize::Zeroizing;

const APP_ID: u32 = 0x5a53504b;
const SCHEMA: u32 = 1;
const MAX_RECORD: usize = 64 * 1024;
const MAX_COINS: u64 = 1000;
const MAX_RESPONSES: u64 = 256;

pub(super) fn lock_guarded(
    db: &Path,
    checkpoint: &Path,
    guard: &dyn Fn() -> Result<()>,
) -> Result<crate::checkpoint::CheckpointLock> {
    let parent = db.parent().context("private database parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    ensure!(db != checkpoint, "checkpoint cannot be database");
    for path in [db, checkpoint] {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
                "unsafe private persistence file"
            );
        }
    }
    crate::checkpoint::CheckpointLock::acquire(db, checkpoint, guard)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Floor {
    database: Digest,
    config: Digest,
    pub sequence: u64,
    root: Digest,
}
impl Floor {
    pub fn database(&self) -> Digest {
        self.database
    }
}

pub(super) struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: &Path, config: Digest) -> Result<Self> {
        let connection = Connection::open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        connection.busy_timeout(Duration::from_secs(2))?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let tables: u64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if version == 0 && tables == 0 {
            connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;
                BEGIN IMMEDIATE;
                CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_id BLOB NOT NULL,config BLOB NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>=0),chain BLOB NOT NULL,previous_floor TEXT NOT NULL);
                CREATE TABLE coins(coin BLOB PRIMARY KEY,revision INTEGER NOT NULL CHECK(revision>0),body TEXT NOT NULL,checksum BLOB NOT NULL);
                CREATE TABLE responses(coin BLOB NOT NULL REFERENCES coins(coin),operation BLOB NOT NULL,purpose INTEGER NOT NULL,session BLOB NOT NULL,intent BLOB NOT NULL,request BLOB NOT NULL,body TEXT NOT NULL,checksum BLOB NOT NULL,PRIMARY KEY(coin,operation,purpose,session));")?;
            connection.pragma_update(None, "user_version", SCHEMA)?;
            connection.pragma_update(None, "application_id", APP_ID)?;
            connection.execute(
                "INSERT INTO metadata VALUES(1,?1,?2,0,?3,'')",
                params![
                    random32().as_slice(),
                    config.as_slice(),
                    [0u8; 32].as_slice()
                ],
            )?;
            connection.execute_batch("COMMIT;")?;
            fs::File::open(path.parent().context("Spark database parent")?)?.sync_all()?;
        } else {
            let application: u32 =
                connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
            ensure!(
                application == APP_ID && version == SCHEMA,
                "not a Spark signer store; no migration is permitted"
            );
            let saved: Vec<u8> = connection.query_row(
                "SELECT config FROM metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            ensure!(saved == config, "Spark signer configuration changed");
            let journal: String =
                connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
            ensure!(journal == "delete", "Spark signer journal mode changed");
            connection.execute_batch(
                "PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;",
            )?;
        }
        Ok(Self { connection })
    }

    pub fn validate(&self, policy: &Policy) -> Result<()> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        ensure!(integrity == "ok", "Spark database integrity");
        let orphan: Option<String> = self
            .connection
            .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
            .optional()?;
        ensure!(
            orphan.is_none(),
            "Spark journal contains an orphaned record"
        );
        let mut statement = self.connection.prepare("SELECT coin FROM coins")?;
        let ids = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(ids.len() <= MAX_COINS as usize, "Spark coin capacity");
        for id in ids {
            let id = array(id)?;
            let (coin, _) = self.coin(&id)?.context("missing Spark coin")?;
            ensure!(coin.coin == id, "Spark coin row identity");
            coin.validate(policy)?;
            let count: u64 = self.connection.query_row(
                "SELECT count(*) FROM responses WHERE coin=?1",
                [id.as_slice()],
                |row| row.get(0),
            )?;
            ensure!(count <= MAX_RESPONSES, "Spark per-coin response capacity");
        }
        self.floor()?;
        Ok(())
    }
    pub fn validate_receive_frames(&self, engine: &super::Engine) -> Result<()> {
        let mut query = self.connection.prepare("SELECT coin FROM coins")?;
        let ids = query
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in ids {
            let (coin, _) = self.coin(&array(id)?)?.context("missing Spark coin")?;
            if let Some(receive) = &coin.receive {
                receive.validate_frames(engine)?;
            }
            if let Some(identities) = &coin.identities {
                identities.validate_frames(engine)?;
            }
            if let Some(native) = &coin.native
                && let Some(tweaks) = &native.tweaks
            {
                tweaks.validate_frames(engine, &native.intent, native.session)?;
            }
        }
        Ok(())
    }

    pub fn coin(&self, id: &Digest) -> Result<Option<(Coin, u64)>> {
        let row: Option<(u64, String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT revision,body,checksum FROM coins WHERE coin=?1",
                [id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(revision, body, checksum)| {
            let body = Zeroizing::new(body);
            ensure!(
                body.len() <= MAX_RECORD && hash(&[body.as_bytes()]).as_slice() == checksum,
                "Spark coin checksum"
            );
            let coin: Coin = serde_json::from_str(&body)?;
            if let Some(native) = &coin.native {
                native.validate_revision(revision)?;
            }
            if let Some(bootstrap) = &coin.bootstrap {
                bootstrap.validate_revision(revision)?;
            }
            if let Some(single) = &coin.single_user {
                single.validate_revision(revision)?;
            }
            if let Some(receive) = &coin.receive {
                receive.validate_revision(revision)?;
            }
            Ok((coin, revision))
        })
        .transpose()
    }

    pub fn replay(&self, request: &Request, digest: &Digest) -> Result<Option<Value>> {
        let cancelled: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM responses WHERE coin=?1 AND operation=?2 AND purpose IN (9,14,19,22))",
            params![
                request.intent.coin.as_slice(),
                request.intent.operation.as_slice()
            ],
            |row| row.get(0),
        )?;
        ensure!(
            !cancelled
                || matches!(
                    request.command,
                    super::Command::Cancel { .. }
                        | super::Command::NativeExitCancel { .. }
                        | super::Command::NativeBootstrapCancel { .. }
                        | super::Command::SingleUserCancel {}
                ),
            "Spark operation was cancelled"
        );
        type Row = (Vec<u8>, Vec<u8>, String, Vec<u8>);
        let saved: Option<Row> = self.connection.query_row("SELECT intent,request,body,checksum FROM responses WHERE coin=?1 AND operation=?2 AND purpose=?3 AND session=?4", params![request.intent.coin.as_slice(), request.intent.operation.as_slice(), request.command.purpose(), request.session.as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).optional()?;
        saved
            .map(|(intent, expected, body, checksum)| {
                let body = Zeroizing::new(body);
                ensure!(
                    expected == digest.as_slice() && intent == request.intent.digest()?.as_slice(),
                    "Spark retry changed frozen request"
                );
                ensure!(
                    body.len() <= MAX_RECORD && hash(&[body.as_bytes()]).as_slice() == checksum,
                    "Spark response checksum"
                );
                Ok(serde_json::from_str(&body)?)
            })
            .transpose()
    }

    pub fn operation_exists(&self, coin: &Digest, operation: &Digest) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM responses WHERE coin=?1 AND operation=?2)",
            params![coin.as_slice(), operation.as_slice()],
            |row| row.get(0),
        )?)
    }

    pub(super) fn require_response_capacity(&self, coin: &Digest, needed: u64) -> Result<()> {
        let count: u64 = self.connection.query_row(
            "SELECT count(*) FROM responses WHERE coin=?1",
            [coin.as_slice()],
            |row| row.get(0),
        )?;
        ensure!(
            count
                .checked_add(needed)
                .is_some_and(|n| n <= MAX_RESPONSES),
            "insufficient Spark response capacity for complete native operation"
        );
        Ok(())
    }

    // One transaction freezes the mutation, exact response, request and floor.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &mut self,
        coin: &Coin,
        revision: Option<u64>,
        request: &Request,
        digest: Digest,
        response: &Value,
        floor: &Floor,
        purge_mask: bool,
    ) -> Result<()> {
        // Identity nonce/ECDH metadata is auxiliary to ownership. It changes
        // the authenticated global checkpoint and exact response journal, but
        // not the leaf's ownership CAS.
        let auxiliary = super::identity::is_command(&request.command)
            || super::auth::is_command(&request.command)
            || super::ecdsa_2p::is_command(&request.command)
            || super::native_tweaks::auxiliary(&request.command)
            || super::mpc_exit::auxiliary(&request.command);
        let next = if auxiliary {
            revision
        } else {
            revision.map_or(Some(1), |value| value.checked_add(1))
        };
        if let Some(native) = &coin.native {
            native.validate_revision(next.context("Spark revision exhausted")?)?;
        }
        // The same accounting `Store::coin` checks on load: a slip must fail
        // here rather than commit a coin that can never be loaded again.
        if let Some(receive) = &coin.receive {
            receive.validate_revision(next.context("Spark revision exhausted")?)?;
        }
        if let Some(bootstrap) = &coin.bootstrap {
            bootstrap.validate_revision(
                revision
                    .map_or(Some(1), |value| value.checked_add(1))
                    .context("Spark revision exhausted")?,
            )?;
        }
        if let Some(single) = &coin.single_user {
            single.validate_revision(
                revision
                    .map_or(Some(1), |v| v.checked_add(1))
                    .context("Spark revision exhausted")?,
            )?;
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sequence: u64 = tx.query_row(
            "SELECT sequence FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(sequence == floor.sequence, "stale Spark checkpoint floor");
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM responses WHERE coin=?1",
            [coin.coin.as_slice()],
            |row| row.get(0),
        )?;
        let needed = if matches!(request.command, super::Command::ReceivePrepare { .. }) {
            144
        } else if matches!(
            request.command,
            super::Command::SingleUserPrepare { .. } | super::Command::AuthPrepare { .. }
        ) {
            2
        } else if matches!(
            request.command,
            super::Command::Reserve { .. }
                | super::Command::NativeExitPrepare { .. }
                | super::Command::NativeBootstrapPrepare { .. }
        ) {
            7
        } else {
            1
        };
        ensure!(
            count + needed <= MAX_RESPONSES,
            "Spark response journal capacity"
        );
        let body = Zeroizing::new(serde_json::to_string(coin)?);
        let response = Zeroizing::new(serde_json::to_string(response)?);
        ensure!(
            body.len() <= MAX_RECORD && response.len() <= MAX_RECORD,
            "Spark persistence record size"
        );
        let checksum = hash(&[body.as_bytes()]);
        let response_checksum = hash(&[response.as_bytes()]);
        if let Some(revision) = revision {
            let changed = tx.execute(
                "UPDATE coins SET revision=?2,body=?3,checksum=?4 WHERE coin=?1 AND revision=?5",
                params![
                    coin.coin.as_slice(),
                    if auxiliary {
                        revision
                    } else {
                        revision
                            .checked_add(1)
                            .context("Spark revision exhausted")?
                    },
                    body.as_str(),
                    checksum.as_slice(),
                    revision
                ],
            )?;
            ensure!(changed == 1, "stale Spark coin revision");
        } else {
            let count: u64 = tx.query_row("SELECT count(*) FROM coins", [], |row| row.get(0))?;
            ensure!(count < MAX_COINS, "Spark coin capacity");
            tx.execute(
                "INSERT INTO coins VALUES(?1,1,?2,?3)",
                params![coin.coin.as_slice(), body.as_str(), checksum.as_slice()],
            )?;
        }
        if matches!(
            request.command,
            super::Command::Cancel { .. }
                | super::Command::NativeExitCancel { .. }
                | super::Command::NativeBootstrapCancel { .. }
                | super::Command::SingleUserCancel {}
        ) {
            let tombstone = "{\"cancelled\":true}";
            tx.execute(
                "UPDATE responses SET body=?3,checksum=?4 WHERE coin=?1 AND operation=?2",
                params![
                    coin.coin.as_slice(),
                    request.intent.operation.as_slice(),
                    tombstone,
                    hash(&[tombstone.as_bytes()]).as_slice()
                ],
            )?;
        } else if purge_mask {
            let tombstone = "{\"superseded\":true}";
            tx.execute("UPDATE responses SET body=?3,checksum=?4 WHERE coin=?1 AND operation=?2 AND purpose=3", params![coin.coin.as_slice(), request.intent.operation.as_slice(), tombstone, hash(&[tombstone.as_bytes()]).as_slice()])?;
        }
        tx.execute(
            "INSERT INTO responses VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                coin.coin.as_slice(),
                request.intent.operation.as_slice(),
                request.command.purpose(),
                request.session.as_slice(),
                request.intent.digest()?.as_slice(),
                digest.as_slice(),
                response.as_str(),
                response_checksum.as_slice()
            ],
        )?;
        let chain: Vec<u8> =
            tx.query_row("SELECT chain FROM metadata WHERE singleton=1", [], |row| {
                row.get(0)
            })?;
        let chain = hash(&[
            b"ZARK/spark/signer/commit/v1",
            &array(chain)?,
            &coin.coin,
            &checksum,
            &response_checksum,
            &digest,
        ]);
        tx.execute(
            "UPDATE metadata SET sequence=?1,chain=?2,previous_floor=?3 WHERE singleton=1",
            params![
                sequence
                    .checked_add(1)
                    .context("Spark sequence exhausted")?,
                chain.as_slice(),
                serde_json::to_string(floor)?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn array(bytes: Vec<u8>) -> Result<Digest> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Spark persistence digest length"))
}
