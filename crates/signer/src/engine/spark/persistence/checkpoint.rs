//! Commit/checkpoint publication follows the original signer's fail-closed gap.
use super::{Floor, MAX_COINS, MAX_RECORD, MAX_RESPONSES, Store, array};
use anyhow::{Result, ensure};
use std::{fs, path::Path};
use zark_protocol::{hash, storage::atomic_write};
use zeroize::Zeroizing;

impl Store {
    pub(super) fn floor(&self) -> Result<Floor> {
        let tx = self.connection.unchecked_transaction()?;
        type Metadata = (Vec<u8>, Vec<u8>, u64, Vec<u8>, String);
        let (database, config, sequence, chain, previous): Metadata = tx.query_row(
            "SELECT database_id,config,sequence,chain,previous_floor FROM metadata WHERE singleton=1", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
        ensure!(previous.len() < 4096, "Spark previous floor size");
        let database = array(database)?;
        let config = array(config)?;
        let records: u64 = tx.query_row(
            "SELECT (SELECT count(*) FROM coins)+(SELECT count(*) FROM responses)",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            sequence > 0 || records == 0,
            "uncommitted Spark records without checkpoint history"
        );
        let mut bytes = Vec::new();
        bytes.extend(database);
        bytes.extend(config);
        bytes.extend(sequence.to_le_bytes());
        bytes.extend(array(chain)?);
        bytes.extend(hash(&[previous.as_bytes()]));
        {
            let mut query =
                tx.prepare("SELECT coin,revision,body,checksum FROM coins ORDER BY coin")?;
            let rows = query.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?;
            let mut count = 0;
            for row in rows {
                let (coin, revision, body, checksum) = row?;
                let body = Zeroizing::new(body);
                ensure!(
                    revision > 0
                        && body.len() <= MAX_RECORD
                        && hash(&[body.as_bytes()]).as_slice() == checksum,
                    "Spark checkpoint coin checksum"
                );
                bytes.extend(array(coin)?);
                bytes.extend(revision.to_le_bytes());
                bytes.extend(array(checksum)?);
                count += 1;
            }
            ensure!(count <= MAX_COINS, "Spark checkpoint coin capacity");
        }
        {
            let mut query = tx.prepare("SELECT coin,operation,purpose,session,intent,request,body,checksum FROM responses ORDER BY coin,operation,purpose,session")?;
            type Row = (
                Vec<u8>,
                Vec<u8>,
                u8,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                String,
                Vec<u8>,
            );
            let rows = query.query_map([], |row| -> rusqlite::Result<Row> {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })?;
            let mut count = 0;
            for row in rows {
                let (coin, operation, purpose, session, intent, request, body, checksum) = row?;
                let body = Zeroizing::new(body);
                ensure!(
                    ((1..=9).contains(&purpose) || (12..=44).contains(&purpose))
                        && body.len() <= MAX_RECORD
                        && hash(&[body.as_bytes()]).as_slice() == checksum,
                    "Spark checkpoint response checksum or purpose"
                );
                bytes.extend(array(coin)?);
                bytes.extend(array(operation)?);
                bytes.push(purpose);
                bytes.extend(array(session)?);
                bytes.extend(array(intent)?);
                bytes.extend(array(request)?);
                bytes.extend(array(checksum)?);
                count += 1;
            }
            ensure!(
                count <= MAX_COINS * MAX_RESPONSES,
                "Spark checkpoint response capacity"
            );
        }
        tx.commit()?;
        Ok(Floor {
            database,
            config,
            sequence,
            root: hash(&[b"ZARK/spark/signer/checkpoint/v1", &bytes]),
        })
    }

    pub fn verify_floor(&self, path: &Path) -> Result<Floor> {
        let current = self.floor()?;
        if path.exists() {
            ensure!(
                read_floor(path)? == current,
                "Spark checkpoint mismatch; service paused"
            );
        } else {
            ensure!(
                current.sequence == 0,
                "missing Spark checkpoint for existing state"
            );
            atomic_write(path, &serde_json::to_vec(&current)?)?;
        }
        super::witness::advance(path, &current)?;
        Ok(current)
    }

    /// The witness follows the checkpoint so neither is behind a released reply.
    pub fn publish(&self, path: &Path) -> Result<()> {
        let floor = self.floor()?;
        atomic_write(path, &serde_json::to_vec(&floor)?)?;
        super::witness::advance(path, &floor)
    }

    /// Explicit operator action for a store opened before the witness existed:
    /// only a fully published state may become the witness's starting point.
    pub fn initialise_witness(&self, path: &Path) -> Result<()> {
        let current = self.floor()?;
        ensure!(
            read_floor(path)? == current,
            "Spark checkpoint mismatch; witness not initialised"
        );
        super::witness::initialise(path, &current)
    }

    /// Only an explicit operator action may repair one committed publication gap.
    pub fn repair_floor(&self, path: &Path) -> Result<()> {
        let old = read_floor(path)?;
        let current = self.floor()?;
        if old == current {
            return Ok(());
        }
        let previous: String = self.connection.query_row(
            "SELECT previous_floor FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(previous.len() < 4096, "Spark previous floor size");
        let previous: Floor = serde_json::from_str(&previous)?;
        ensure!(
            old == previous
                && old.database == current.database
                && old.config == current.config
                && old.sequence.checked_add(1) == Some(current.sequence),
            "not one interrupted Spark checkpoint publication"
        );
        self.publish(path)
    }
}

fn read_floor(path: &Path) -> Result<Floor> {
    ensure!(
        fs::metadata(path)?.len() < 4096,
        "Spark checkpoint file size"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
