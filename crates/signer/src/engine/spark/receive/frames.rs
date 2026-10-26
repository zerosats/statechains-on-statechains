//! Content-addressed opaque frames are outside bounded SQL records. Their
//! digests enter the same committed checkpoint as the protocol transition.
use super::*;
use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};
use zark_spark_claim_mpc::{ClaimContributor, EncryptionMask};
use zeroize::Zeroizing;
const MAX_FRAME: usize = 64 * 1024 * 1024;
impl Engine {
    fn receive_blob_directory(&self) -> Result<PathBuf> {
        let parent = self.db.parent().context("receive database directory")?;
        let name = self
            .db
            .file_name()
            .context("receive database name")?
            .to_string_lossy();
        let path = parent.join(format!("{name}.claim-frames"));
        if !path.exists() {
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            fs::File::open(parent)?.sync_all()?;
        }
        let meta = fs::symlink_metadata(&path)?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.permissions().mode() & 0o777 == 0o700,
            "receive frame directory permissions/type"
        );
        Ok(path)
    }
    pub(super) fn read_receive_blob(&self, digest: &Digest) -> Result<Vec<u8>> {
        let directory = self.receive_blob_directory()?;
        let path = directory.join(hex::encode(digest));
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = file.metadata()?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.len() <= MAX_FRAME as u64
                && meta.permissions().mode() & 0o777 == 0o600,
            "receive frame size/type/permissions"
        );
        zark_protocol::storage::sync_observed(&file, &directory)?;
        let mut bytes = Vec::new();
        file.take(MAX_FRAME as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_FRAME && hash(&[&bytes]) == *digest,
            "receive frame digest changed"
        );
        Ok(bytes)
    }
    pub(super) fn write_receive_blob(&self, bytes: &[u8]) -> Result<Digest> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_FRAME,
            "receive frame size"
        );
        let digest = hash(&[bytes]);
        let path = self.receive_blob_directory()?.join(hex::encode(digest));
        if path.exists() {
            ensure!(
                self.read_receive_blob(&digest)? == bytes,
                "receive frame collision"
            );
        } else {
            zark_protocol::storage::atomic_write(&path, bytes)?;
        }
        Ok(digest)
    }
    fn receive_request_slot(&self, request: &Request) -> Result<PathBuf> {
        Ok(self.receive_blob_directory()?.join(format!(
            "round-{}-{}",
            hex::encode(request.intent.coin),
            hex::encode(request.intent.operation)
        )))
    }
    pub(super) fn check_receive_request_slot(&self, request: &Request) -> Result<()> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.receive_request_slot(request)?)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file() && m.nlink() == 1 && m.len() == 32 && m.mode() & 0o777 == 0o600,
            "receive request slot shape"
        );
        zark_protocol::storage::sync_observed(&file, &self.receive_blob_directory()?)?;
        let mut digest = Vec::new();
        file.take(33).read_to_end(&mut digest)?;
        // Public entry points authenticate before reaching this check. Reopen
        // validation also reconstructs this digest from committed public fields.
        ensure!(
            digest == request.digest()?,
            "receive round input was already frozen differently"
        );
        Ok(())
    }
    /// Only authenticated, configured receive sessions can stage opaque input.
    /// The method returns after SQL commit AND checkpoint publication.
    pub fn handle_receive_frame(
        &self,
        request: &Request,
        frame: &[u8],
    ) -> Result<(Value, Option<Vec<u8>>)> {
        request.authenticate()?;
        let Command::ReceiveFrame {
            operator,
            step,
            frame: digest,
        } = &request.command
        else {
            anyhow::bail!("not a receive frame");
        };
        ensure!(
            !frame.is_empty() && frame.len() <= MAX_FRAME && hash(&[frame]) == *digest,
            "receive frame size/hash"
        );
        {
            let _lock = super::super::lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
            let store = super::super::Store::open(&self.db, self.config)?;
            store.verify_floor(&self.checkpoint)?;
            let (coin, _) = store
                .coin(&request.intent.coin)?
                .context("unknown receive coin")?;
            coin.validate(&self.policy)?;
            let w = coin
                .receive
                .as_ref()
                .context("receive preparation missing")?;
            ensure!(
                request.session == w.session
                    && request.intent == frame_intent(&w.intent, operator, *step)?
                    && w.transcripts.contains_key(operator),
                "receive frame session/context"
            );
            if store.replay(request, &request.authenticate()?)?.is_none() {
                ensure!(
                    w.stage == Stage::Prepared
                        && w.transcripts[operator].rounds.len() == usize::from(*step),
                    "receive frame stage/order"
                );
            }
            // Freeze the authenticated input BEFORE processing it. Even a
            // process failure inside the MPC cannot permit an alternate input
            // to reuse this round's published OT messages and private seed.
            let slot = self.receive_request_slot(request)?;
            if slot.exists() {
                self.check_receive_request_slot(request)?;
            }
            self.write_receive_blob(frame)?;
            if !slot.exists() {
                zark_protocol::storage::atomic_write(&slot, &request.authenticate()?)?;
            }
            self.check_receive_request_slot(request)?;
        }
        let response = self.handle(request)?;
        let reply = response
            .get("reply")
            .map(|v| serde_json::from_value::<Digest>(v.clone()))
            .transpose()?;
        Ok((
            response,
            reply
                .map(|digest| self.read_receive_blob(&digest))
                .transpose()?,
        ))
    }
    /// Fetch only a committed initial frame for this authenticated preparation.
    pub fn receive_initial_frame(&self, request: &Request, operator: &str) -> Result<Vec<u8>> {
        ensure!(
            matches!(request.command, Command::ReceivePrepare { .. }),
            "not receive preparation"
        );
        let digest = request.authenticate()?;
        let _lock = super::super::lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
        let store = super::super::Store::open(&self.db, self.config)?;
        store.verify_floor(&self.checkpoint)?;
        let response = store
            .replay(request, &digest)?
            .context("receive preparation is not committed")?;
        let raw = response
            .get("operators")
            .and_then(|v| v.get(operator))
            .and_then(|v| v.get("initial"))
            .context("receive operator missing")?;
        self.read_receive_blob(&serde_json::from_value(raw.clone())?)
    }
    pub(super) fn receive_contributor(
        &self,
        w: &Workflow,
        secret: &Digest,
        id: &str,
    ) -> Result<(EncryptionMask, ClaimContributor, Vec<u8>)> {
        let runtime = self.receive.as_ref().context("receive runtime missing")?;
        let op = runtime
            .cluster
            .operators
            .get(id)
            .context("unconfigured receive operator")?;
        let s = w
            .secrets
            .as_ref()
            .context("receive MPC inputs already retired")?;
        let derive = |purpose: &[u8]| -> Result<Zeroizing<Digest>> {
            Ok(Zeroizing::new(hash(&[
                b"ZARK/spark/receive/randomness/v1",
                purpose,
                &s.seed,
                &w.intent.encode()?,
                &w.circuit,
                id.as_bytes(),
            ])))
        };
        let mask = EncryptionMask::from_seed(
            &op.encryption_key,
            runtime.circuit.spec().plaintext_bytes,
            derive(b"ecies")?,
        )?;
        let evaluation = Zeroizing::new(
            -scalar(secret)? + scalar(&s.slope)? * k256::Scalar::from(u64::from(op.index)),
        );
        let (contributor, message) = ClaimContributor::start(
            &runtime.circuit,
            Zeroizing::new(evaluation.to_bytes().into()),
            &mask,
            derive(b"ot")?,
        )?;
        Ok((mask, contributor, message))
    }
    pub(super) fn advance_receive(
        &self,
        w: &Workflow,
        secret: &Digest,
        id: &str,
        frame: &Digest,
    ) -> Result<Digest> {
        let transcript = w
            .transcripts
            .get(id)
            .context("receive transcript missing")?;
        self.read_receive_blob(&transcript.initial)?;
        for (input, output) in &transcript.rounds {
            self.read_receive_blob(input)?;
            self.read_receive_blob(output)?;
        }
        let runtime = self.receive.as_ref().context("receive runtime missing")?;
        let key = (w.intent.coin, w.intent.operation, id.to_owned());
        let prefix = hash(&[&serde_json::to_vec(transcript)?]);
        let cached = runtime
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("receive cache poisoned"))?
            .remove(&key)
            .filter(|c| c.prefix == prefix);
        let mut contributor = if let Some(c) = cached {
            c.contributor
        } else {
            let (_, mut contributor, initial) = self.receive_contributor(w, secret, id)?;
            ensure!(
                hash(&[&initial]) == transcript.initial,
                "receive reconstructed initial frame changed"
            );
            for (request, reply) in &transcript.rounds {
                let output = contributor.advance(&self.read_receive_blob(request)?)?;
                ensure!(
                    hash(&[&output]) == *reply,
                    "receive reconstructed transcript changed"
                );
            }
            contributor
        };
        let output = contributor.advance(&self.read_receive_blob(frame)?)?;
        let reply = self.write_receive_blob(&output)?;
        if transcript.rounds.len() + 1 < 7 {
            let mut next = transcript.clone();
            next.rounds.push((*frame, reply));
            runtime
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("receive cache poisoned"))?
                .insert(
                    key,
                    ContributorCache {
                        prefix: hash(&[&serde_json::to_vec(&next)?]),
                        contributor,
                    },
                );
        }
        Ok(reply)
    }
    pub(super) fn clear_receive_cache(&self, w: &Workflow) -> Result<()> {
        self.receive
            .as_ref()
            .context("receive runtime missing")?
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("receive cache poisoned"))?
            .retain(|(coin, operation, _), _| {
                *coin != w.intent.coin || *operation != w.intent.operation
            });
        Ok(())
    }
}
