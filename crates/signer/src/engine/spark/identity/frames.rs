//! Signed input slots freeze before MPC processing; checkpoint commits precede
//! frame release. On restart only the original frozen transcript can replay.
use super::*;
use zark_protocol::{
    spark_wire::opaque_frames::{FrameStore, HashedFrame},
    timing::{Phase as Timing, Span},
};
const MAX_FRAME: usize = 512 * 1024 * 1024;
impl Engine {
    pub(super) fn identity_files(&self) -> Result<FrameStore> {
        let name = self
            .db
            .file_name()
            .context("identity DB name")?
            .to_string_lossy();
        FrameStore::open(
            &self
                .db
                .parent()
                .context("identity DB parent")?
                .join(format!("{name}.identity-frames")),
            MAX_FRAME,
        )
    }
    pub fn handle_identity_frame(
        &self,
        request: &Request,
        frame: &[u8],
    ) -> Result<(Value, Option<Vec<u8>>)> {
        let digest = request.authenticate()?;
        let Command::IdentityFrame {
            identity,
            step,
            frame: expected,
        } = &request.command
        else {
            anyhow::bail!("not identity frame")
        };
        ensure!(
            !frame.is_empty() && frame.len() <= MAX_FRAME,
            "identity frame size/hash"
        );
        let frame = HashedFrame::new(frame);
        ensure!(frame.digest() == *expected, "identity frame size/hash");
        {
            let _lock = super::super::lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
            let store = super::super::Store::open(&self.db, self.config)?;
            store.verify_floor(&self.checkpoint)?;
            // Old scopes can be retired after a handover. Their authenticated
            // exact replies remain replayable without reviving old secrets.
            if let Some(response) = store.replay(request, &digest)? {
                let reply = response
                    .get("reply")
                    .map(|v| serde_json::from_value::<Digest>(v.clone()))
                    .transpose()?;
                return Ok((
                    response,
                    reply.map(|d| self.identity_files()?.read(&d)).transpose()?,
                ));
            }
            let (coin, _) = store
                .coin(&request.intent.coin)?
                .context("unknown identity allocation")?;
            coin.validate(&self.policy)?;
            let w = coin
                .identities
                .as_ref()
                .and_then(|s| s.sessions.get(&hex::encode(identity)))
                .context("unknown identity session")?;
            ensure!(
                w.session == request.session
                    && request.intent == identity_frame_intent(&w.intent, *step)?,
                "identity frame session/context"
            );
            scope(&coin, &request.session)?;
            ensure!(
                w.message.is_some() && w.secrets.is_some() && usize::from(*step) == w.rounds.len(),
                "identity frame stage/order"
            );
            let files = self.identity_files()?;
            files.store(&frame)?;
            files.freeze_slot(&slot(request), &digest)?;
        }
        let response = self.handle(request)?;
        let reply = response
            .get("reply")
            .map(|v| serde_json::from_value::<Digest>(v.clone()))
            .transpose()?;
        Ok((
            response,
            reply.map(|d| self.identity_files()?.read(&d)).transpose()?,
        ))
    }
    pub fn identity_initial_frame(&self, request: &Request) -> Result<Vec<u8>> {
        ensure!(
            matches!(request.command, Command::IdentityPrepare { .. }),
            "not identity prepare"
        );
        let digest = request.authenticate()?;
        let _lock = super::super::lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
        let store = super::super::Store::open(&self.db, self.config)?;
        store.verify_floor(&self.checkpoint)?;
        let response = store
            .replay(request, &digest)?
            .context("identity prepare not committed")?;
        self.identity_files()?
            .read(&serde_json::from_value(response["initial"].clone())?)
    }
    /// Any error here retires the session, so the caller reads the durable
    /// input frame first; an unavailable frame remains a retryable failure.
    pub(super) fn advance_identity(
        &self,
        w: &Workflow,
        secret: &Digest,
        frame: &Digest,
        input: &[u8],
    ) -> Result<Digest> {
        let files = self.identity_files()?;
        let runtime = self.identity.as_ref().context("identity disabled")?;
        let key = (w.intent.coin, w.intent.operation);
        let prefix = hash(&[&serde_json::to_vec(&w.rounds)?]);
        // A cached contributor exists only after this process produced or
        // replayed exactly this committed transcript, storing every frame
        // durably on the way. Restarts take the verified replay below.
        let cached = runtime
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("identity cache poisoned"))?
            .remove(&key)
            .filter(|c| c.prefix == prefix && c.initial == w.initial);
        let mut contributor = if let Some(c) = cached {
            c.contributor
        } else {
            files.read(&w.initial)?;
            let (mut c, initial) = self.identity_contributor(w, secret)?;
            ensure!(
                hash(&[&initial]) == w.initial,
                "identity initial replay changed"
            );
            for (input, expected) in &w.rounds {
                files.read(expected)?;
                ensure!(
                    hash(&[&c.advance(&files.read(input)?)?]) == *expected,
                    "identity transcript replay changed"
                );
            }
            c
        };
        let reply = {
            let _timing = Span::new(Timing::IdentityMpc);
            contributor.advance(input)?
        };
        let reply = files.write(&reply)?;
        if w.rounds.len() + 1 < 7 {
            let mut next = w.rounds.clone();
            next.push((*frame, reply));
            self.cache_identity(w, &next, contributor)?;
        }
        Ok(reply)
    }
    pub(super) fn cache_identity(
        &self,
        w: &Workflow,
        rounds: &[(Digest, Digest)],
        contributor: IdentityContributor,
    ) -> Result<()> {
        let runtime = self.identity.as_ref().context("identity disabled")?;
        let cache = Cache {
            prefix: hash(&[&serde_json::to_vec(rounds)?]),
            initial: w.initial,
            contributor,
        };
        runtime
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("identity cache poisoned"))?
            .insert((w.intent.coin, w.intent.operation), cache);
        Ok(())
    }
}
