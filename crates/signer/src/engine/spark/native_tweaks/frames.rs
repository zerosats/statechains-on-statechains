//! Authenticated input slots freeze before private MPC work. Only committed
//! frame hashes can release a response, including after process recovery.
use super::*;
impl Engine {
    pub(super) fn tweak_files(&self) -> Result<FrameStore> {
        let parent = self.db.parent().context("native tweak DB parent")?;
        let name = self
            .db
            .file_name()
            .context("native tweak DB name")?
            .to_string_lossy();
        FrameStore::open(
            &parent.join(format!("{name}.native-tweak-frames")),
            512 * 1024 * 1024,
        )
    }
    pub fn handle_native_tweak_frame(
        &self,
        request: &Request,
        frame: &[u8],
    ) -> Result<(Value, Option<Vec<u8>>)> {
        let digest = request.authenticate()?;
        let Command::NativeTweakFrame {
            operator,
            step,
            frame: expected,
        } = &request.command
        else {
            anyhow::bail!("not native tweak frame")
        };
        ensure!(
            !frame.is_empty() && frame.len() <= 512 * 1024 * 1024 && hash(&[frame]) == *expected,
            "native tweak frame size/hash"
        );
        {
            let _lock = super::super::lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
            let store = super::super::Store::open(&self.db, self.config)?;
            store.verify_floor(&self.checkpoint)?;
            if let Some(response) = store.replay(request, &digest)? {
                let reply = response
                    .get("reply")
                    .map(|v| serde_json::from_value::<Digest>(v.clone()))
                    .transpose()?;
                return Ok((
                    response,
                    reply.map(|d| self.tweak_files()?.read(&d)).transpose()?,
                ));
            }
            let (coin, _) = store
                .coin(&request.intent.coin)?
                .context("unknown native tweak coin")?;
            coin.validate(&self.policy)?;
            let native = coin.native.as_ref().context("native exit missing")?;
            let w = native
                .tweaks
                .as_ref()
                .context("native tweak preparation missing")?;
            ensure!(
                native.session == request.session
                    && !native.completed()
                    && w.secrets.is_some()
                    && request.intent
                        == native_tweak_frame_intent(&native.intent, operator, *step)?
                    && w.transcripts
                        .get(operator)
                        .is_some_and(|t| t.rounds.len() == usize::from(*step)),
                "native tweak frame session/order"
            );
            let files = self.tweak_files()?;
            files.write(frame)?;
            files.freeze_slot(&slot(request), &digest)?;
        }
        let response = self.handle(request)?;
        let reply = response
            .get("reply")
            .map(|v| serde_json::from_value::<Digest>(v.clone()))
            .transpose()?;
        Ok((
            response,
            reply.map(|d| self.tweak_files()?.read(&d)).transpose()?,
        ))
    }
    pub fn native_tweak_initial_frame(&self, request: &Request, operator: &str) -> Result<Vec<u8>> {
        ensure!(
            matches!(request.command, Command::NativeTweakPrepare { .. }),
            "not native tweak preparation"
        );
        let digest = request.authenticate()?;
        let _lock = super::super::lock_guarded(&self.db, &self.checkpoint, &|| Ok(()))?;
        let store = super::super::Store::open(&self.db, self.config)?;
        store.verify_floor(&self.checkpoint)?;
        let response = store
            .replay(request, &digest)?
            .context("native tweak preparation not committed")?;
        self.tweak_files()?.read(&serde_json::from_value(
            response["operators"][operator]["initial"].clone(),
        )?)
    }
    pub(super) fn tweak_contributor(
        &self,
        w: &Workflow,
        intent: &Intent,
        secret: &Digest,
        id: &str,
    ) -> Result<(EncryptionMask, ClaimContributor, Vec<u8>)> {
        let cluster = self
            .policy
            .native_cluster
            .as_ref()
            .context("native tweak cluster missing")?;
        let key = cluster
            .operators
            .get(id)
            .context("native tweak operator missing")?;
        let s = w.secrets.as_ref().context("native tweak inputs retired")?;
        let derive = |purpose: &[u8]| -> Result<Zeroizing<Digest>> {
            Ok(Zeroizing::new(hash(&[
                b"ZARK/spark/native-tweak/randomness/v1",
                purpose,
                &s.seed,
                &intent.encode()?,
                &w.circuit,
                id.as_bytes(),
            ])))
        };
        let circuit = self.tweak_circuit(w.spec)?;
        ensure!(
            circuit.digest() == w.circuit,
            "native tweak circuit changed"
        );
        let mask = EncryptionMask::from_seed(key, w.spec.plaintext_bytes, derive(b"ecies")?)?;
        let evaluation = Zeroizing::new(
            scalar(secret)? + scalar(&s.slope)? * k256::Scalar::from(u64::from(index(id)?)),
        );
        let (contributor, message) = ClaimContributor::start(
            &circuit,
            Zeroizing::new(evaluation.to_bytes().into()),
            &mask,
            derive(b"ot")?,
        )?;
        Ok((mask, contributor, message))
    }
    pub(super) fn advance_tweak(
        &self,
        w: &Workflow,
        intent: &Intent,
        secret: &Digest,
        id: &str,
        frame: &Digest,
    ) -> Result<Digest> {
        let files = self.tweak_files()?;
        let t = w
            .transcripts
            .get(id)
            .context("native tweak transcript missing")?;
        files.read(&t.initial)?;
        for (input, output) in &t.rounds {
            files.read(input)?;
            files.read(output)?;
        }
        let prefix = hash(&[&serde_json::to_vec(t)?]);
        let key = (intent.coin, intent.operation, id.to_owned());
        let cached = self
            .native_tweaks
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("native tweak cache poisoned"))?
            .remove(&key)
            .filter(|c| c.prefix == prefix);
        let mut contributor = if let Some(c) = cached {
            c.contributor
        } else {
            let (_, mut c, initial) = self.tweak_contributor(w, intent, secret, id)?;
            ensure!(
                hash(&[&initial]) == t.initial,
                "native tweak initial replay changed"
            );
            for (input, expected) in &t.rounds {
                ensure!(
                    hash(&[&c.advance(&files.read(input)?)?]) == *expected,
                    "native tweak transcript replay changed"
                );
            }
            c
        };
        let reply = files.write(&contributor.advance(&files.read(frame)?)?)?;
        if t.rounds.len() + 1 < 7 {
            let mut next = t.clone();
            next.rounds.push((*frame, reply));
            self.native_tweaks
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("native tweak cache poisoned"))?
                .insert(
                    key,
                    Cache {
                        prefix: hash(&[&serde_json::to_vec(&next)?]),
                        contributor,
                    },
                );
        }
        Ok(reply)
    }
}
