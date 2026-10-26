//! Deterministic local replay uses only frozen private inputs and exact frames.
//! Final native ciphertexts are wallet outputs, never requests to Zark.
use super::*;
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
use zark_spark_claim_mpc::ClaimEvaluator;
const MAX_FRAME: usize = 64 * 1024 * 1024;
impl ReceiveJournal {
    pub(super) fn write_blob(&self, bytes: &[u8]) -> Result<Digest> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_FRAME,
            "receive wallet frame size"
        );
        let digest = hash(&[bytes]);
        let path = self
            .directory
            .join(format!("frame-{}", hex::encode(digest)));
        if path.exists() {
            ensure!(
                self.read_blob(&digest)? == bytes,
                "receive wallet frame collision"
            );
        } else {
            zark_protocol::storage::atomic_write(&path, bytes)?;
        }
        Ok(digest)
    }
    pub(super) fn read_blob(&self, digest: &Digest) -> Result<Vec<u8>> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(
                self.directory
                    .join(format!("frame-{}", hex::encode(digest))),
            )?;
        let m = file.metadata()?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o777 == 0o600
                && m.uid() == unsafe { libc::geteuid() }
                && m.len() <= MAX_FRAME as u64,
            "receive wallet frame permissions/size"
        );
        zark_protocol::storage::sync_observed(&file, &self.directory)?;
        let mut bytes = Vec::new();
        file.take(MAX_FRAME as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_FRAME && hash(&[&bytes]) == *digest,
            "receive wallet frame digest changed"
        );
        Ok(bytes)
    }
    fn initial_digest(&self, id: &str) -> Result<Digest> {
        let p = self
            .record
            .prepared
            .as_ref()
            .context("receive preparation absent")?;
        ensure!(
            self.record.cluster.operators.contains_key(id),
            "unconfigured receive operator"
        );
        Ok(serde_json::from_value(
            p["operators"][id]["initial"].clone(),
        )?)
    }
    pub fn bind_initial_frame(&self, id: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            hash(&[bytes]) == self.initial_digest(id)?,
            "receive initial frame differs"
        );
        self.write_blob(bytes)?;
        self.persist()
    }
    fn evaluator(&mut self, id: &str) -> Result<(ClaimEvaluator, Vec<u8>)> {
        let t = self
            .record
            .transcripts
            .get(id)
            .context("unconfigured receive operator")?;
        if let Some((count, evaluator, message)) = self.cache.remove(id)
            && count == t.rounds.len()
            && t.rounds
                .last()
                .and_then(|r| r.reply)
                .is_some_and(|digest| digest == hash(&[&message]))
        {
            return Ok((evaluator, message));
        }
        let op = self
            .record
            .cluster
            .operators
            .get(id)
            .context("unconfigured receive operator")?;
        let secrets = self
            .record
            .mpc
            .as_ref()
            .context("receive wallet inputs already retired")?;
        let evaluation = Zeroizing::new(
            scalar(&secrets.incoming)? - scalar(&self.record.user)?
                + scalar(&secrets.slope)? * k256::Scalar::from(u64::from(op.index)),
        );
        let template = self.proofs()?.joint_template(&self.record.claim)?;
        let spec = self.circuit.spec();
        ensure!(
            template.len() == spec.plaintext_bytes
                && template[spec.scalar_offset..spec.scalar_offset + 32] == [0; 32],
            "native protobuf shape differs from MPC deployment"
        );
        let header: Vec<u8> = serde_json::from_value(
            self.record
                .prepared
                .as_ref()
                .context("receive preparation absent")?["operators"][id]["header"]
                .clone(),
        )?;
        let mut evaluator = ClaimEvaluator::start(
            &self.circuit,
            Zeroizing::new(evaluation.to_bytes().into()),
            template,
            &header,
            Zeroizing::new(
                *secrets
                    .seeds
                    .get(id)
                    .context("receive evaluator seed absent")?,
            ),
        )?;
        let mut message = self.read_blob(&self.initial_digest(id)?)?;
        for round in &self.record.transcripts[id].rounds {
            let output = evaluator.advance(&message)?;
            let req = Request::decode(&round.request)?;
            let Command::ReceiveFrame { frame, .. } = req.command else {
                anyhow::bail!("invalid receive round");
            };
            ensure!(
                hash(&[&output]) == frame && self.read_blob(&frame)? == output,
                "reconstructed wallet frame differs"
            );
            if let Some(reply) = round.reply {
                message = self.read_blob(&reply)?;
            } else {
                anyhow::bail!("receive reply is still pending");
            }
        }
        Ok((evaluator, message))
    }
    /// Freeze the next signed frame before returning it to a transport. An
    /// uncertain call always replays these identical bytes after reopening.
    pub fn next_mpc_request(&mut self, id: &str) -> Result<(Request, Vec<u8>)> {
        let transcript = self
            .record
            .transcripts
            .get(id)
            .context("unconfigured receive operator")?;
        ensure!(
            transcript.ciphertext.is_none() && transcript.rounds.len() <= 7,
            "receive MPC already completed"
        );
        if let Some(round) = transcript.rounds.last().filter(|r| r.reply.is_none()) {
            let request = Request::decode(&round.request)?;
            let Command::ReceiveFrame { frame, .. } = &request.command else {
                anyhow::bail!("invalid receive round");
            };
            self.persist()?;
            return Ok((request.clone(), self.read_blob(frame)?));
        }
        let step = transcript.rounds.len();
        ensure!(step < 7, "receive operator needs finalization");
        let (mut evaluator, message) = self.evaluator(id)?;
        let bytes = evaluator.advance(&message)?;
        let frame = self.write_blob(&bytes)?;
        let request = Request::sign(
            zark_protocol::spark_receive::frame_intent(&self.record.intent, id, step as u8)?,
            Command::ReceiveFrame {
                operator: id.into(),
                step: step as u8,
                frame,
            },
            &normalized_key(&self.record.session)?,
        )?;
        self.record
            .transcripts
            .get_mut(id)
            .context("receive transcript absent")?
            .rounds
            .push(Round {
                request: request.encode()?,
                reply: None,
            });
        self.cache
            .insert(id.into(), (step + 1, evaluator, Vec::new()));
        self.persist()?;
        Ok((request, bytes))
    }
    pub fn bind_mpc_reply(
        &mut self,
        request: &Request,
        response: &Value,
        bytes: &[u8],
    ) -> Result<()> {
        let Command::ReceiveFrame { operator, step, .. } = &request.command else {
            anyhow::bail!("not a receive frame");
        };
        ensure!(
            response.get("aborted").is_none(),
            "Zark retired the receive allocation after MPC failure"
        );
        let digest: Digest = serde_json::from_value(response["reply"].clone())?;
        ensure!(hash(&[bytes]) == digest, "receive reply hash differs");
        let round = self
            .record
            .transcripts
            .get(operator)
            .and_then(|t| t.rounds.get(usize::from(*step)))
            .context("receive request not frozen")?;
        ensure!(
            round.request == request.encode()? && round.reply.is_none_or(|r| r == digest),
            "receive reply changed frozen round"
        );
        self.write_blob(bytes)?;
        self.record
            .transcripts
            .get_mut(operator)
            .context("receive transcript absent")?
            .rounds[usize::from(*step)]
        .reply = Some(digest);
        if let Some((count, _, message)) = self.cache.get_mut(operator)
            && *count == usize::from(*step) + 1
        {
            *message = bytes.to_vec();
        }
        self.persist()
    }
    pub fn finish_operator(&mut self, id: &str) -> Result<()> {
        let t = self
            .record
            .transcripts
            .get(id)
            .context("unconfigured receive operator")?;
        if t.ciphertext.is_some() {
            return self.persist();
        }
        ensure!(
            t.rounds.len() == 7 && t.rounds.iter().all(|r| r.reply.is_some()),
            "receive MPC rounds incomplete"
        );
        let (evaluator, message) = self.evaluator(id)?;
        let bytes = evaluator.finish(&message)?;
        let digest = self.write_blob(&bytes)?;
        self.record
            .transcripts
            .get_mut(id)
            .context("receive transcript absent")?
            .ciphertext = Some(digest);
        if self
            .record
            .transcripts
            .values()
            .all(|t| t.ciphertext.is_some())
        {
            self.record.mpc = None;
        }
        self.persist()
    }
    pub fn packages(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        self.persist()?;
        self.record
            .transcripts
            .iter()
            .map(|(id, t)| {
                Ok((
                    id.clone(),
                    self.read_blob(&t.ciphertext.context("receive MPC package incomplete")?)?,
                ))
            })
            .collect()
    }
}
