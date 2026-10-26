//! Freeze the signing message before releasing reusable presigning material.
//! Restoring an unused ticket must never authorize a different message.
use super::*;
use zark_protocol::{
    spark_wire::opaque_frames::HashedFrame,
    timing::{Phase, Span},
};
impl JointIdentityJournal {
    /// Resume the same unfinished presign before allocating any fresh nonce.
    pub fn pending_presign_request(&self) -> Result<Option<Request>> {
        self.persist()?;
        self.record
            .signing
            .values()
            .find(|s| {
                !s.aborted && s.nonce.is_some() && s.presign.is_none() && s.signature.is_none()
            })
            .map(|s| Request::decode(&s.prepare))
            .transpose()
    }
    pub fn presign_rounds_complete(&self, id: &Digest) -> Result<bool> {
        let s = self
            .record
            .signing
            .get(&hex::encode(id))
            .context("identity presign missing")?;
        ensure!(!s.aborted, "identity presign aborted");
        self.persist()?;
        Ok(s.rounds.len() == 7 && s.rounds.iter().all(|r| r.reply.is_some()))
    }
    pub fn ready_signatures(&self) -> usize {
        self.record
            .signing
            .values()
            .filter(|s| {
                !s.aborted
                    && s.presign.is_some()
                    && s.sign.is_none()
                    && Request::decode(&s.prepare).is_ok_and(|r| {
                        matches!(
                            r.command,
                            Command::IdentityPrepare {
                                message: Some(_),
                                ..
                            }
                        )
                    })
            })
            .count()
    }
    pub fn saved_sign_request(&self, digest: &Digest) -> Result<Option<Request>> {
        self.persist()?;
        for s in self.record.signing.values() {
            if let Some(wire) = &s.sign {
                let request = Request::decode(wire)?;
                if matches!(request.command,Command::IdentitySign {digest:d,..} if d==*digest) {
                    return Ok(Some(request));
                }
            }
        }
        Ok(None)
    }
    pub fn prepare_request(&mut self) -> Result<Request> {
        anyhow::bail!(
            "unbound identity tickets are retired; use prepare_message_request with the exact message digest"
        )
    }
    pub fn prepare_message_request(&mut self, message: Digest) -> Result<Request> {
        ensure!(
            self.record.server.is_some() && self.record.signing.len() < 8,
            "identity presigning capacity/allocation"
        );
        let nonce: Digest = random_scalar().to_bytes().into();
        let public = nonce_public(&nonce)?;
        let commitment = self.key_commitment()?;
        let request = self.signed(
            identity_message_intent(&self.record.intent, &commitment, &public, &message)?,
            Command::IdentityPrepare {
                commitment,
                nonce: public,
                message: Some(message),
            },
        )?;
        self.record.signing.insert(
            hex::encode(request.intent.operation),
            Signing {
                prepare: request.encode()?,
                nonce: Some(nonce),
                seed: Some(random32()),
                prepared: None,
                rounds: Vec::new(),
                presign: None,
                sign: None,
                signature: None,
                aborted: false,
            },
        );
        self.persist()?;
        Ok(request)
    }
    pub fn bind_prepare(&mut self, id: &Digest, response: &Value, initial: &[u8]) -> Result<()> {
        let id = hex::encode(id);
        let s = self
            .record
            .signing
            .get(&id)
            .context("identity prepare not saved")?;
        let public: Vec<u8> = serde_json::from_value(response["nonce"].clone())?;
        let r: Digest = serde_json::from_value(response["r"].clone())?;
        let first: Digest = serde_json::from_value(response["initial"].clone())?;
        ensure!(
            response["circuit"] == serde_json::json!(self.circuit.digest())
                && r == nonce_r(&s.nonce.context("identity nonce retired")?, &public)?
                && hash(&[initial]) == first,
            "identity prepare nonce/circuit/frame mismatch"
        );
        if let Some(old) = &s.prepared {
            ensure!(old == response, "identity preparation changed");
        }
        self.frames.write(initial)?;
        self.record.signing.get_mut(&id).unwrap().prepared = Some(response.clone());
        self.persist()
    }
    fn evaluator(&mut self, id: &str) -> Result<(IdentityEvaluator, Vec<u8>)> {
        let s = self
            .record
            .signing
            .get(id)
            .context("identity presign missing")?;
        if let Some((count, e, Some((reply, message)))) = self.cache.remove(id)
            && count == s.rounds.len()
            && s.rounds.last().and_then(|r| r.reply) == Some(reply)
        {
            return Ok((e, message));
        }
        let prepared = s
            .prepared
            .as_ref()
            .context("identity preparation missing")?;
        let mut e = IdentityEvaluator::start(
            &self.circuit,
            Zeroizing::new(self.record.user),
            Zeroizing::new(s.nonce.context("identity nonce retired")?),
            Zeroizing::new(self.record.key_salt),
            Zeroizing::new(s.seed.context("identity seed retired")?),
        )?;
        let first: Digest = serde_json::from_value(prepared["initial"].clone())?;
        let mut message = self.frames.read(&first)?;
        for round in &s.rounds {
            let bytes = e.advance(&message)?;
            let request = Request::decode(&round.request)?;
            let Command::IdentityFrame { frame, .. } = request.command else {
                anyhow::bail!("invalid identity round")
            };
            ensure!(
                hash(&[&bytes]) == frame && self.frames.read(&frame)? == bytes,
                "identity wallet replay changed"
            );
            message = self
                .frames
                .read(&round.reply.context("identity reply pending")?)?;
        }
        Ok((e, message))
    }
    pub fn next_request(&mut self, id: &Digest) -> Result<(Request, Vec<u8>)> {
        let id = hex::encode(id);
        let s = self.record.signing.get(&id).context("identity missing")?;
        ensure!(
            !s.aborted && s.presign.is_none() && s.signature.is_none() && s.rounds.len() <= 7,
            "identity presigning completed or aborted"
        );
        if let Some(round) = s.rounds.last().filter(|r| r.reply.is_none()) {
            let req = Request::decode(&round.request)?;
            let Command::IdentityFrame { frame, .. } = &req.command else {
                anyhow::bail!("invalid identity round")
            };
            self.persist()?;
            return Ok((req.clone(), self.frames.read(frame)?));
        }
        let step = s.rounds.len();
        ensure!(step < 7, "identity presigning needs finalization");
        let prepared = Request::decode(&s.prepare)?;
        let (mut e, message) = self.evaluator(&id)?;
        let bytes = {
            let _timing = Span::new(Phase::IdentityMpc);
            e.advance(&message)?
        };
        let frame = self.frames.write(&bytes)?;
        let req = self.signed(
            identity_frame_intent(&prepared.intent, step as u8)?,
            Command::IdentityFrame {
                identity: prepared.intent.operation,
                step: step as u8,
                frame,
            },
        )?;
        self.record
            .signing
            .get_mut(&id)
            .unwrap()
            .rounds
            .push(Round {
                request: req.encode()?,
                reply: None,
            });
        self.cache.insert(id, (step + 1, e, None));
        self.persist()?;
        Ok((req, bytes))
    }
    pub fn bind_reply(
        &mut self,
        id: &Digest,
        request: &Request,
        response: &Value,
        bytes: &[u8],
    ) -> Result<()> {
        let id = hex::encode(id);
        if response["aborted"] == true {
            let s = self
                .record
                .signing
                .get_mut(&id)
                .context("identity missing")?;
            s.aborted = true;
            s.nonce = None;
            s.seed = None;
            self.cache.remove(&id);
            self.persist()?;
            anyhow::bail!("identity MPC aborted; nonce retired");
        }
        let Command::IdentityFrame { step, .. } = &request.command else {
            anyhow::bail!("not identity round")
        };
        let reply: Digest = serde_json::from_value(response["reply"].clone())?;
        let round = self
            .record
            .signing
            .get(&id)
            .and_then(|s| s.rounds.get(*step as usize))
            .context("identity round not saved")?;
        let frame = HashedFrame::new(bytes);
        ensure!(
            frame.digest() == reply
                && round.request == request.encode()?
                && round.reply.is_none_or(|v| v == reply),
            "identity reply differs"
        );
        self.frames.store(&frame)?;
        self.record.signing.get_mut(&id).unwrap().rounds[*step as usize].reply = Some(reply);
        if let Some((count, _, message)) = self.cache.get_mut(&id)
            && *count == *step as usize + 1
        {
            *message = Some((reply, bytes.to_vec()));
        }
        self.persist()
    }
    pub fn finish_presign(&mut self, id: &Digest) -> Result<()> {
        let id = hex::encode(id);
        let s = self
            .record
            .signing
            .get(&id)
            .context("identity presign missing")?;
        if s.presign.is_some() || s.signature.is_some() {
            return self.persist();
        }
        ensure!(
            !s.aborted && s.rounds.len() == 7 && s.rounds.iter().all(|r| r.reply.is_some()),
            "identity rounds incomplete"
        );
        let (e, message) = self.evaluator(&id)?;
        let presign = {
            let _timing = Span::new(Phase::IdentityMpc);
            e.finish(&message)?
        };
        let s = self.record.signing.get_mut(&id).unwrap();
        s.presign = Some(presign.to_vec());
        s.nonce = None;
        s.seed = None;
        self.persist()
    }
    pub fn saved_signature(&self, digest: &Digest) -> Result<Option<Vec<u8>>> {
        self.persist()?;
        if let Some(ecdsa) = &self.record.ecdsa {
            return Ok(ecdsa.signature(digest));
        }
        for s in self.record.signing.values() {
            if let Some(sign) = &s.sign {
                let req = Request::decode(sign)?;
                if matches!(req.command,Command::IdentitySign{digest:d,..} if d==*digest) {
                    return Ok(s.signature.clone());
                }
            }
        }
        Ok(None)
    }
    pub fn sign_request(&mut self, digest: Digest) -> Result<Request> {
        for s in self.record.signing.values() {
            if let Some(sign) = &s.sign {
                let req = Request::decode(sign)?;
                if matches!(req.command,Command::IdentitySign{digest:d,..} if d==digest) {
                    self.persist()?;
                    return Ok(req);
                }
            }
        }
        let (id, s) = self
            .record
            .signing
            .iter()
            .find(|(_, s)| {
                !s.aborted && s.presign.is_some() && s.sign.is_none()
                    && Request::decode(&s.prepare).is_ok_and(|request| {
                        matches!(request.command, Command::IdentityPrepare { message: Some(message), .. } if message == digest)
                    })
            })
            .context("prepare an identity ticket bound to this exact message digest")?;
        let prepare = Request::decode(&s.prepare)?;
        let id = id.clone();
        let req = self.signed(
            identity_sign_intent(&prepare.intent, &digest)?,
            Command::IdentitySign {
                identity: prepare.intent.operation,
                digest,
            },
        )?;
        self.record.signing.get_mut(&id).unwrap().sign = Some(req.encode()?);
        self.persist()?;
        Ok(req)
    }
    pub fn complete_signature(&mut self, request: &Request, response: &Value) -> Result<Vec<u8>> {
        let Command::IdentitySign { identity, digest } = &request.command else {
            anyhow::bail!("not identity signing")
        };
        let id = hex::encode(identity);
        let s = self
            .record
            .signing
            .get(&id)
            .context("identity ticket missing")?;
        ensure!(
            s.sign.as_deref() == Some(request.encode()?.as_slice()),
            "identity signing request not frozen"
        );
        if let Some(sig) = &s.signature {
            self.persist()?;
            return Ok(sig.clone());
        }
        let presign = Zeroizing::new(<[u8; 64]>::try_from(
            s.presign
                .as_ref()
                .context("identity presign retired")?
                .as_slice(),
        )?);
        let partial: Digest = serde_json::from_value(response["partial"].clone())?;
        let r: Digest =
            serde_json::from_value(s.prepared.as_ref().context("identity missing")?["r"].clone())?;
        let signature = zark_spark_claim_mpc::identity::complete_signature(
            &presign,
            &r,
            digest,
            &partial,
            &self.public_key()?,
        )?;
        let s = self.record.signing.get_mut(&id).unwrap();
        s.signature = Some(signature.clone());
        if let Some(p) = &mut s.presign {
            p.zeroize();
        }
        s.presign = None;
        self.persist()?;
        Ok(signature)
    }
    pub(super) fn validate_signing(&self) -> Result<()> {
        use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
        for (id, s) in &self.record.signing {
            let prepare = Request::decode(&s.prepare)?;
            let Command::IdentityPrepare {
                commitment,
                nonce,
                message,
            } = &prepare.command
            else {
                anyhow::bail!("identity prepare encoding")
            };
            ensure!(
                *id == hex::encode(prepare.intent.operation)
                    && *commitment == self.key_commitment()?
                    && prepare.intent
                        == match message {
                            Some(message) => identity_message_intent(
                                &self.record.intent,
                                commitment,
                                nonce,
                                message
                            )?,
                            None => identity_intent(&self.record.intent, commitment, nonce)?,
                        }
                    && prepare.session[..]
                        == normalized_key(&self.record.session)?
                            .verifying_key()
                            .to_bytes()[..]
                    && s.rounds.len() <= 7
                    && s.nonce.is_some() == s.seed.is_some()
                    && s.nonce.is_some()
                        == (!s.aborted && s.presign.is_none() && s.signature.is_none()),
                "identity presign lifecycle"
            );
            if let Some(secret) = s.nonce {
                ensure!(
                    nonce_public(&secret)? == *nonce,
                    "identity private nonce changed"
                );
            }
            if let Some(p) = &s.prepared {
                ensure!(
                    p["circuit"] == serde_json::json!(self.circuit.digest()),
                    "identity circuit changed"
                );
                self.frames
                    .read(&serde_json::from_value(p["initial"].clone())?)?;
            }
            for (step, round) in s.rounds.iter().enumerate() {
                let req = Request::decode(&round.request)?;
                let Command::IdentityFrame {
                    identity,
                    step: actual,
                    frame,
                } = &req.command
                else {
                    anyhow::bail!("identity round encoding")
                };
                ensure!(
                    *identity == prepare.intent.operation
                        && usize::from(*actual) == step
                        && req.intent == identity_frame_intent(&prepare.intent, *actual)?
                        && req.session == prepare.session
                        && (round.reply.is_some() || step + 1 == s.rounds.len()),
                    "identity round context"
                );
                self.frames.read(frame)?;
                if let Some(reply) = round.reply {
                    self.frames.read(&reply)?;
                }
            }
            if let Some(p) = &s.presign {
                ensure!(
                    p.len() == 64
                        && !s.aborted
                        && s.rounds.len() == 7
                        && s.rounds.iter().all(|r| r.reply.is_some()),
                    "incomplete identity presign output"
                );
                scalar(&p[..32])?;
                scalar(&p[32..])?;
            }
            if let Some(encoded) = &s.sign {
                let req = Request::decode(encoded)?;
                let Command::IdentitySign { identity, digest } = &req.command else {
                    anyhow::bail!("identity online command")
                };
                ensure!(
                    *identity == prepare.intent.operation
                        && message.is_none_or(|message| message == *digest)
                        && req.intent == identity_sign_intent(&prepare.intent, digest)?
                        && req.session == prepare.session,
                    "identity online context"
                );
                if let Some(signature) = &s.signature {
                    ensure!(
                        s.presign.is_none() && !s.aborted && s.rounds.len() == 7,
                        "identity signature lifecycle"
                    );
                    VerifyingKey::from_sec1_bytes(&self.public_key()?)?
                        .verify_prehash(digest, &Signature::from_der(signature)?)?;
                }
            } else {
                ensure!(
                    s.signature.is_none(),
                    "identity signature has no frozen request"
                );
            }
        }
        Ok(())
    }
}
