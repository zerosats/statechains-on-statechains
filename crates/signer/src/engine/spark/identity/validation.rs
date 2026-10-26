//! Retained identity transcripts contain public nonce points and opaque frame
//! hashes. Completed or aborted sessions retain no nonce or key-share copy.
use super::*;
impl Sessions {
    pub(in crate::engine::spark) fn validate(&self, coin: &Coin, policy: &Policy) -> Result<()> {
        ensure!(
            policy.identity == Some(self.circuit)
                && !self.sessions.is_empty()
                && self.sessions.len() <= 8,
            "identity circuit/session coverage"
        );
        ensure!(
            self.sessions
                .values()
                .filter(|w| w.secrets.is_some())
                .count()
                <= 1,
            "multiple active identity sessions"
        );
        for (id, w) in &self.sessions {
            ensure!(
                *id == hex::encode(w.intent.operation)
                    && w.commitment == self.commitment
                    && w.intent.coin == coin.coin
                    && w.intent.deployment == coin.deployment
                    && w.initial != [0; 32]
                    && w.rounds.len() <= 7
                    && w.rounds.iter().all(|(a, b)| *a != [0; 32] && *b != [0; 32]),
                "identity transcript shape"
            );
            w.intent.encode()?;
            zark_protocol::point(&w.server)?;
            k256::schnorr::VerifyingKey::from_bytes(&w.session)?;
            ensure!(
                w.wallet_nonce.len() == 33 && w.server_nonce.len() == 33,
                "identity nonce encoding"
            );
            k256::PublicKey::from_sec1_bytes(&w.wallet_nonce)?;
            k256::PublicKey::from_sec1_bytes(&w.server_nonce)?;
            ensure!(
                scalar(&w.r)? != k256::Scalar::ZERO
                    && w.secrets.is_some() == (!w.aborted && w.rounds.len() < 7),
                "identity nonce lifecycle"
            );
            // Ready masks still encode the current server share. They must stay
            // in the same ownership lock until consumed or explicitly retired.
            if w.masks.is_some() {
                let base = scope(coin, &w.session)?;
                ensure!(
                    coin.server()?.as_slice() == w.server
                        && match w.message {
                            Some(message) => identity_message_intent(
                                base,
                                &w.commitment,
                                &w.wallet_nonce,
                                &message
                            )?,
                            None => identity_intent(base, &w.commitment, &w.wallet_nonce)?,
                        } == w.intent,
                    "identity ownership scope changed"
                );
            }
            if let Some(secrets) = &w.secrets {
                ensure!(
                    nonce_public(&secrets.nonce)? == w.server_nonce
                        && nonce_r(&secrets.nonce, &w.wallet_nonce)? == w.r
                        && secrets.seed != [0; 32],
                    "identity secret nonce differs"
                );
            }
            ensure!(
                w.digest.is_some() == w.partial.is_some()
                    && w.masks.is_some() == (!w.aborted && w.digest.is_none()),
                "identity presign mask lifecycle"
            );
            if let Some(m) = &w.masks {
                for value in m {
                    ensure!(scalar(value)? != k256::Scalar::ZERO, "zero identity mask");
                }
            }
            if w.digest.is_some() {
                ensure!(
                    w.message.is_none_or(|message| Some(message) == w.digest),
                    "identity signing message changed"
                );
                ensure!(
                    !w.aborted && w.rounds.len() == 7 && w.secrets.is_none(),
                    "identity online signature without completed presign"
                );
            }
        }
        Ok(())
    }
    pub(in crate::engine::spark) fn validate_frames(&self, engine: &Engine) -> Result<()> {
        let files = engine.identity_files()?;
        for w in self.sessions.values() {
            files.read(&w.initial)?;
            for (step, (input, output)) in w.rounds.iter().enumerate() {
                files.read(input)?;
                files.read(output)?;
                let request = Request {
                    intent: identity_frame_intent(&w.intent, step as u8)?,
                    session: w.session,
                    command: Command::IdentityFrame {
                        identity: w.intent.operation,
                        step: step as u8,
                        frame: *input,
                    },
                    signature: Vec::new(),
                };
                files.check_slot(&slot(&request), &request.digest()?)?;
            }
        }
        Ok(())
    }
}
