//! Retained auth tickets hold public nonce points, frozen commitments and
//! issued responses. Only a live ticket retains its nonce secret.
use super::*;
use crate::engine::spark::Policy;
use k256::ProjectivePoint;
use zark_protocol::{point, scalar};

impl Tickets {
    pub(in crate::engine::spark) fn validate(&self, coin: &Coin, policy: &Policy) -> Result<()> {
        ensure!(
            policy.auth.is_some() && !self.tickets.is_empty() && self.key_commitment != [0; 32],
            "Spark auth policy or ticket coverage"
        );
        ensure!(
            identity_responses(coin, self.tickets.len()) <= IDENTITY_RESPONSE_BUDGET,
            "Spark joint identity response budget"
        );
        if let Some(identities) = &coin.identities {
            ensure!(
                identities.key_commitment() == self.key_commitment,
                "Spark auth and ECDSA identity keys differ"
            );
        }
        ensure!(
            self.tickets.values().filter(|t| t.live()).count() <= MAX_LIVE,
            "too many live Spark auth tickets"
        );
        let server = coin.server()?;
        let mut nonces = std::collections::BTreeSet::new();
        for (id, t) in &self.tickets {
            ensure!(
                *id == hex::encode(t.intent.operation)
                    && t.intent.coin == coin.coin
                    && t.intent.deployment == coin.deployment
                    && t.base.coin == coin.coin
                    && t.base.deployment == coin.deployment
                    && t.server == server.to_vec()
                    && t.commitment != [0; 32]
                    && t.intent
                        == auth_prepare_intent(
                            &t.base,
                            &self.key_commitment,
                            t.timestamp,
                            &t.commitment
                        )?,
                "Spark auth ticket shape"
            );
            k256::schnorr::VerifyingKey::from_bytes(&t.session)?;
            t.header(self.key_commitment)?.encode()?;
            let nonce = point(&t.nonce)?;
            ensure!(
                nonces.insert(t.nonce[..32].to_vec()),
                "Spark auth nonce reuse"
            );
            match (&t.secret, &t.challenge, &t.partial) {
                (Some(secret), None, None) => ensure!(
                    ProjectivePoint::GENERATOR * scalar(secret)? == nonce,
                    "Spark auth secret nonce differs"
                ),
                (None, Some(challenge), Some(partial)) => ensure!(
                    ProjectivePoint::GENERATOR * scalar(partial)?
                        == nonce + point(&t.server)? * scalar(challenge)?,
                    "Spark auth retained response changed"
                ),
                (None, None, None) => {}
                _ => anyhow::bail!("Spark auth ticket lifecycle"),
            }
        }
        Ok(())
    }
}
