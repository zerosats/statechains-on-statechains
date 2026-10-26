//! Terminal exit: the signer durably marks the coin exited, erases its share
//! and returns that share encrypted to the current owner's fresh key.
//!
//! The release consumes the ownership CAS revision like `Reserve`: it is
//! re-planned under the second lock, so a concurrent handover or release that
//! committed in between makes this one stale. The ciphertext exists only in the
//! committed response row and is served to exact retries from there; the coin
//! keeps only its hash. `Exited` is absorbing, so x_s is released at most once.
use super::{
    Command, Engine, Request,
    state::{Coin, Phase},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zark_protocol::{
    hash, point,
    spark_lineage::{Digest, Intent},
    spark_share_release::{self as release, Binding},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Released {
    /// Fixed by this record version, never selected by a client.
    purpose: String,
    intent: Intent,
    session: Digest,
    recipient: Vec<u8>,
    server: Vec<u8>,
    ciphertext: Digest,
}

impl Released {
    pub(super) fn server(&self) -> Result<[u8; 64]> {
        let server: [u8; 64] = self.server.as_slice().try_into()?;
        point(&server)?;
        Ok(server)
    }

    pub(super) fn validate(&self, coin: &Coin) -> Result<()> {
        ensure!(
            self.purpose == release::PURPOSE
                && self.intent.deployment == coin.deployment
                && self.intent.coin == coin.coin
                && self.intent.previous_state == coin.state
                && self.intent.recipient_claim
                    == release::recipient_claim(&coin.deployment, &coin.coin, &self.recipient)?
                && self.ciphertext != [0; 32],
            "Spark share release record changed"
        );
        self.intent.encode()?;
        k256::schnorr::VerifyingKey::from_bytes(&self.session)?;
        self.server()?;
        ensure!(
            coin.phase == Phase::Exited
                && coin.secret == [0; 32]
                && coin.owner.is_some()
                && coin.pending.is_none()
                && coin.native.is_none()
                && coin.single_user.is_none()
                && coin.identities.is_none()
                && coin.auth.is_none()
                && coin.ecdsa.is_none(),
            "Spark exited coin retains live signing state"
        );
        Ok(())
    }
}

pub(super) fn is_command(command: &Command) -> bool {
    matches!(command, Command::ShareRelease { .. })
}

/// Every other command, including a second release, is refused for an exited
/// coin before any other gate; only replay and `Head` still answer.
pub(super) fn terminal_gate(coin: &Coin) -> Result<()> {
    ensure!(
        coin.phase != Phase::Exited && coin.exit.is_none(),
        "Spark coin exited; only exact retries and heads are served"
    );
    Ok(())
}

impl Engine {
    pub(super) fn plan_share_release(&self, coin: &Coin, request: &Request) -> Result<()> {
        let Command::ShareRelease { recipient, owner } = &request.command else {
            anyhow::bail!("not a Spark share release");
        };
        ensure!(
            self.share_release,
            "Spark share release is not enabled for this deployment"
        );
        // Remaining live work must be cancelled or finished first. Identity,
        // auth and retired ECDSA-2P entry residue is out of scope at Accepted
        // and is dropped by the release; `ecdsa_2p::State::validate` already
        // refuses a live key, key generation or ticket outside `Allocated`.
        ensure!(
            coin.phase == Phase::Accepted
                && coin.pending.is_none()
                && coin.native.is_none()
                && coin.single_user.is_none()
                && coin.ecdsa.as_ref().is_none_or(|e| !e.ready())
                && coin.owner.is_some(),
            "Spark share release requires an idle accepted coin"
        );
        let intent = &request.intent;
        ensure!(
            intent.deployment == coin.deployment
                && intent.coin == coin.coin
                && intent.previous_state == coin.state
                && intent.recipient_claim
                    == release::recipient_claim(&coin.deployment, &coin.coin, recipient)?,
            "Spark share release intent differs from current state or recipient"
        );
        release::verify_owner(
            owner,
            &release::context(intent, request.session),
            recipient,
            &coin.server()?,
            &coin.capability,
        )
    }

    pub(super) fn apply_share_release(
        &self,
        mut coin: Coin,
        request: &Request,
    ) -> Result<(Coin, Value, bool)> {
        let Command::ShareRelease { recipient, .. } = &request.command else {
            anyhow::bail!("not a Spark share release");
        };
        let server = coin.server()?;
        let binding = Binding {
            deployment: coin.deployment,
            coin: coin.coin,
            intent: release::intent_digest(&request.intent)?,
            request: request.digest()?,
            session: request.session,
            recipient: recipient.as_slice().try_into()?,
            server,
            state: coin.state,
            capability: coin.capability,
            revision: request.intent.revision,
            committed_revision: request
                .intent
                .revision
                .checked_add(1)
                .context("Spark revision exhausted")?,
        };
        let secret = Zeroizing::new(coin.secret);
        let ciphertext = release::seal(&binding, &secret)?;
        coin.secret.zeroize();
        coin.phase = Phase::Exited;
        coin.identities = None;
        coin.auth = None;
        coin.ecdsa = None;
        coin.exit = Some(Released {
            purpose: release::PURPOSE.into(),
            intent: request.intent.clone(),
            session: request.session,
            recipient: recipient.clone(),
            server: server.to_vec(),
            ciphertext: hash(&[b"ZARK/spark/share-release/ciphertext/v1", &ciphertext]),
        });
        let response = json!({
            "ciphertext": ciphertext,
            "server": server.to_vec(),
            "state": coin.state,
            "capability": coin.capability,
        });
        Ok((coin, response, false))
    }
}
