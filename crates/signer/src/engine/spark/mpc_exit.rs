//! Upstream Spark `start_transfer_mpc` exit inside an issued two-role native
//! exit. Ownership is already permanently locked by `NativeExitIssue`, so a
//! previous owner cannot reach these steps after a handover, and a current
//! owner cannot hand over after reaching them.
//!
//! `NativeMpcContribution` seals the signer's position-two sub-shares to the
//! pinned operator identities. `NativeTransferAuthPrepare` freezes one wallet
//! commitment with a fresh hedged nonce; `NativeTransferAuthIssue` releases the
//! single blinded BIP-340 response only for a pinned proof that the challenge
//! is over the exact Spark authorization payload of the frozen plan, with the
//! UUIDs and commitment vector of this contribution. One ticket per exit: the
//! response journal serves exact retries and rejects any changed request.
//! Prepare and issue are auxiliary to the ownership CAS revision.
#[cfg(test)]
mod tests;
use super::{
    Command, Engine, ProofRole, ProofSpec, Request, blind_issuance, native::Workflow, state::Coin,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zark_protocol::{
    hash, point, point_bytes, random32, reduce, spark_auth,
    spark_lineage::Digest,
    spark_mpc_exit::{MpcContribution, TransferAuthHeader, TransferAuthStatement},
    spark_native_vss::Cluster,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MpcExit {
    contribution: MpcContribution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ticket: Option<Ticket>,
}

/// Live: secret only. Issued: challenge and partial, never the secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    key_commitment: Digest,
    commitment: Digest,
    nonce: Vec<u8>,
    secret: Option<Digest>,
    challenge: Option<Digest>,
    partial: Option<Digest>,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.zeroize();
        }
    }
}

pub(super) fn is_command(command: &Command) -> bool {
    matches!(
        command,
        Command::NativeMpcContribution { .. }
            | Command::NativeTransferAuthPrepare { .. }
            | Command::NativeTransferAuthIssue { .. }
    )
}
pub(super) fn auxiliary(command: &Command) -> bool {
    matches!(
        command,
        Command::NativeTransferAuthPrepare { .. } | Command::NativeTransferAuthIssue { .. }
    )
}

impl MpcExit {
    /// The proof statement for the issued ticket; its digest is the packet a
    /// native completion must name for this exit.
    pub(super) fn issued_statement(
        &self,
        workflow: &Workflow,
        coin: &Coin,
    ) -> Result<Option<TransferAuthStatement>> {
        let Some(t) = &self.ticket else {
            return Ok(None);
        };
        let Some(challenge) = t.challenge else {
            return Ok(None);
        };
        Ok(Some(statement(self, t, workflow, coin, challenge)?))
    }
    pub(super) fn validate(
        &self,
        workflow: &Workflow,
        coin: &Coin,
        cluster: &Cluster,
    ) -> Result<()> {
        self.contribution
            .validate(cluster, &-point(&coin.server()?)?)?;
        if let Some(t) = &self.ticket {
            ensure!(
                t.commitment != [0; 32] && t.key_commitment != [0; 32],
                "Spark transfer auth ticket binding"
            );
            ensure!(
                t.challenge.is_some() == t.partial.is_some()
                    && t.secret.is_some() != t.challenge.is_some(),
                "Spark transfer auth ticket lifecycle"
            );
            if let Some(secret) = t.secret {
                ensure!(
                    point_bytes(
                        k256::ProjectivePoint::GENERATOR * zark_protocol::scalar(&secret)?
                    )?[..]
                        == t.nonce,
                    "Spark transfer auth nonce changed"
                );
            }
            if let (Some(challenge), Some(partial)) = (t.challenge, t.partial) {
                let s = statement(self, t, workflow, coin, challenge)?;
                ensure!(
                    k256::ProjectivePoint::GENERATOR * zark_protocol::scalar(&partial)?
                        == point(&s.nonce)?
                            + point(&s.header.server)? * zark_protocol::scalar(&challenge)?,
                    "Spark transfer auth retained response changed"
                );
            }
            if let Some(identities) = &coin.identities {
                ensure!(
                    identities.key_commitment() == t.key_commitment,
                    "Spark transfer auth names another identity key"
                );
            }
        }
        Ok(())
    }
}

fn statement(
    mpc: &MpcExit,
    t: &Ticket,
    workflow: &Workflow,
    coin: &Coin,
    challenge: Digest,
) -> Result<TransferAuthStatement> {
    let value = TransferAuthStatement {
        header: TransferAuthHeader {
            scope: spark_auth::scope_digest(&workflow.intent)?,
            key_commitment: t.key_commitment,
            server: coin.server()?,
            plan: workflow.plan(),
            transfer_id: mpc.contribution.transfer_id,
            leaf_id: mpc.contribution.leaf_id,
            signer_proofs: mpc.contribution.proof_points()?,
        },
        commitment: t.commitment,
        nonce: t.nonce.as_slice().try_into()?,
        challenge,
    };
    value.encode()?;
    Ok(value)
}

impl Engine {
    /// Called from native planning after the frozen intent and session match.
    pub(super) fn plan_mpc_exit(
        &self,
        coin: &Coin,
        workflow: &Workflow,
        request: &Request,
    ) -> Result<Option<ProofSpec>> {
        ensure!(
            self.native_verifier
                .as_ref()
                .is_some_and(|v| !v.is_ordinary()),
            "Spark MPC exit requires the two-role native registry"
        );
        plan(
            coin,
            workflow,
            request,
            self.policy.native_cluster.as_ref(),
            self.transfer_auth_verifier.is_some(),
        )
    }
    pub(super) fn apply_mpc_exit(&self, coin: &mut Coin, request: &Request) -> Result<Value> {
        apply(
            coin,
            request,
            self.policy
                .native_cluster
                .as_ref()
                .context("native MPC cluster missing")?,
        )
    }
}

fn plan(
    coin: &Coin,
    workflow: &Workflow,
    request: &Request,
    cluster: Option<&Cluster>,
    signing: bool,
) -> Result<Option<ProofSpec>> {
    ensure!(
        workflow.statement.is_some() && !workflow.completed(),
        "Spark MPC exit requires an issued, unfinished native exit"
    );
    match &request.command {
        Command::NativeMpcContribution {
            transfer_id,
            leaf_id,
        } => {
            ensure!(
                workflow.contribution.is_none()
                    && workflow.tweaks.is_none()
                    && workflow.mpc.is_none(),
                "native signing material already released"
            );
            let cluster = cluster.context("native MPC cluster is not configured")?;
            ensure!(
                cluster.digest()? == workflow.cluster(),
                "native MPC cluster changed"
            );
            ensure!(
                *transfer_id != [0; 16] && *leaf_id != [0; 16],
                "Spark MPC transfer or leaf missing"
            );
            Ok(None)
        }
        Command::NativeTransferAuthPrepare {
            key_commitment,
            commitment,
        } => {
            ensure!(signing, "Spark transfer auth signing disabled");
            let mpc = workflow
                .mpc
                .as_ref()
                .context("Spark MPC contribution missing")?;
            ensure!(mpc.ticket.is_none(), "Spark transfer auth already prepared");
            ensure!(
                *commitment != [0; 32] && *key_commitment != [0; 32],
                "zero Spark transfer auth binding"
            );
            // The leaf ECDSA signature and this response must name one wallet share.
            if let Some(identities) = &coin.identities {
                ensure!(
                    identities.key_commitment() == *key_commitment,
                    "Spark transfer auth names another identity key"
                );
            }
            Ok(None)
        }
        Command::NativeTransferAuthIssue { challenge, .. } => {
            ensure!(signing, "Spark transfer auth signing disabled");
            let mpc = workflow
                .mpc
                .as_ref()
                .context("Spark MPC contribution missing")?;
            let t = mpc
                .ticket
                .as_ref()
                .context("Spark transfer auth ticket missing")?;
            ensure!(
                t.secret.is_some() && t.challenge.is_none(),
                "Spark transfer auth ticket already issued"
            );
            let value = statement(mpc, t, workflow, coin, *challenge)?;
            Ok(Some(ProofSpec {
                role: ProofRole::TransferAuth,
                statement: value.encode()?,
            }))
        }
        _ => anyhow::bail!("not a Spark MPC exit command"),
    }
}

/// Only after `plan` and, for issue, proof verification, both repeated under
/// the relock. The enclosing commit saves every response before release.
fn apply(coin: &mut Coin, request: &Request, cluster: &Cluster) -> Result<Value> {
    let secret = Zeroizing::new(coin.secret);
    let server = coin.server()?;
    let workflow = coin.native.as_mut().context("native workflow missing")?;
    match &request.command {
        Command::NativeMpcContribution {
            transfer_id,
            leaf_id,
        } => {
            let constant: Zeroizing<Digest> =
                Zeroizing::new((-zark_protocol::scalar(&secret[..])?).to_bytes().into());
            let contribution =
                MpcContribution::prepare(&constant, *transfer_id, *leaf_id, cluster)?;
            contribution.validate(cluster, &-point(&server)?)?;
            workflow.mpc = Some(MpcExit {
                contribution: contribution.clone(),
                ticket: None,
            });
            Ok(json!({"contribution":contribution,"native_pending":true}))
        }
        Command::NativeTransferAuthPrepare {
            key_commitment,
            commitment,
        } => {
            let mpc = workflow
                .mpc
                .as_mut()
                .context("Spark MPC contribution missing")?;
            // Hedged: a weak RNG alone cannot repeat a nonce across exits.
            let nonce = Zeroizing::new(reduce(hash(&[
                b"ZARK/spark/mpc-exit/transfer-auth-nonce/v1",
                &*secret,
                &request.intent.operation,
                commitment,
                &random32(),
            ])));
            ensure!(
                !bool::from(nonce.is_zero()),
                "zero Spark transfer auth nonce"
            );
            let point = point_bytes(k256::ProjectivePoint::GENERATOR * *nonce)?;
            mpc.ticket = Some(Ticket {
                key_commitment: *key_commitment,
                commitment: *commitment,
                nonce: point.to_vec(),
                secret: Some(nonce.to_bytes().into()),
                challenge: None,
                partial: None,
            });
            Ok(json!({"nonce":point.to_vec()}))
        }
        Command::NativeTransferAuthIssue { challenge, .. } => {
            let t = workflow
                .mpc
                .as_mut()
                .and_then(|m| m.ticket.as_mut())
                .context("Spark transfer auth ticket missing")?;
            let (nonce_point, commitment) = (t.nonce.clone(), t.commitment);
            // issue() validates everything before consuming the nonce.
            let [partial] = blind_issuance::issue(
                &secret,
                [&mut t.secret],
                [blind_issuance::FrozenResponse {
                    nonce_point: &nonce_point,
                    nonce_commitment: &commitment,
                    blinded_challenge: challenge,
                }],
            )?;
            t.challenge = Some(*challenge);
            t.partial = Some(partial);
            Ok(json!({"partial":partial}))
        }
        _ => anyhow::bail!("not a Spark MPC exit command"),
    }
}
