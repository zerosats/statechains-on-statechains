//! Wallet-owned dual-refund recovery draft for the actual Spark lineage path.
//! Exact reopen/retry retains the same user key, payouts and blinding witnesses.
use super::PrivateBacking;
use crate::{
    blind_recovery::FrozenRecovery,
    wrapped_recovery::{RecoveryPlan, RecoveryTarget, ValidatedRecovery},
};
use anyhow::{Result, ensure};
use bitcoin::{
    Transaction,
    consensus::deserialize,
    secp256k1::{Parity, XOnlyPublicKey},
};
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use zark_protocol::{
    blind_signing::{Blinding, FundingKey},
    handoff::RecoverySchedule,
    point, random32, scalar,
    spark_lineage::{Intent, draft_state_commitment, server_commitment},
    spark_recovery::{
        NonceOpening, RecoveryAuthorization, RecoveryContext, RecoveryWitness, TargetOpening,
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SCHEMA: &str = "zark-spark-private-recovery";
const MAX_RECORD: usize = 32 * 1024;

/// Private wallet inputs only. `server` is a public point, never its secret.
pub struct RecoveryParameters {
    pub intent: Intent,
    pub session: [u8; 32],
    pub server: [u8; 64],
    pub server_salt: [u8; 32],
    pub user: [u8; 32],
    pub next_capability: [u8; 32],
    pub payout_secret: [u8; 32],
    pub fee: u64,
    pub owner_index: u32,
    pub schedule: RecoverySchedule,
}
impl Drop for RecoveryParameters {
    fn drop(&mut self) {
        self.server_salt.zeroize();
        self.user.zeroize();
        self.payout_secret.zeroize();
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct SavedNonce {
    alpha: [u8; 32],
    beta: [u8; 32],
    salt: [u8; 32],
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    #[zeroize(skip)]
    intent: Intent,
    session: [u8; 32],
    server: Vec<u8>,
    server_salt: [u8; 32],
    user: [u8; 32],
    next_capability: [u8; 32],
    payout_secret: [u8; 32],
    fee: u64,
    owner_index: u32,
    initial: u32,
    gap: u32,
    margin: u32,
    recovery_salt: [u8; 32],
    nonces: [SavedNonce; 2],
    server_nonces: Option<[Vec<u8>; 2]>,
    partials: Option<[[u8; 32]; 2]>,
}

/// This draft is not an ownership authority. Its proof must be composed into
/// the receiver/deposit role and accepted by the actual Zark signer engine.
pub struct PrivateRecovery {
    record: Record,
    key: FundingKey,
    plan: RecoveryPlan,
    witness: RecoveryWitness,
    frozen: FrozenRecovery,
    authorization: Option<RecoveryAuthorization>,
}

impl PrivateRecovery {
    pub fn prepare(backing: &PrivateBacking, p: RecoveryParameters) -> Result<Self> {
        let random = || {
            let b = Blinding::default();
            SavedNonce {
                alpha: b.alpha.to_bytes().into(),
                beta: b.beta.to_bytes().into(),
                salt: random32(),
            }
        };
        let record = Record {
            schema: SCHEMA.into(),
            version: 1,
            intent: p.intent.clone(),
            session: p.session,
            server: p.server.to_vec(),
            server_salt: p.server_salt,
            user: p.user,
            next_capability: p.next_capability,
            payout_secret: p.payout_secret,
            fee: p.fee,
            owner_index: p.owner_index,
            initial: p.schedule.initial,
            gap: p.schedule.gap,
            margin: p.schedule.margin,
            recovery_salt: random32(),
            nonces: [random(), random()],
            server_nonces: None,
            partials: None,
        };
        Self::reconstruct(backing, record)
    }

    fn reconstruct(backing: &PrivateBacking, record: Record) -> Result<Self> {
        ensure!(
            record.schema == SCHEMA && record.version == 1,
            "private Spark recovery schema"
        );
        record.intent.encode()?;
        ensure!(
            record.intent.deployment == backing.keys().scope().deployment
                && record.intent.coin == backing.keys().scope().coin,
            "private recovery backing domain"
        );
        ensure!(
            (1..=8).contains(&record.owner_index),
            "private Spark owner slot"
        );
        SigningKey::from_bytes(&record.payout_secret)?;
        k256::schnorr::VerifyingKey::from_bytes(&record.session)?;
        let server: [u8; 64] = record
            .server
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("private recovery server point length"))?;
        let user = Zeroizing::new(scalar(&record.user)?);
        let key = backing.owner_key(&server, *user)?;
        let schedule = RecoverySchedule {
            initial: record.initial,
            gap: record.gap,
            margin: record.margin,
        };
        let payout = SigningKey::from_bytes(&record.payout_secret)?;
        let plan = RecoveryPlan::from_native_backing(
            backing.validated_exit(),
            schedule,
            RecoveryTarget {
                revision: u64::from(record.owner_index),
                payout: XOnlyPublicKey::from_slice(&payout.verifying_key().to_bytes())?,
                fee_sats: record.fee,
            },
        )?;
        let transaction: Transaction = deserialize(&plan.unsigned_transactions()[0])?;
        let payout =
            XOnlyPublicKey::from_slice(&transaction.output[0].script_pubkey.as_bytes()[2..])?;
        let target = TargetOpening {
            salt: record.recovery_salt,
            payout: payout.public_key(Parity::Even).serialize_uncompressed()[1..].try_into()?,
            fee: record.fee,
            delay: plan.delay_blocks(),
            owner_index: record.owner_index,
            initial: record.initial,
            gap: record.gap,
            margin: record.margin,
        };
        let mut context = RecoveryContext {
            deployment: record.intent.deployment,
            coin: record.intent.coin,
            previous_state: record.intent.previous_state,
            operation: record.intent.operation,
            session: record.session,
            successor_state: [1; 32],
            revision: record.intent.revision,
        };
        let backing_commitment = backing.commitment(&context, &key)?;
        let server_share = server_commitment(
            &context.deployment,
            &context.coin,
            &server,
            &record.server_salt,
        )?;
        let policy = target.policy()?;
        context.successor_state = draft_state_commitment(
            &context,
            &backing_commitment,
            &record.next_capability,
            &server_share,
            &policy,
            &target,
        )?;
        let recovery = target.commitment(&context, &backing_commitment)?;
        let nonces = std::array::from_fn(|i| NonceOpening {
            alpha: record.nonces[i].alpha,
            beta: record.nonces[i].beta,
            salt: record.nonces[i].salt,
        });
        let frozen = FrozenRecovery {
            context: context.clone(),
            backing: backing_commitment,
            recovery,
            policy,
            server,
            nonce_commitments: [
                nonces[0].commitment(&context, &backing_commitment, &recovery, 0)?,
                nonces[1].commitment(&context, &backing_commitment, &recovery, 1)?,
            ],
        };
        let witness = RecoveryWitness {
            user: record.user,
            backing: backing.opening(),
            target,
            nonces,
        };
        let mut value = Self {
            record,
            key,
            plan,
            witness,
            frozen,
            authorization: None,
        };
        if let Some(nonces) = value.record.server_nonces.clone() {
            let nonces = [
                nonces[0].as_slice().try_into()?,
                nonces[1].as_slice().try_into()?,
            ];
            value.bind_nonces(nonces)?;
        }
        if let Some(partials) = value.record.partials {
            value.finish(partials)?;
        }
        Ok(value)
    }

    pub fn frozen(&self) -> &FrozenRecovery {
        &self.frozen
    }
    pub fn intent(&self) -> &Intent {
        &self.record.intent
    }
    pub fn plan(&self) -> &RecoveryPlan {
        &self.plan
    }
    pub fn witness(&self) -> &RecoveryWitness {
        &self.witness
    }
    pub fn server_salt(&self) -> &[u8; 32] {
        &self.record.server_salt
    }
    pub fn next_capability(&self) -> [u8; 32] {
        self.record.next_capability
    }

    pub fn bind_nonces(&mut self, nonces: [[u8; 64]; 2]) -> Result<&RecoveryAuthorization> {
        let saved = nonces.map(|n| n.to_vec());
        if let Some(existing) = &self.record.server_nonces {
            ensure!(*existing == saved, "private recovery nonce retry changed");
        }
        if self.authorization.is_none() {
            let copy = copy_witness(&self.witness);
            let (authorization, _) =
                copy.authorize(self.frozen.context.clone(), self.frozen.server, nonces)?;
            ensure!(
                authorization.backing == self.frozen.backing
                    && authorization.recovery == self.frozen.recovery
                    && authorization.policy == self.frozen.policy,
                "private recovery frozen commitments changed"
            );
            for i in 0..2 {
                ensure!(
                    authorization.branches[i].nonce_commitment == self.frozen.nonce_commitments[i],
                    "private recovery blinding commitment changed"
                );
                ensure!(
                    zark_protocol::spark_recovery::recovery_sighash(
                        &self.witness.backing.refunds[i],
                        self.key.xonly()?,
                        &self.witness.target
                    )? == self.plan.sighashes()[i],
                    "private recovery native sighash differs"
                );
            }
            self.record.server_nonces = Some(saved);
            self.authorization = Some(authorization);
        }
        Ok(self
            .authorization
            .as_ref()
            .expect("bound private recovery authorization"))
    }

    pub fn authorization(&self) -> Result<&RecoveryAuthorization> {
        self.authorization
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("private recovery signer nonces missing"))
    }

    /// Verify BOTH real signer contributions and both native recovery spends.
    /// The caller must persist this completed draft before acknowledging.
    pub fn finish(&mut self, partials: [[u8; 32]; 2]) -> Result<ValidatedRecovery> {
        if let Some(saved) = self.record.partials {
            ensure!(saved == partials, "private recovery partial retry changed");
        }
        let complete = self.verify_partials(partials)?;
        self.record.partials = Some(partials);
        Ok(complete)
    }

    pub fn completed(&self) -> Result<ValidatedRecovery> {
        self.verify_partials(
            self.record
                .partials
                .ok_or_else(|| anyhow::anyhow!("private recovery is not complete"))?,
        )
    }

    fn verify_partials(&self, partials: [[u8; 32]; 2]) -> Result<ValidatedRecovery> {
        let auth = self.authorization()?;
        let mut signatures = Vec::with_capacity(2);
        for (i, partial) in partials.iter().enumerate() {
            let opening = &self.witness.nonces[i];
            let blinding = Blinding {
                alpha: scalar(&opening.alpha)?,
                beta: scalar(&opening.beta)?,
            };
            let server = point(&auth.server)?;
            let nonce = point(&auth.branches[i].server_nonce)?;
            let session = blinding.bind(&self.key, server, nonce, self.plan.sighashes()[i])?;
            ensure!(
                session.challenge.to_bytes()[..] == auth.branches[i].challenge,
                "private recovery challenge changed"
            );
            let partial = Zeroizing::new(scalar(partial)?);
            signatures.push(
                blinding
                    .finish(&self.key, &session, server, nonce, *partial)?
                    .to_vec(),
            );
        }
        let complete = self.plan.finalize(
            signatures
                .try_into()
                .map_err(|_| anyhow::anyhow!("private recovery branch count"))?,
        )?;
        Ok(complete)
    }

    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.record)?);
        ensure!(bytes.len() <= MAX_RECORD, "private recovery record size");
        Ok(bytes)
    }
    pub fn decode_private(backing: &PrivateBacking, bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RECORD,
            "private recovery record size"
        );
        let record: Record = serde_json::from_slice(bytes)?;
        let value = Self::reconstruct(backing, record)?;
        ensure!(
            value.encode_private()?.as_slice() == bytes,
            "noncanonical private recovery record"
        );
        Ok(value)
    }
}

fn copy_witness(w: &RecoveryWitness) -> RecoveryWitness {
    use zark_protocol::spark_recovery::{BackingOpening, RefundOpening};
    RecoveryWitness {
        user: w.user,
        backing: BackingOpening {
            salt: w.backing.salt,
            refunds: std::array::from_fn(|i| RefundOpening {
                txid: w.backing.refunds[i].txid,
                amount: w.backing.refunds[i].amount,
            }),
        },
        target: TargetOpening {
            salt: w.target.salt,
            payout: w.target.payout,
            fee: w.target.fee,
            delay: w.target.delay,
            owner_index: w.target.owner_index,
            initial: w.target.initial,
            gap: w.target.gap,
            margin: w.target.margin,
        },
        nonces: std::array::from_fn(|i| NonceOpening {
            alpha: w.nonces[i].alpha,
            beta: w.nonces[i].beta,
            salt: w.nonces[i].salt,
        }),
    }
}
