//! Isolated Spark request domain; existing Bitcoin wire bytes remain unchanged.
use crate::{
    hash, random32,
    spark_lineage::{Digest, Intent},
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
mod head;
pub use head::{Head, HeadAuthorization, HeadPhase, SignedHead};
pub mod ecdsa_2p;
mod native_receipt;
pub mod opaque_frames;
pub use native_receipt::{NativeAttestation, NativeCompletion, NativeExitReceipt};

pub const MAX_WIRE: usize = 160 * 1024;

pub fn native_tweak_frame_intent(base: &Intent, operator: &str, step: u8) -> Result<Intent> {
    ensure!(
        operator.len() == 64 && hex::decode(operator)?.len() == 32 && step < 7,
        "native tweak frame scope"
    );
    let mut value = base.clone();
    value.operation = hash(&[
        b"ZARK/spark/native-tweak/frame/v1",
        &base.encode()?,
        operator.as_bytes(),
        &[step],
    ]);
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predecessor {
    Origin,
    Transfer,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAuthorization {
    pub public_key: Digest,
    pub signature: Vec<u8>,
}

impl OwnerAuthorization {
    pub fn sign_receive(
        context: &crate::spark_bootstrap::BootstrapContext,
        backing: &Digest,
        capability: &Digest,
        plan: &Digest,
        cluster: &Digest,
        commitments: &[Digest; 2],
        key: &SigningKey,
    ) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes().into();
        ensure!(
            public_key != context.session,
            "receive owner/session separation"
        );
        Ok(Self {
            public_key,
            signature: key
                .sign_raw(
                    &crate::spark_receive::owner_message(
                        context,
                        backing,
                        capability,
                        plan,
                        cluster,
                        commitments,
                    )?,
                    &random32(),
                )?
                .to_bytes()
                .to_vec(),
        })
    }
    pub fn sign_single_user(
        context: &crate::spark_native::ExitContext,
        plan: &Digest,
        commitment: &Digest,
        key: &SigningKey,
    ) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes().into();
        ensure!(
            public_key != context.session,
            "single-USER owner/session separation"
        );
        Ok(Self {
            public_key,
            signature: key
                .sign_raw(
                    &crate::spark_single_user::owner_message(context, plan, commitment)?,
                    &random32(),
                )?
                .to_bytes()
                .to_vec(),
        })
    }
    pub fn sign_bootstrap(
        context: &crate::spark_bootstrap::BootstrapContext,
        backing: &Digest,
        capability: &Digest,
        plan: &Digest,
        server: &[u8; 64],
        commitments: &[Digest; 3],
        key: &SigningKey,
    ) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes().into();
        ensure!(
            public_key != context.session,
            "bootstrap owner and session keys must differ"
        );
        Ok(Self {
            public_key,
            signature: key
                .sign_raw(
                    &context.owner_message(backing, capability, plan, server, commitments)?,
                    &random32(),
                )?
                .to_bytes()
                .to_vec(),
        })
    }

    pub fn sign_native(
        context: &crate::spark_native::ExitContext,
        plan: &Digest,
        commitments: &[Digest; 2],
        key: &SigningKey,
    ) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes().into();
        ensure!(
            public_key != context.session,
            "native owner and session keys must differ"
        );
        Ok(Self {
            public_key,
            signature: key
                .sign_raw(&context.owner_message(plan, commitments)?, &random32())?
                .to_bytes()
                .to_vec(),
        })
    }

    pub fn sign(intent: &Intent, session: &Digest, key: &SigningKey) -> Result<Self> {
        let public_key = key.verifying_key().to_bytes().into();
        ensure!(
            public_key != *session,
            "Spark owner and session keys must differ"
        );
        Ok(Self {
            public_key,
            signature: key
                .sign_raw(&intent.owner_reservation_message(session)?, &random32())?
                .to_bytes()
                .to_vec(),
        })
    }

    pub fn verify(&self, intent: &Intent, session: &Digest, capability: &Digest) -> Result<()> {
        ensure!(
            self.public_key != *session,
            "Spark owner and session keys must differ"
        );
        intent.verify_owner_reservation(
            session,
            capability,
            &self.public_key,
            &self.signature.as_slice().try_into()?,
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Allocate {},
    FreezeOrigin {
        backing: Digest,
        capability: Digest,
    },
    Reserve {
        owner: OwnerAuthorization,
    },
    Handover {
        predecessor: Predecessor,
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    ProposeRecipient {
        token: Digest,
        delta: Digest,
        delta_salt: Digest,
        next_capability: Digest,
    },
    Prepare {
        successor_state: Digest,
        recovery: Digest,
        nonce_commitments: [Digest; 2],
    },
    Issue {
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    Acknowledge {
        state: Digest,
        certificate: Digest,
    },
    Cancel {},
    /// Legacy generic exit is closed; native exit uses the typed proof commands.
    Exit {},
    /// Every query needs a fresh random challenge; responses are never cached.
    Head {
        challenge: Digest,
        owner: Option<HeadAuthorization>,
    },
    NativeExitPrepare {
        plan: Digest,
        nonce_commitments: [Digest; 2],
        owner: OwnerAuthorization,
    },
    NativeExitIssue {
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    /// Safe only before either native response has been released.
    NativeExitCancel {},
    /// Encrypted role-two VSS output after the real native proof was accepted.
    NativeExitContribution {},
    NativeExitComplete {
        receipt: NativeExitReceipt,
    },
    /// A deployed external observer must admit this exact settled native
    /// operation. This request alone is never evidence of Spark settlement.
    NativeExitObservedComplete {
        completion: NativeCompletion,
        evidence: Digest,
    },
    NativeBootstrapPrepare {
        backing: Digest,
        capability: Digest,
        plan: Digest,
        nonce_commitments: [Digest; 3],
        owner: OwnerAuthorization,
    },
    NativeBootstrapIssue {
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    /// Retires this allocation's native preparation before any response pair.
    NativeBootstrapCancel {},
    SingleUserPrepare {
        plan: Digest,
        nonce_commitment: Digest,
        owner: OwnerAuthorization,
    },
    SingleUserIssue {
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    /// Cancelling is allowed only before the blind response is issued.
    SingleUserCancel {},
    ReceivePrepare {
        backing: Digest,
        capability: Digest,
        plan: Digest,
        nonce_commitments: [Digest; 2],
        owner: OwnerAuthorization,
    },
    /// The large opaque MPC frame travels separately, bound by this signed hash.
    ReceiveFrame {
        operator: String,
        step: u8,
        frame: Digest,
    },
    ReceiveIssue {
        statement: Vec<u8>,
        proof: Vec<u8>,
    },
    /// Wallet-only output; the joint public key and final ECDSA signature must
    /// never be sent to the blind authority through these commands.
    IdentityPrepare {
        commitment: Digest,
        nonce: Vec<u8>,
        /// Frozen before any presigning output is released. Omission decodes
        /// historical records only; new unbound tickets must be rejected.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<Digest>,
    },
    IdentityFrame {
        identity: Digest,
        step: u8,
        frame: Digest,
    },
    IdentityDecrypt {
        ephemeral: Vec<u8>,
    },
    IdentitySign {
        identity: Digest,
        digest: Digest,
    },
    /// Only bounded protobuf shape crosses the blind boundary. Final native
    /// templates and ciphertexts are wallet-only MPC input and output.
    NativeTweakPrepare {
        plaintext_bytes: u16,
        scalar_offset: u16,
    },
    NativeTweakFrame {
        operator: String,
        step: u8,
        frame: Digest,
    },
    NativeTweakSeal {
        packet: Digest,
    },
    /// Freezes one blinded Spark authentication response before its nonce
    /// exists. Only the commitment and public challenge timestamp cross.
    AuthPrepare {
        key_commitment: Digest,
        timestamp: u64,
        commitment: Digest,
    },
    /// Releases the single response for a proof over the frozen commitment.
    AuthIssue {
        ticket: Digest,
        challenge: Digest,
        proof: Vec<u8>,
    },
    /// Upstream Spark MPC position-two sub-shares after an issued two-role
    /// native exit. The UUIDs are later proven to be the frozen plan's.
    NativeMpcContribution {
        transfer_id: [u8; 16],
        leaf_id: [u8; 16],
    },
    /// Freezes the one blinded `start_transfer_mpc` authorization response.
    NativeTransferAuthPrepare {
        key_commitment: Digest,
        commitment: Digest,
    },
    /// Releases it for a proof over the exact Spark authorization payload.
    NativeTransferAuthIssue {
        challenge: Digest,
        proof: Vec<u8>,
    },
    /// cb-mpc ECDSA-2P key generation for a fresh allocation. The signer's
    /// share replaces its allocation secret before anything depends on it.
    EcdsaKeygen {
        frame: ecdsa_2p::Frame,
    },
    EcdsaKeygenFinish {
        keygen: Digest,
        frame: ecdsa_2p::Frame,
    },
    /// Opens a single-use blind ECDSA-2P ticket. The signer never receives the
    /// digest; `message` decodes historical records only and must be absent.
    EcdsaSign {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<Digest>,
        nonce: Digest,
        frame: ecdsa_2p::Frame,
    },
    /// Carries the wallet's message 3 with m'' = m + r·tau.
    EcdsaSignFinish {
        ticket: Digest,
        frame: ecdsa_2p::Frame,
    },
    /// Additive receive tweak u = b - x_w. The signer returns one sealed
    /// Feldman share of u - x_s per operator; the wallet completes the packages.
    ReceiveTweak {
        tweak: Digest,
    },
    /// Terminal exit: marks the coin exited, then returns its server share
    /// encrypted to `recipient`, a fresh compressed wallet key.
    ShareRelease {
        recipient: Vec<u8>,
        owner: OwnerAuthorization,
    },
}

impl Command {
    pub fn purpose(&self) -> u8 {
        match self {
            Self::Allocate { .. } => 1,
            Self::FreezeOrigin { .. } => 2,
            Self::Reserve { .. } => 3,
            Self::Handover { .. } => 4,
            Self::ProposeRecipient { .. } => 5,
            Self::Prepare { .. } => 6,
            Self::Issue { .. } => 7,
            Self::Acknowledge { .. } => 8,
            Self::Cancel { .. } => 9,
            Self::Exit { .. } => 10,
            Self::Head { .. } => 11,
            Self::NativeExitPrepare { .. } => 12,
            Self::NativeExitIssue { .. } => 13,
            Self::NativeExitCancel { .. } => 14,
            Self::NativeExitContribution { .. } => 15,
            Self::NativeExitComplete { .. } => 16,
            Self::NativeBootstrapPrepare { .. } => 17,
            Self::NativeBootstrapIssue { .. } => 18,
            Self::NativeBootstrapCancel { .. } => 19,
            Self::SingleUserPrepare { .. } => 20,
            Self::SingleUserIssue { .. } => 21,
            Self::SingleUserCancel { .. } => 22,
            Self::ReceivePrepare { .. } => 23,
            Self::ReceiveFrame { .. } => 24,
            Self::ReceiveIssue { .. } => 25,
            Self::IdentityPrepare { .. } => 26,
            Self::IdentityFrame { .. } => 27,
            Self::IdentityDecrypt { .. } => 28,
            Self::IdentitySign { .. } => 29,
            Self::NativeExitObservedComplete { .. } => 30,
            Self::NativeTweakPrepare { .. } => 31,
            Self::NativeTweakFrame { .. } => 32,
            Self::NativeTweakSeal { .. } => 33,
            Self::AuthPrepare { .. } => 34,
            Self::AuthIssue { .. } => 35,
            Self::NativeMpcContribution { .. } => 36,
            Self::NativeTransferAuthPrepare { .. } => 37,
            Self::NativeTransferAuthIssue { .. } => 38,
            Self::EcdsaKeygen { .. } => 39,
            Self::EcdsaKeygenFinish { .. } => 40,
            Self::EcdsaSign { .. } => 41,
            Self::EcdsaSignFinish { .. } => 42,
            Self::ReceiveTweak { .. } => 43,
            Self::ShareRelease { .. } => 44,
        }
    }
    pub fn proof(&self) -> Option<&[u8]> {
        match self {
            Self::Handover { proof, .. }
            | Self::Issue { proof, .. }
            | Self::NativeExitIssue { proof, .. }
            | Self::NativeBootstrapIssue { proof, .. }
            | Self::SingleUserIssue { proof, .. }
            | Self::ReceiveIssue { proof, .. }
            | Self::AuthIssue { proof, .. }
            | Self::NativeTransferAuthIssue { proof, .. } => Some(proof),
            _ => None,
        }
    }
}

/// Auxiliary identity work is checkpointed without advancing the leaf's
/// ownership CAS revision. Each message has its own domain-separated operation.
pub fn identity_intent(base: &Intent, digest: &Digest, nonce: &[u8]) -> Result<Intent> {
    let mut intent = base.clone();
    intent.operation = hash(&[
        b"ZARK/spark/identity/prepare/v1",
        &base.encode()?,
        digest,
        nonce,
    ]);
    Ok(intent)
}
/// Separate from legacy preparation: a ready ticket must already name its only
/// signing message, including after a database/checkpoint rollback.
pub fn identity_message_intent(
    base: &Intent,
    commitment: &Digest,
    nonce: &[u8],
    message: &Digest,
) -> Result<Intent> {
    let mut intent = base.clone();
    intent.operation = hash(&[
        b"ZARK/spark/identity/prepare-message/v2",
        &base.encode()?,
        commitment,
        nonce,
        message,
    ]);
    Ok(intent)
}
pub fn identity_frame_intent(prepared: &Intent, step: u8) -> Result<Intent> {
    ensure!(step < 7, "identity round bound");
    let mut intent = prepared.clone();
    intent.operation = hash(&[
        b"ZARK/spark/identity/frame/v1",
        &prepared.encode()?,
        &[step],
    ]);
    Ok(intent)
}
pub fn identity_decrypt_intent(base: &Intent, ephemeral: &[u8]) -> Result<Intent> {
    let mut intent = base.clone();
    intent.operation = hash(&[
        b"ZARK/spark/identity/decrypt/v1",
        &base.encode()?,
        ephemeral,
    ]);
    Ok(intent)
}
pub fn identity_sign_intent(prepared: &Intent, digest: &Digest) -> Result<Intent> {
    let mut intent = prepared.clone();
    intent.operation = hash(&[b"ZARK/spark/identity/sign/v1", &prepared.encode()?, digest]);
    Ok(intent)
}
/// Auth tickets share the identity scope but never the ECDSA ticket domain.
pub fn auth_prepare_intent(
    base: &Intent,
    key_commitment: &Digest,
    timestamp: u64,
    commitment: &Digest,
) -> Result<Intent> {
    let mut intent = base.clone();
    intent.operation = hash(&[
        b"ZARK/spark/auth/prepare/v1",
        &base.encode()?,
        key_commitment,
        &timestamp.to_le_bytes(),
        commitment,
    ]);
    Ok(intent)
}
pub fn auth_issue_intent(prepared: &Intent, challenge: &Digest) -> Result<Intent> {
    let mut intent = prepared.clone();
    intent.operation = hash(&[b"ZARK/spark/auth/issue/v1", &prepared.encode()?, challenge]);
    Ok(intent)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub intent: Intent,
    pub session: Digest,
    pub command: Command,
    pub signature: Vec<u8>,
}

impl Request {
    pub fn sign(intent: Intent, command: Command, key: &SigningKey) -> Result<Self> {
        let mut value = Self {
            intent,
            session: key.verifying_key().to_bytes().into(),
            command,
            signature: Vec::new(),
        };
        value.signature = key
            .sign_raw(&value.digest()?, &random32())?
            .to_bytes()
            .to_vec();
        Ok(value)
    }

    pub fn digest(&self) -> Result<Digest> {
        let command = Zeroizing::new(serde_json::to_vec(&self.command)?);
        ensure!(command.len() < MAX_WIRE, "Spark request size");
        VerifyingKey::from_bytes(&self.session)?;
        Ok(hash(&[
            b"ZARK/spark/signer/request/v1",
            &self.intent.encode()?,
            &self.session,
            &[self.command.purpose()],
            &command,
        ]))
    }

    pub fn authenticate(&self) -> Result<Digest> {
        let digest = self.digest()?;
        VerifyingKey::from_bytes(&self.session)?
            .verify_raw(&digest, &Signature::try_from(self.signature.as_slice())?)?;
        Ok(digest)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.authenticate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= MAX_WIRE, "Spark wire size");
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_WIRE, "Spark wire size");
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(value.encode()? == bytes, "noncanonical Spark request");
        Ok(value)
    }
}
