//! Fresh authenticated Spark heads; no Bitcoin head encoding is reused.
use super::{Command, Request};
use crate::{
    hash, random32,
    spark_lineage::{self as lineage, Digest, Intent},
};
use anyhow::{Result, ensure};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadAuthorization {
    pub public_key: Digest,
    pub signature: Vec<u8>,
}

impl HeadAuthorization {
    fn message(intent: &Intent, session: &Digest, challenge: &Digest) -> Result<Digest> {
        VerifyingKey::from_bytes(session)?;
        ensure!(*challenge != [0; 32], "zero Spark head challenge");
        Ok(hash(&[
            b"ZARK/spark/signer/head-owner/v1",
            &intent.encode()?,
            session,
            challenge,
        ]))
    }

    pub fn sign(
        intent: &Intent,
        session: &Digest,
        challenge: &Digest,
        owner: &SigningKey,
    ) -> Result<Self> {
        let public_key = owner.verifying_key().to_bytes().into();
        ensure!(
            public_key != *session,
            "Spark head owner and session keys must differ"
        );
        Ok(Self {
            public_key,
            signature: owner
                .sign_raw(&Self::message(intent, session, challenge)?, &random32())?
                .to_bytes()
                .to_vec(),
        })
    }

    pub fn verify(
        &self,
        intent: &Intent,
        session: &Digest,
        challenge: &Digest,
        current_capability: &Digest,
    ) -> Result<()> {
        ensure!(
            self.public_key != *session
                && lineage::public_capability_commitment(
                    &intent.deployment,
                    &intent.coin,
                    &self.public_key
                )? == *current_capability,
            "Spark head current owner authorization"
        );
        VerifyingKey::from_bytes(&self.public_key)?.verify_raw(
            &Self::message(intent, session, challenge)?,
            &Signature::try_from(self.signature.as_slice())?,
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum HeadPhase {
    Origin = 0,
    Available = 1,
    Locked = 2,
    Issued = 3,
    Exited = 4,
}

/// Contains commitments and operation status only, never native openings or
/// either participant's public/secret share. CAS revision is not an owner slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub deployment: Digest,
    pub coin: Digest,
    pub query: Digest,
    pub challenge: Digest,
    pub session: Digest,
    pub state: Digest,
    pub capability: Digest,
    pub policy: Digest,
    pub revision: u64,
    pub phase: HeadPhase,
    pub locked_operation: Option<Digest>,
    /// Origin-signed enablement of `ShareRelease` for this deployment. False
    /// keeps the version-1 head bytes that existing wallets already verify.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub share_release: bool,
}

impl Head {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = if self.share_release { 2u32 } else { 1u32 }
            .to_le_bytes()
            .to_vec();
        for value in [
            &self.deployment,
            &self.coin,
            &self.query,
            &self.challenge,
            &self.session,
            &self.state,
            &self.capability,
            &self.policy,
        ] {
            ensure!(*value != [0; 32], "zero Spark head field");
            out.extend_from_slice(value);
        }
        VerifyingKey::from_bytes(&self.session)?;
        ensure!(self.revision > 0, "zero Spark head revision");
        ensure!(
            self.locked_operation.is_none()
                == matches!(self.phase, HeadPhase::Available | HeadPhase::Exited),
            "Spark head lock/phase mismatch"
        );
        if let Some(operation) = self.locked_operation {
            ensure!(operation != [0; 32], "zero Spark head lock");
        }
        out.extend_from_slice(&self.revision.to_le_bytes());
        out.push(self.phase as u8);
        out.extend_from_slice(&self.locked_operation.unwrap_or([0; 32]));
        if self.share_release {
            out.push(1);
        }
        Ok(out)
    }

    pub fn message(&self) -> Result<Digest> {
        Ok(hash(&[
            b"ZARK/spark/signer/signed-head/v1",
            &self.encode()?,
        ]))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHead {
    pub head: Head,
    pub signature: Vec<u8>,
}

impl SignedHead {
    /// The caller must choose a fresh unpredictable challenge for each read and
    /// pin the origin key through its authenticated Spark deployment config.
    pub fn verify(&self, request: &Request, expected_origin: &Digest) -> Result<&Head> {
        let query = request.authenticate()?;
        let Command::Head { challenge, .. } = &request.command else {
            anyhow::bail!("not a Spark head query");
        };
        ensure!(
            self.head.deployment == request.intent.deployment
                && self.head.coin == request.intent.coin
                && self.head.session == request.session
                && self.head.challenge == *challenge
                && self.head.query == query,
            "Spark head differs from fresh query"
        );
        VerifyingKey::from_bytes(expected_origin)?.verify_raw(
            &self.head.message()?,
            &Signature::try_from(self.signature.as_slice())?,
        )?;
        Ok(&self.head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> SigningKey {
        SigningKey::from_bytes(&crate::random_scalar().to_bytes()).unwrap()
    }

    #[test]
    fn head_signature_rejects_changed_query_and_owner_purpose_substitution() -> Result<()> {
        let origin = key();
        let owner = key();
        let session = key();
        let intent = Intent {
            deployment: [1; 32],
            coin: [2; 32],
            previous_state: [3; 32],
            operation: [4; 32],
            recipient_claim: [5; 32],
            revision: 17,
        };
        let challenge = random32();
        let session_public = session.verifying_key().to_bytes().into();
        let authorization = HeadAuthorization::sign(&intent, &session_public, &challenge, &owner)?;
        let capability = lineage::public_capability_commitment(
            &intent.deployment,
            &intent.coin,
            &owner.verifying_key().to_bytes().into(),
        )?;
        authorization.verify(&intent, &session_public, &challenge, &capability)?;
        let request = Request::sign(
            intent.clone(),
            Command::Head {
                challenge,
                owner: Some(authorization.clone()),
            },
            &session,
        )?;
        let head = Head {
            deployment: intent.deployment,
            coin: intent.coin,
            query: request.digest()?,
            challenge,
            session: session_public,
            state: [6; 32],
            capability,
            policy: [7; 32],
            revision: 19,
            phase: HeadPhase::Available,
            locked_operation: None,
            share_release: false,
        };
        let version_one = head.encode()?;
        assert_eq!(&version_one[..4], &1u32.to_le_bytes());
        let enabled = Head {
            share_release: true,
            ..head.clone()
        };
        assert_eq!(
            [&2u32.to_le_bytes()[..], &version_one[4..], &[1]].concat(),
            enabled.encode()?
        );
        assert!(!serde_json::to_string(&head)?.contains("share_release"));
        let forged = SignedHead {
            signature: origin
                .sign_raw(&head.message()?, &random32())?
                .to_bytes()
                .to_vec(),
            head: enabled,
        };
        assert!(
            forged
                .verify(&request, &origin.verifying_key().to_bytes().into())
                .is_err()
        );
        let response = SignedHead {
            signature: origin
                .sign_raw(&head.message()?, &random32())?
                .to_bytes()
                .to_vec(),
            head,
        };
        response.verify(&request, &origin.verifying_key().to_bytes().into())?;
        let other = Request::sign(
            intent.clone(),
            Command::Head {
                challenge: random32(),
                owner: Some(authorization),
            },
            &session,
        )?;
        assert!(
            response
                .verify(&other, &origin.verifying_key().to_bytes().into())
                .is_err()
        );
        let reserve = super::super::OwnerAuthorization::sign(&intent, &session_public, &owner)?;
        assert!(
            HeadAuthorization {
                public_key: reserve.public_key,
                signature: reserve.signature
            }
            .verify(&intent, &session_public, &challenge, &capability)
            .is_err()
        );
        Ok(())
    }
}
