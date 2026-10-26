//! Private persistence hooks beside the legacy nonce state machine.
use super::{
    Commitment, Nonce, Reveal, RevealedNonce, Session, check_roles, reveal_hash, session_binding,
};
use crate::{keys::Share, leaf_signing::LeafAuthority, signing_session};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateNonce {
    session_binding: [u8; 32],
    reveal: Reveal,
    commitment: Commitment,
    frozen: Option<[Commitment; 2]>,
}

impl Nonce {
    pub(crate) fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.encode_with("legacy-prepared", None)
    }

    pub(crate) fn decode_private(
        bytes: &[u8],
        share: &Share,
        authority: &LeafAuthority,
        session: Session,
    ) -> Result<Self> {
        let (nonce, frozen) =
            Self::decode_with(bytes, "legacy-prepared", share, authority, session)?;
        ensure!(frozen.is_none(), "prepared legacy nonce has frozen reveals");
        Ok(nonce)
    }

    fn encode_with(
        &self,
        kind: &str,
        frozen: Option<[Commitment; 2]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let public = serde_json::to_vec(&PrivateNonce {
            session_binding: self.session_binding,
            reveal: self.reveal.clone(),
            commitment: self.commitment.clone(),
            frozen,
        })?;
        signing_session::encode(
            kind,
            self.reveal.position,
            self.authority_binding,
            &self.inner,
            &public,
        )
    }

    fn decode_with(
        bytes: &[u8],
        kind: &str,
        share: &Share,
        authority: &LeafAuthority,
        session: Session,
    ) -> Result<(Self, Option<[Commitment; 2]>)> {
        authority.participant_package(share)?;
        let authority_binding = authority.binding()?;
        let expected_session = session_binding(authority, session)?;
        let (inner, public) =
            signing_session::decode(bytes, kind, share.public().position, authority_binding)?;
        let record: PrivateNonce = serde_json::from_slice(&public)?;
        ensure!(
            serde_json::to_vec(&record)? == public,
            "noncanonical legacy nonce metadata"
        );
        ensure!(
            record.session_binding == expected_session
                && record.reveal.position == share.public().position
                && record.commitment.position == share.public().position
                && record.commitment.digest == reveal_hash(expected_session, &record.reveal),
            "persisted legacy nonce session or reveal mismatch"
        );
        signing_session::check_public(&inner, &record.reveal.nonce_commitment)?;
        Ok((
            Self {
                authority_binding,
                session_binding: expected_session,
                inner,
                reveal: record.reveal,
                commitment: record.commitment,
            },
            record.frozen,
        ))
    }
}

impl RevealedNonce {
    pub(crate) fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.nonce
            .encode_with("legacy-revealed", Some(self.commitments.clone()))
    }

    pub(crate) fn decode_private(
        bytes: &[u8],
        share: &Share,
        authority: &LeafAuthority,
        session: Session,
    ) -> Result<Self> {
        let (nonce, frozen) =
            Nonce::decode_with(bytes, "legacy-revealed", share, authority, session)?;
        let commitments = frozen.context("revealed legacy nonce missing frozen commitments")?;
        check_roles(&commitments)?;
        ensure!(
            commitments[usize::from(share.public().position - 1)] == nonce.commitment,
            "persisted legacy nonce frozen commitment mismatch"
        );
        Ok(Self { nonce, commitments })
    }
}
