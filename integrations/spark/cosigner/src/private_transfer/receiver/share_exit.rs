//! Terminal share-release exit from this recipient's current ownership. The
//! owner key and wallet share stay inside; the journal holds certified points.
use super::{PrivateCertificate, PrivateReceiver, PrivateRecovery};
use crate::share_exit::{ExitCoin, ShareExit};
use anyhow::{Result, ensure};
use bitcoin::hashes::Hash;
use serde_json::Value;
use zark_protocol::{
    owner_auth::{generate_secret, normalized_key},
    point_bytes, random32, scalar,
    spark_lineage::Intent,
    spark_wire::{Command, HeadAuthorization, Request},
};

impl PrivateReceiver {
    /// X_s is taken from this owner's certificate and P from the signed native
    /// backing; both are checked to complete with the wallet share before the
    /// journal exists, so no signer response can choose either.
    pub fn share_exit_coin(
        &self,
        recovery: &PrivateRecovery,
        certificate: &PrivateCertificate,
        receiver: &[u8],
    ) -> Result<ExitCoin> {
        ensure!(
            recovery.witness().user == self.record.user
                && certificate.authorization().next_capability == self.next_capability()?,
            "share exit recipient current owner differs"
        );
        let lineage = certificate.native_lineage()?;
        let server = certificate.authorization().recovery.server;
        let backing = self.offer.backing();
        backing.owner_key(&server, scalar(&self.record.user)?)?;
        let joint = k256::PublicKey::from_sec1_bytes(backing.keys().user_key())?.to_projective();
        let [root, cpfp, direct] = backing.validated_exit().txids();
        Ok(ExitCoin {
            deployment: lineage.deployment,
            coin: lineage.coin,
            state: lineage.state,
            capability: self.next_capability()?,
            server: server.to_vec(),
            joint: point_bytes(joint)?.to_vec(),
            root: root.to_byte_array(),
            refunds: [cpfp.to_byte_array(), direct.to_byte_array()],
            receiver: receiver.to_vec(),
        })
    }

    pub fn share_release_request(&self, exit: &mut ShareExit, revision: u64) -> Result<Request> {
        exit.new_attempt(&normalized_key(&self.record.owner)?, random32(), revision)
    }

    pub fn accept_share_release(&self, exit: &mut ShareExit, response: &Value) -> Result<()> {
        exit.accept(response, &self.record.user)
    }

    /// Owner-authorized fresh head; the signer answers it in every phase.
    pub fn owner_head_request(
        &self,
        certificate: &PrivateCertificate,
        revision: u64,
    ) -> Result<Request> {
        let lineage = certificate.native_lineage()?;
        let intent = Intent {
            deployment: lineage.deployment,
            coin: lineage.coin,
            previous_state: lineage.state,
            operation: random32(),
            recipient_claim: random32(),
            revision,
        };
        let session = normalized_key(&generate_secret())?;
        let challenge = random32();
        let owner = HeadAuthorization::sign(
            &intent,
            &session.verifying_key().to_bytes().into(),
            &challenge,
            &normalized_key(&self.record.owner)?,
        )?;
        Request::sign(
            intent,
            Command::Head {
                challenge,
                owner: Some(owner),
            },
            &session,
        )
    }
}
