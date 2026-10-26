//! The sender's private recursive witness, separate from durable orchestration.
use super::super::witness;
use super::PrivateSender;
use anyhow::Result;
use std::path::Path;
use zark_protocol::{
    point_bytes,
    spark_lineage::{PinnedSparkVerifier, SparkRole},
    spark_wire::Predecessor,
};
use zeroize::Zeroizing;

impl PrivateSender {
    pub fn prover_toml(
        &self,
        verifier: &PinnedSparkVerifier,
        scratch: &Path,
    ) -> Result<Zeroizing<String>> {
        self.verify_current(verifier, scratch)?;
        self.persist()?;
        let handover = self.handover()?;
        let previous = self.certificate.native_lineage()?;
        let auth = self.certificate.authorization();
        let mask = self.record.mask.as_ref().expect("handover checked mask");
        let w = self.recovery.witness();
        // The recovery plan checks this exact TapTweaked USER key against both
        // native refunds; verify_current binds its owner shares and certificate.
        // Derive the new private witness without changing the saved journal.
        let funding_output_key = self.recovery.plan().output_key().serialize();
        let mut out = witness::statement(&handover.encode()?)?;
        let previous_bytes = Zeroizing::new(previous.encode()?);
        let authorization_bytes = Zeroizing::new(auth.encode()?);
        for (name, value) in [
            ("token", self.record.token.as_slice()),
            ("previous", previous_bytes.as_slice()),
            ("previous_authorization", authorization_bytes.as_slice()),
            ("server", auth.recovery.server.as_slice()),
            ("server_salt", self.certificate.server_salt().as_slice()),
            ("user", w.user.as_slice()),
            ("owner_secret", self.record.owner.as_slice()),
            ("mask", mask.value.as_slice()),
            ("mask_salt", mask.salt.as_slice()),
            ("masked", mask.masked.as_slice()),
            ("masked_salt", self.record.masked_salt.as_slice()),
            ("funding_salt", w.backing.salt.as_slice()),
            ("funding_output_key", funding_output_key.as_slice()),
            ("txid_0", w.backing.refunds[0].txid.as_slice()),
            ("txid_1", w.backing.refunds[1].txid.as_slice()),
            ("payout", w.target.payout.as_slice()),
            ("recovery_salt", w.target.salt.as_slice()),
            ("bridge_salt", self.record.bridge_salt.as_slice()),
        ] {
            witness::bytes(&mut out, name, value)?;
        }
        let role = if self.certificate.kind() == Predecessor::Origin {
            SparkRole::Deposit
        } else {
            SparkRole::Receiver
        };
        witness::fields(
            &mut out,
            "previous_vk",
            &verifier.recursive_key_bytes(role)?,
            115,
        )?;
        witness::fields(&mut out, "previous_proof", self.certificate.proof(), 458)?;
        witness::partials(&mut out, &self.certificate.partials())?;
        if let Some(signature) = self.certificate.origin_signature() {
            let key = k256::schnorr::VerifyingKey::from_bytes(&previous.config.origin_key)?;
            let nonce = k256::schnorr::VerifyingKey::from_bytes(&signature[..32])?;
            witness::bytes(
                &mut out,
                "origin_key",
                &point_bytes((*key.as_affine()).into())?,
            )?;
            witness::bytes(
                &mut out,
                "origin_nonce",
                &point_bytes((*nonce.as_affine()).into())?,
            )?;
            witness::bytes(&mut out, "origin_signature", signature)?;
        }
        out.push_str(&format!("amount_0 = {}\namount_1 = {}\nfee = {}\ndelay = {}\nowner_index = {}\ninitial = {}\ngap = {}\nmargin = {}\n",w.backing.refunds[0].amount,w.backing.refunds[1].amount,w.target.fee,w.target.delay,w.target.owner_index,w.target.initial,w.target.gap,w.target.margin));
        Ok(out)
    }
}
