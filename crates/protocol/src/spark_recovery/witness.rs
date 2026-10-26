//! Explicit wallet-local proof witness export. Never send this file to a signer.
use super::{BackingOpening, NonceOpening, RecoveryAuthorization, TargetOpening};
use anyhow::Result;
use zeroize::Zeroize;

pub struct RecoveryWitness {
    pub user: [u8; 32],
    pub backing: BackingOpening,
    pub target: TargetOpening,
    pub nonces: [NonceOpening; 2],
}
impl Drop for RecoveryWitness {
    fn drop(&mut self) {
        self.user.zeroize();
        self.backing.salt.zeroize();
        self.target.salt.zeroize();
    }
}
impl RecoveryWitness {
    /// Caller must save with private permissions under ignored work/.
    pub fn prover_toml(&self, authorization: &RecoveryAuthorization) -> Result<String> {
        let statement = authorization.encode()?;
        let mut out = format!(
            "statement = {}\npacked = [{}]\n",
            array(&statement),
            crate::public_fields(&statement)
                .chunks_exact(32)
                .map(|b| format!("\"0x{}\"", hex::encode(b)))
                .collect::<Vec<_>>()
                .join(",")
        );
        self.append_prover_fields(&mut out)?;
        Ok(out)
    }

    /// Append the same private recovery witness to a composed ownership role's
    /// canonical statement/packed header. This material is wallet-local only.
    pub fn append_prover_fields(&self, out: &mut String) -> Result<()> {
        for (name, value) in [
            ("user", self.user.as_slice()),
            ("funding_salt", self.backing.salt.as_slice()),
            ("recovery_salt", self.target.salt.as_slice()),
            ("payout", self.target.payout.as_slice()),
        ] {
            out.push_str(&format!("{name} = {}\n", array(value)));
        }
        for (name, value) in [
            ("fee", self.target.fee),
            ("delay", self.target.delay as u64),
            ("owner_index", self.target.owner_index as u64),
            ("initial", self.target.initial as u64),
            ("gap", self.target.gap as u64),
            ("margin", self.target.margin as u64),
        ] {
            out.push_str(&format!("{name} = {value}\n"));
        }
        for i in 0..2 {
            for (name, value) in [
                ("txid", self.backing.refunds[i].txid.as_slice()),
                ("alpha", self.nonces[i].alpha.as_slice()),
                ("beta", self.nonces[i].beta.as_slice()),
                ("nonce_salt", self.nonces[i].salt.as_slice()),
            ] {
                out.push_str(&format!("{name}_{i} = {}\n", array(value)));
            }
            out.push_str(&format!(
                "amount_{i} = {}\n",
                self.backing.refunds[i].amount
            ));
        }
        Ok(())
    }
}

fn array(bytes: &[u8]) -> String {
    format!(
        "[{}]",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}
