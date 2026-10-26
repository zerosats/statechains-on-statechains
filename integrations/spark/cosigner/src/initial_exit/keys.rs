//! Checked native aggregate keys; no historical per-holder public shares.
use crate::keys::{Purpose, Scope};
use anyhow::{Result, ensure};
use bitcoin::secp256k1::PublicKey;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct NativeLeafKeys {
    scope: Scope,
    user: Vec<u8>,
    operator: Vec<u8>,
    combined: Vec<u8>,
}

impl NativeLeafKeys {
    pub fn new(scope: Scope, user: &[u8], operator: &[u8], combined: &[u8]) -> Result<Self> {
        ensure!(
            scope.purpose == Purpose::LeafSigning
                && scope.deployment != [0; 32]
                && scope.coin != [0; 32],
            "native leaf key scope"
        );
        let parse = |bytes: &[u8]| -> Result<PublicKey> {
            ensure!(bytes.len() == 33, "native aggregate key length");
            let key = PublicKey::from_slice(bytes)?;
            ensure!(
                key.serialize().as_slice() == bytes,
                "noncanonical native aggregate key"
            );
            Ok(key)
        };
        ensure!(
            parse(user)?.combine(&parse(operator)?)? == parse(combined)?,
            "native USER/operator aggregate differs"
        );
        Ok(Self {
            scope,
            user: user.to_vec(),
            operator: operator.to_vec(),
            combined: combined.to_vec(),
        })
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn user_key(&self) -> &[u8] {
        &self.user
    }
    pub fn operator_key(&self) -> &[u8] {
        &self.operator
    }
    pub fn combined_key(&self) -> &[u8] {
        &self.combined
    }

    pub(super) fn binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"ZARK/spark/native-leaf-aggregate/v1");
        hash.update(self.scope.deployment);
        hash.update(self.scope.coin);
        hash.update([self.scope.purpose as u8]);
        hash.update(&self.user);
        hash.update(&self.operator);
        hash.update(&self.combined);
        hash.finalize().into()
    }
}
