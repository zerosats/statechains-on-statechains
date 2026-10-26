//! Freeze random encryption before releasing a standard operator package.
//! No RPC, identity signature, ownership acknowledgement or signer call occurs.
use super::{ClaimPlan, TweakProofs, seal, wire};
use crate::private_transfer::persistence::OperationFile;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
use zeroize::Zeroizing;

const FILE: &str = "standard-claim-package.json";
const SCHEMA: &str = "zark-spark-standard-operator-claim";
const MAX_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u32,
    plan: ClaimPlan,
    proofs: TweakProofs,
    operator: String,
    ciphertext: Vec<u8>,
}

/// One recipient's private package journal. The scalar evaluation is checked,
/// encrypted and discarded; only native public facts and ciphertext persist.
/// This type cannot manufacture the combined evaluation from the two holders.
pub struct OperatorClaimJournal {
    file: OperationFile,
    record: Record,
}

impl OperatorClaimJournal {
    /// Supply one final per-operator evaluation, never individual Zark shares.
    /// This is an encryption primitive, not permission to disclose evaluations
    /// from the real blind signer. No such export is installed in that engine.
    pub fn create(
        directory: &Path,
        plan: &ClaimPlan,
        proofs: &TweakProofs,
        operator: &str,
        evaluation: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let ciphertext = seal(plan, proofs, operator, evaluation)?;
        let record = Record {
            schema: SCHEMA.into(),
            version: 1,
            plan: plan.clone(),
            proofs: proofs.clone(),
            operator: operator.into(),
            ciphertext,
        };
        let file = OperationFile::create(directory, FILE)?;
        let value = Self { file, record };
        value.validate(plan, proofs, operator)?;
        value.persist()?;
        Ok(value)
    }

    /// Reopen only; missing/unsafe records never generate replacement packages.
    pub fn open(
        directory: &Path,
        plan: &ClaimPlan,
        proofs: &TweakProofs,
        operator: &str,
    ) -> Result<Self> {
        let (file, bytes) = OperationFile::open(directory, FILE, MAX_BYTES)?;
        let record: Record = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&record)?.as_slice() == bytes.as_slice(),
            "noncanonical standard claim journal"
        );
        let value = Self { file, record };
        value.validate(plan, proofs, operator)?;
        value.persist()?;
        Ok(value)
    }

    fn validate(&self, plan: &ClaimPlan, proofs: &TweakProofs, operator: &str) -> Result<()> {
        proofs.validate(plan)?;
        ensure!(
            self.record.schema == SCHEMA
                && self.record.version == 1
                && self.record.plan == *plan
                && self.record.proofs == *proofs
                && self.record.operator == operator
                && plan.operators.contains_key(operator),
            "standard claim journal pins changed"
        );
        // Ciphertext is opaque. Reopening can check format and binding, not
        // prove its hidden plaintext or re-establish ownership authorization.
        let expected = wire::encode(
            &plan.leaf_id,
            &[0; 32],
            &proofs.coefficients,
            &proofs.public_shares(plan)?,
        )
        .len();
        let cipher = &self.record.ciphertext;
        ensure!(
            cipher.len() == expected + 97 && cipher[0] == 4,
            "standard claim ECIES shape"
        );
        let ephemeral = k256::PublicKey::from_sec1_bytes(&cipher[..65])?;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        ensure!(
            ephemeral.to_encoded_point(false).as_bytes() == &cipher[..65],
            "standard claim ECIES ephemeral point"
        );
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        self.file
            .save(&serde_json::to_vec(&self.record)?, MAX_BYTES)
    }

    /// Exact saved ciphertext. Retry also crosses the durable-write barrier:
    /// failed saves must not allow an in-memory cached package to escape.
    pub fn package(&self) -> Result<Vec<u8>> {
        self.persist()?;
        Ok(self.record.ciphertext.clone())
    }
}

/// Form Spark's normal key_tweak_package map after saving every recipient.
/// This does not construct/sign a claim or establish that joint MPC completed.
pub fn collect_packages(
    plan: &ClaimPlan,
    proofs: &TweakProofs,
    journals: &[&OperatorClaimJournal],
) -> Result<BTreeMap<String, Vec<u8>>> {
    proofs.validate(plan)?;
    ensure!(
        journals.len() == plan.operators.len(),
        "incomplete standard claim packages"
    );
    let mut packages = BTreeMap::new();
    for journal in journals {
        journal.validate(plan, proofs, &journal.record.operator)?;
        ensure!(
            packages
                .insert(journal.record.operator.clone(), journal.package()?)
                .is_none(),
            "duplicate standard claim package"
        );
    }
    ensure!(
        packages.keys().eq(plan.operators.keys()),
        "standard claim recipient coverage changed"
    );
    Ok(packages)
}
