//! Additive receive: the signer seals only the share scalar. The wallet checks
//! the polynomial constant against B - P (`TweakProofs::validate`) and
//! completes every package from its own template, so all operators receive
//! identical proofs and public shares.
use super::*;
use zark_protocol::spark_ecies;

const PURPOSE: u8 = 43;

impl ReceiveJournal {
    /// The request is frozen before it is returned; a lost response is
    /// recovered only by resending these exact bytes.
    pub fn tweak_request(&mut self) -> Result<Request> {
        ensure!(
            self.record.additive,
            "receive journal uses garbled circuits"
        );
        ensure!(self.record.prepared.is_some(), "receive preparation absent");
        if let Some(r) = self.frozen(PURPOSE)? {
            return Ok(r);
        }
        let secrets = self
            .record
            .mpc
            .as_ref()
            .context("receive tweak inputs retired")?;
        let tweak = Zeroizing::new(scalar(&secrets.incoming)? - scalar(&self.record.user)?);
        self.freeze(Command::ReceiveTweak {
            tweak: tweak.to_bytes().into(),
        })
    }

    pub fn bind_tweak(&mut self, response: &Value) -> Result<()> {
        ensure!(
            self.record.requests.contains_key(&PURPOSE),
            "receive tweak request not frozen"
        );
        let (proofs, packages) = self.complete_packages(response)?;
        if let Some(saved) = &self.record.proofs {
            ensure!(
                *saved == proofs
                    && packages.iter().all(|(id, package)| {
                        self.record.transcripts[id].ciphertext == Some(hash(&[package]))
                    }),
                "receive tweak retry changed"
            );
            return self.persist();
        }
        ensure!(self.record.mpc.is_some(), "receive tweak inputs retired");
        for (id, package) in packages {
            let digest = self.write_blob(&package)?;
            self.record
                .transcripts
                .get_mut(&id)
                .context("receive transcript absent")?
                .ciphertext = Some(digest);
        }
        self.record.proofs = Some(proofs);
        self.record.mpc = None;
        self.persist()
    }

    fn complete_packages(
        &self,
        response: &Value,
    ) -> Result<(TweakProofs, BTreeMap<String, Vec<u8>>)> {
        let coefficients: Vec<String> = serde_json::from_value(response["coefficients"].clone())?;
        let proofs = TweakProofs {
            coefficients: coefficients
                .iter()
                .map(|c| Ok(hex::decode(c)?))
                .collect::<Result<_>>()?,
        };
        proofs.validate(&self.record.claim)?;
        let template = Zeroizing::new(proofs.joint_template(&self.record.claim)?);
        let (length, offset) = self.record.cluster.template_shape()?;
        ensure!(template.len() == length, "native protobuf shape differs");
        let operators = response["operators"]
            .as_object()
            .context("receive tweak operators absent")?;
        ensure!(
            operators.keys().eq(self.record.cluster.operators.keys()),
            "receive tweak operator coverage"
        );
        let mut packages = BTreeMap::new();
        for (id, op) in operators {
            let sealed = hex::decode(op["sealed"].as_str().context("sealed share absent")?)?;
            let hash_key: [u8; 16] =
                hex::decode(op["hash_key"].as_str().context("hash key absent")?)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("receive tweak hash key length"))?;
            packages.insert(
                id.clone(),
                spark_ecies::complete_slot(&sealed, &hash_key, offset, &template)?,
            );
        }
        Ok((proofs, packages))
    }
}
