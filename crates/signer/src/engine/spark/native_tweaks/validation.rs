//! Reopen checks bind retained MPC randomness to the real-proof-locked share.
use super::*;
impl Workflow {
    pub(in crate::engine::spark) fn validate(
        &self,
        coin: &Coin,
        policy: &Policy,
        intent: &Intent,
        session: Digest,
    ) -> Result<()> {
        self.spec.validate()?;
        ensure!(
            self.server == coin.server()?.to_vec() && self.circuit != [0; 32],
            "native tweak server/circuit changed"
        );
        zark_protocol::point(&self.slope)?;
        let cluster = policy
            .native_cluster
            .as_ref()
            .context("native tweak cluster absent")?;
        ensure!(
            self.transcripts.keys().eq(cluster.operators.keys()) && !self.transcripts.is_empty(),
            "native tweak operator coverage"
        );
        let complete = self.transcripts.values().all(|t| t.rounds.len() == 7);
        ensure!(
            self.secrets.is_some() == (!self.aborted && !complete)
                && (self.packet.is_none() || (self.ready() && self.packet != Some([0; 32]))),
            "native tweak lifecycle"
        );
        if let Some(s) = &self.secrets {
            ensure!(
                s.seed != [0; 32]
                    && scalar(&s.slope)? != k256::Scalar::ZERO
                    && point_bytes(k256::ProjectivePoint::GENERATOR * scalar(&s.slope)?)?.to_vec()
                        == self.slope,
                "native tweak private slope changed"
            );
        }
        for (id, t) in &self.transcripts {
            index(id)?;
            ensure!(
                t.initial != [0; 32] && t.rounds.len() <= 7,
                "native tweak transcript shape"
            );
            for (step, (input, output)) in t.rounds.iter().enumerate() {
                ensure!(
                    *input != [0; 32] && *output != [0; 32],
                    "zero native tweak frame hash"
                );
                native_tweak_frame_intent(intent, id, step as u8)?;
            }
        }
        k256::schnorr::VerifyingKey::from_bytes(&session)?;
        Ok(())
    }
    pub(in crate::engine::spark) fn validate_frames(
        &self,
        engine: &Engine,
        intent: &Intent,
        session: Digest,
    ) -> Result<()> {
        ensure!(
            engine.tweak_circuit(self.spec)?.digest() == self.circuit,
            "native tweak deployed circuit differs"
        );
        let files = engine.tweak_files()?;
        for (id, t) in &self.transcripts {
            files.read(&t.initial)?;
            for (step, (input, output)) in t.rounds.iter().enumerate() {
                files.read(input)?;
                files.read(output)?;
                let request = Request {
                    intent: native_tweak_frame_intent(intent, id, step as u8)?,
                    session,
                    command: Command::NativeTweakFrame {
                        operator: id.clone(),
                        step: step as u8,
                        frame: *input,
                    },
                    signature: Vec::new(),
                };
                files.check_slot(&slot(&request), &request.digest()?)?;
            }
        }
        Ok(())
    }
}
