//! Separate-party state machines. Messages are untrusted and output remains
//! evaluator-only. Callers must journal seeds/inputs and every exact frame.
use crate::{
    ClaimCircuit, EncryptionMask,
    circuit::{bits, bytes},
};
use anyhow::{Result, ensure};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{borrow::Borrow, sync::Arc};
use tandem::states::{Contributor, Evaluator};
use zeroize::Zeroizing;

struct PrivateInput(Zeroizing<Vec<bool>>);
impl Borrow<[bool]> for PrivateInput {
    fn borrow(&self) -> &[bool] {
        &self.0
    }
}
type ContributorState = Contributor<Arc<tandem::Circuit>, PrivateInput>;
type EvaluatorState = Evaluator<Arc<tandem::Circuit>, PrivateInput>;
pub struct ClaimContributor {
    state: Option<ContributorState>,
}
pub struct ClaimEvaluator {
    state: Option<EvaluatorState>,
    header: Vec<u8>,
}
impl ClaimContributor {
    pub fn start(
        circuit: &ClaimCircuit,
        scalar: Zeroizing<[u8; 32]>,
        mask: &EncryptionMask,
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<(Self, Vec<u8>)> {
        ensure!(
            mask.length() == circuit.spec.plaintext_bytes,
            "joint claim encryption mask length"
        );
        let input = mask.input(&scalar);
        let (state, message) = Contributor::new(
            circuit.circuit.clone(),
            PrivateInput(input),
            ChaCha20Rng::from_seed(*seed),
        )?;
        Ok((Self { state: Some(state) }, message))
    }
    pub fn advance(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let state = self
            .state
            .take()
            .ok_or_else(|| anyhow::anyhow!("joint claim contributor stopped"))?;
        let (state, reply) = state.run(message)?;
        self.state = Some(state);
        Ok(reply)
    }
    pub fn steps(&self) -> u32 {
        self.state.as_ref().map_or(0, |s| s.steps())
    }
}
impl ClaimEvaluator {
    pub fn start(
        circuit: &ClaimCircuit,
        scalar: Zeroizing<[u8; 32]>,
        template: Zeroizing<Vec<u8>>,
        header: &[u8],
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        ensure!(
            template.len() == circuit.spec.plaintext_bytes && header.len() == 81 && header[0] == 4,
            "joint claim evaluator shape"
        );
        k256::PublicKey::from_sec1_bytes(&header[..65])?;
        let mut input = Zeroizing::new(bits(&*scalar));
        input.extend(bits(&template));
        let state = Evaluator::new(
            circuit.circuit.clone(),
            PrivateInput(input),
            ChaCha20Rng::from_seed(*seed),
        )?;
        Ok(Self {
            state: Some(state),
            header: header.to_vec(),
        })
    }
    pub fn advance(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let state = self
            .state
            .take()
            .ok_or_else(|| anyhow::anyhow!("joint claim evaluator stopped"))?;
        let (state, reply) = state.run(message)?;
        self.state = Some(state);
        Ok(reply)
    }
    pub fn steps(&self) -> u32 {
        self.state.as_ref().map_or(0, |s| s.steps())
    }
    pub fn finish(mut self, message: &[u8]) -> Result<Vec<u8>> {
        let state = self
            .state
            .take()
            .ok_or_else(|| anyhow::anyhow!("joint claim evaluator stopped"))?;
        let output = Zeroizing::new(state.output(message)?);
        ensure!(
            output.first() == Some(&true),
            "noncanonical or zero joint claim evaluation"
        );
        let mut wire = self.header.clone();
        wire.extend(bytes(&output[1..])?);
        Ok(wire)
    }
}
