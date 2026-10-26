//! Separate-party identity arithmetic. No API emits either private key share.
use super::*;
use crate::circuit::bytes;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::borrow::Borrow;
use tandem::states::{Contributor, Evaluator};
struct PrivateInput(Zeroizing<Vec<bool>>);
impl Borrow<[bool]> for PrivateInput {
    fn borrow(&self) -> &[bool] {
        &self.0
    }
}
type ServerState = Contributor<Arc<Circuit>, PrivateInput>;
type WalletState = Evaluator<Arc<Circuit>, PrivateInput>;
pub struct IdentityContributor {
    state: Option<ServerState>,
}
pub struct IdentityEvaluator {
    state: Option<WalletState>,
}
impl IdentityContributor {
    pub fn start(
        circuit: &IdentityCircuit,
        share: Zeroizing<[u8; 32]>,
        nonce: Zeroizing<[u8; 32]>,
        masks: Zeroizing<[[u8; 32]; 2]>,
        commitment: [u8; 32],
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<(Self, Vec<u8>)> {
        let input = server_input(&share, &nonce, &masks, &commitment)?;
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
            .ok_or_else(|| anyhow::anyhow!("identity contributor stopped"))?;
        let (state, reply) = state.run(message)?;
        self.state = Some(state);
        Ok(reply)
    }
    pub fn steps(&self) -> u32 {
        self.state.as_ref().map_or(0, |s| s.steps())
    }
}
impl IdentityEvaluator {
    pub fn start(
        circuit: &IdentityCircuit,
        share: Zeroizing<[u8; 32]>,
        nonce: Zeroizing<[u8; 32]>,
        salt: Zeroizing<[u8; 32]>,
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let input = wallet_input(&share, &nonce, &salt)?;
        let state = Evaluator::new(
            circuit.circuit.clone(),
            PrivateInput(input),
            ChaCha20Rng::from_seed(*seed),
        )?;
        Ok(Self { state: Some(state) })
    }
    pub fn advance(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let state = self
            .state
            .take()
            .ok_or_else(|| anyhow::anyhow!("identity evaluator stopped"))?;
        let (state, reply) = state.run(message)?;
        self.state = Some(state);
        Ok(reply)
    }
    pub fn steps(&self) -> u32 {
        self.state.as_ref().map_or(0, |s| s.steps())
    }
    /// The joint public key stays wallet-local. NEVER publish an unchecked
    /// output, including on errors: correctness checks are a release boundary.
    pub fn finish(mut self, message: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
        let state = self
            .state
            .take()
            .ok_or_else(|| anyhow::anyhow!("identity evaluator stopped"))?;
        let out = Zeroizing::new(state.output(message)?);
        ensure!(
            out.len() == 513 && out[0],
            "invalid identity presign inputs/output"
        );
        let encoded = Zeroizing::new(bytes(&out[1..])?);
        let ri = Option::<Scalar>::from(factor().invert()).unwrap();
        let mut result = Zeroizing::new([0; 64]);
        result[..32].copy_from_slice(&(scalar(encoded[..32].try_into()?)? * ri).to_bytes());
        result[32..].copy_from_slice(&(scalar(encoded[32..].try_into()?)? * ri).to_bytes());
        Ok(result)
    }
}
