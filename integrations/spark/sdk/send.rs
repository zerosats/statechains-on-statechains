//! External single-key Spark send after a Zark share release.
//!
//! p = x_w + x_s is both the leaf's Spark identity and its USER signing key.
//! The stock `SparkSignerAdapter` runs the unchanged transfer flow over an
//! inner `DefaultSigner` (seeded by the wallet's exit journal, so a resumed
//! transfer derives the same new-leaf keys). The identity path is answered
//! with p, and the leaf's key reaches the inner signer only as Spark ECIES
//! ciphertext that the wallet seals to the inner identity key. The private
//! stdio port terminates at the WALLET controller, never the blind signer.
//!
//! The wallet must have run its chain-absence gate immediately before starting
//! this process and supplies the durable transfer ID, so a retry resumes the
//! same Spark transfer instead of creating a second one.
use anyhow::{Context, Result, ensure};
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{
    All, Message, PublicKey, Secp256k1, SecretKey, ecdsa, schnorr, rand::thread_rng,
};
use bitcoin::taproot::TapNodeHash;
use frost_secp256k1_tr::round2::SignatureShare;
use serde_json::{Value, json};
use spark::{
    signer::*,
    tree::{TreeNode, TreeNodeId},
};
use std::{
    io::{self, BufRead, Read, Write},
    sync::{Arc, Mutex},
};

struct WalletPort(Mutex<()>);
impl WalletPort {
    fn call(&self, value: Value) -> Result<Value> {
        let _lock = self.0.lock().map_err(|_| anyhow::anyhow!("wallet port poisoned"))?;
        let mut out = io::stdout().lock();
        serde_json::to_writer(&mut out, &value)?;
        out.write_all(b"\n")?;
        out.flush()?;
        let mut line = String::new();
        io::stdin().lock().take(1024 * 1024).read_line(&mut line)?;
        ensure!(!line.is_empty() && line.len() < 1024 * 1024, "wallet response size");
        let reply: Value = serde_json::from_str(&line)?;
        ensure!(reply["ok"] == true, "wallet exit send operation failed");
        Ok(reply["value"].clone())
    }
}

fn identity_path() -> DerivationPath {
    DerivationPath::from(vec![ChildNumber::from_hardened_idx(0).expect("valid hardened index")])
}
fn generic(e: impl std::fmt::Display) -> SignerError {
    SignerError::Generic(e.to_string())
}

/// Answers the identity path with p and delegates everything else.
struct SingleKeySigner {
    inner: DefaultSigner,
    key: SecretKey,
    identity: PublicKey,
    secp: Secp256k1<All>,
}
impl SingleKeySigner {
    fn is_identity(&self, path: &DerivationPath) -> bool {
        *path == identity_path()
    }
}
impl Drop for SingleKeySigner {
    fn drop(&mut self) {
        self.key.non_secure_erase();
    }
}

#[async_trait::async_trait]
impl Signer for SingleKeySigner {
    async fn derive_public_key(&self, path: &DerivationPath) -> Result<PublicKey, SignerError> {
        if self.is_identity(path) { return Ok(self.identity); }
        self.inner.derive_public_key(path).await
    }
    async fn secret_key(&self, path: &DerivationPath) -> Result<SecretKey, SignerError> {
        if self.is_identity(path) { return Err(generic("identity key is never exported")); }
        self.inner.secret_key(path).await
    }
    async fn sign_message_ecdsa(&self, path: &DerivationPath, message: &[u8]) -> Result<ecdsa::Signature, SignerError> {
        if !self.is_identity(path) { return self.inner.sign_message_ecdsa(path, message).await; }
        let digest = sha256::Hash::hash(message).to_byte_array();
        Ok(self.secp.sign_ecdsa(&Message::from_digest(digest), &self.key))
    }
    async fn sign_hash_schnorr(&self, path: &DerivationPath, hash: &[u8]) -> Result<schnorr::Signature, SignerError> {
        if !self.is_identity(path) { return self.inner.sign_hash_schnorr(path, hash).await; }
        let digest: [u8; 32] = hash.try_into().map_err(|_| generic("hash must be 32 bytes"))?;
        let keypair = self.key.keypair(&self.secp);
        Ok(self.secp.sign_schnorr_with_rng(&Message::from_digest(digest), &keypair, &mut thread_rng()))
    }
    async fn sign_hash_schnorr_with_tweak(&self, secret: &SecretSource, hash: &[u8], tap_tweak: Option<TapNodeHash>) -> Result<schnorr::Signature, SignerError> {
        self.inner.sign_hash_schnorr_with_tweak(secret, hash, tap_tweak).await
    }
    async fn generate_random_signing_commitment(&self) -> Result<FrostSigningCommitmentsWithNonces, SignerError> {
        self.inner.generate_random_signing_commitment().await
    }
    async fn generate_random_secret(&self) -> Result<EncryptedSecret, SignerError> {
        self.inner.generate_random_secret().await
    }
    async fn subtract_secrets(&self, signing_key: &SecretSource, new_signing_key: &SecretSource) -> Result<SecretSource, SignerError> {
        self.inner.subtract_secrets(signing_key, new_signing_key).await
    }
    async fn split_secret_with_proofs(&self, secret: &SecretToSplit, threshold: u32, num_shares: usize) -> Result<Vec<VerifiableSecretShare>, SignerError> {
        self.inner.split_secret_with_proofs(secret, threshold, num_shares).await
    }
    async fn encrypt_secret_for_receiver(&self, secret: &SecretSource, receiver_public_key: &PublicKey) -> Result<Vec<u8>, SignerError> {
        self.inner.encrypt_secret_for_receiver(secret, receiver_public_key).await
    }
    async fn public_key_from_secret(&self, private_key: &SecretSource) -> Result<PublicKey, SignerError> {
        self.inner.public_key_from_secret(private_key).await
    }
    async fn sign_frost<'a>(&self, request: SignFrostRequest<'a>) -> Result<SignatureShare, SignerError> {
        self.inner.sign_frost(request).await
    }
}

/// The exited leaf's key, sealed by the wallet to the inner identity key.
/// This send never splits leaves, so split-key operations are refused.
struct ExitLeafKey {
    leaf: TreeNodeId,
    ciphertext: Vec<u8>,
}
#[async_trait::async_trait]
impl LeafKeyOverrideStore for ExitLeafKey {
    async fn get_leaf_key(&self, node_id: &TreeNodeId) -> Result<Option<Vec<u8>>, LeafKeyOverrideStoreError> {
        Ok((*node_id == self.leaf).then(|| self.ciphertext.clone()))
    }
    async fn get_pending_split_keys(&self, _: &str, _: &TreeNodeId) -> Result<Option<Vec<Vec<u8>>>, LeafKeyOverrideStoreError> {
        Ok(None)
    }
    async fn put_pending_split_keys(&self, _: &str, _: &TreeNodeId, _: &[Vec<u8>]) -> Result<(), LeafKeyOverrideStoreError> {
        Err(LeafKeyOverrideStoreError::Generic("exit send never splits leaves".into()))
    }
    async fn bind_pending_split_keys(&self, _: &str, _: &[TreeNodeId]) -> Result<(), LeafKeyOverrideStoreError> {
        Err(LeafKeyOverrideStoreError::Generic("exit send never splits leaves".into()))
    }
    async fn retire_leaf_keys(&self, _: &[TreeNodeId]) -> Result<(), LeafKeyOverrideStoreError> {
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    use spark::{
        operator::{OperatorConfig, OperatorPool, OperatorPoolConfig, rpc::DefaultConnectionManager},
        services::{TransferId, TransferService},
        session_store::InMemorySessionStore,
    };
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len() == 2, "expected retained native config directory");
    let config = std::path::Path::new(&args[1]);
    let raw: Value = serde_json::from_slice(&std::fs::read(config.join("operators.json"))?)?;
    let operators = raw.as_array().context("operators missing")?.iter().map(|o| -> Result<OperatorConfig> {
        let id = o["id"].as_u64().context("operator index missing")? as usize;
        Ok(OperatorConfig {
            id,
            identifier: frost_secp256k1_tr::Identifier::try_from((id + 1) as u16)?,
            address: format!("https://{}", o["address"].as_str().context("operator address missing")?),
            ca_cert: Some(std::fs::read(o["cert_path"].as_str().context("operator certificate missing")?)?),
            identity_public_key: o["identity_public_key"].as_str().context("operator identity missing")?.parse()?,
            user_agent: None,
        })
    }).collect::<Result<Vec<_>>>()?;

    let port = WalletPort(Mutex::new(()));
    let exit = port.call(json!({"op":"exit_send"}))?;
    let bytes = |name: &str| -> Result<Vec<u8>> { Ok(serde_json::from_value(exit[name].clone())?) };
    let key = SecretKey::from_slice(&bytes("secret")?)?;
    let secp = Secp256k1::new();
    let identity = key.public_key(&secp);
    let inner = DefaultSigner::new(&bytes("seed")?, spark::Network::Regtest)?;
    let leaf: TreeNode = serde_json::from_value(exit["leaf"].clone())?;
    ensure!(leaf.owner_identity_public_key == Some(identity), "leaf is not owned by the released joint key");
    let inner_identity = inner.derive_public_key(&identity_path()).await?;
    let ciphertext: Vec<u8> = serde_json::from_value(
        port.call(json!({"op":"seal_leaf_key","public":inner_identity.serialize().to_vec()}))?,
    )?;
    let transfer_id: TransferId = exit["transfer_id"].as_str().context("transfer ID missing")?.parse().map_err(anyhow::Error::msg)?;
    let receiver = PublicKey::from_slice(&bytes("receiver")?)?;

    let store = Arc::new(ExitLeafKey { leaf: leaf.id.clone(), ciphertext });
    let low: Arc<dyn Signer> = Arc::new(SingleKeySigner { inner, key, identity, secp });
    let signer: Arc<dyn SparkSigner> = Arc::new(SparkSignerAdapter::new(low).with_leaf_key_override_store(store));
    ensure!(signer.get_public_key_for_leaf(&leaf.id).await? == identity, "sealed leaf key differs from P");
    let pool = Arc::new(OperatorPool::connect(&OperatorPoolConfig::new(0, operators)?,
        Arc::new(DefaultConnectionManager::new()), Arc::new(InMemorySessionStore::default()), signer.clone(), None).await?);
    let service = TransferService::new(signer, spark::Network::Regtest, 2, pool, None);
    let transfer = service.transfer_leaves_to(vec![leaf], &receiver, Some(transfer_id), None).await?;
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &json!({"op":"sent","transfer_id":transfer.id.to_string(),"status":format!("{:?}",transfer.status)}))?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
