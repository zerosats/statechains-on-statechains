//! External SparkSigner implementation linked to the unchanged pinned SDK.
//! Its private stdio port terminates at the WALLET controller, not the blind
//! signer. The wallet allow-lists and hashes identity messages itself before
//! any digest reaches the latter service.
use anyhow::{Context, Result, ensure};
use bitcoin::secp256k1::{PublicKey, ecdsa, schnorr};
use frost_secp256k1_tr as frost;
use serde_json::{Value, json};
use spark::{signer::*, tree::TreeNodeId};
use std::{
    io::{self, BufRead, Read, Write},
    sync::{Arc, Mutex},
};

struct WalletPort(Mutex<()>);
impl WalletPort {
    fn call(&self, value: Value) -> Result<Value> {
        let _lock = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet port poisoned"))?;
        let mut out = io::stdout().lock();
        serde_json::to_writer(&mut out, &value)?;
        out.write_all(b"\n")?;
        out.flush()?;
        let mut line = String::new();
        io::stdin().lock().take(1024 * 1024).read_line(&mut line)?;
        ensure!(
            !line.is_empty() && line.len() < 1024 * 1024,
            "wallet response size"
        );
        let reply: Value = serde_json::from_str(&line)?;
        ensure!(reply["ok"] == true, "wallet receive operation failed");
        Ok(reply["value"].clone())
    }
    fn bytes(&self, value: Value) -> Result<Vec<u8>> {
        Ok(serde_json::from_value(self.call(value)?)?)
    }
}
struct ZarkSparkSigner {
    port: Arc<WalletPort>,
}
fn error(e: anyhow::Error) -> SignerError {
    SignerError::Generic(e.to_string())
}
fn unsupported() -> SignerError {
    SignerError::Generic("operation outside ordinary joint-root receive profile".into())
}
impl ZarkSparkSigner {
    /// `kind` names the SDK callback; the wallet parses the raw message as
    /// that kind and refuses anything else, so this driver cannot choose a digest.
    fn identity_signature(&self, kind: &str, message: &[u8]) -> Result<ecdsa::Signature, SignerError> {
        let bytes = self
            .port
            .bytes(json!({"op":"identity_message","kind":kind,"message":message}))
            .map_err(error)?;
        ecdsa::Signature::from_der(&bytes).map_err(|e| SignerError::Generic(e.to_string()))
    }
}
#[async_trait::async_trait]
impl SparkSigner for ZarkSparkSigner {
    async fn get_identity_public_key(&self) -> Result<PublicKey, SignerError> {
        PublicKey::from_slice(
            &self
                .port
                .bytes(json!({"op":"identity_public"}))
                .map_err(error)?,
        )
        .map_err(|e| SignerError::Generic(e.to_string()))
    }
    async fn get_public_key_for_leaf(&self, leaf: &TreeNodeId) -> Result<PublicKey, SignerError> {
        PublicKey::from_slice(
            &self
                .port
                .bytes(json!({"op":"leaf_public","leaf_id":leaf.to_string()}))
                .map_err(error)?,
        )
        .map_err(|e| SignerError::Generic(e.to_string()))
    }
    fn is_remote(&self) -> bool {
        true
    }
    async fn get_static_deposit_public_key(&self, _: u32) -> Result<PublicKey, SignerError> {
        Err(unsupported())
    }
    async fn sign_authentication_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<ecdsa::Signature, SignerError> {
        self.identity_signature("challenge", challenge)
    }
    /// The receive profile signs only the claim-package payload here.
    async fn sign_message(&self, message: &[u8]) -> Result<ecdsa::Signature, SignerError> {
        self.identity_signature("claim", message)
    }
    async fn sign_leaf_refund_spend(
        &self,
        _: &TreeNodeId,
        _: &[u8],
    ) -> Result<schnorr::Signature, SignerError> {
        Err(unsupported())
    }
    async fn sign_frost(&self, jobs: Vec<FrostJob>) -> Result<Vec<FrostShareResult>, SignerError> {
        let encoded=jobs.iter().map(|j|->Result<Value>{
            let FrostDerivation::SigningLeaf{leaf_id}=&j.derivation else {anyhow::bail!("not leaf signing");};
            ensure!(j.adaptor_public_key.is_none(),"unsupported receive adaptor");
            let operators=j.operator_commitments.iter().map(|(id,c)|Ok((hex::encode(id.serialize()),json!({"hiding":c.hiding().serialize()?,"binding":c.binding().serialize()?})))).collect::<Result<std::collections::BTreeMap<_,_>>>()?;
            Ok(json!({"leaf_id":leaf_id.to_string(),"sighash":j.sighash,"combined":j.verifying_key.serialize().to_vec(),"operators":operators}))
        }).collect::<Result<Vec<_>>>().map_err(error)?;
        let response = self
            .port
            .call(json!({"op":"claim_frost","jobs":encoded}))
            .map_err(error)?;
        let rows = response
            .as_array()
            .ok_or_else(|| SignerError::Generic("missing USER result rows".into()))?;
        if rows.len() != jobs.len() {
            return Err(unsupported());
        }
        rows.iter()
            .map(|row| -> Result<FrostShareResult> {
                let bytes = |name: &str| -> Result<Vec<u8>> {
                    Ok(serde_json::from_value(row[name].clone())?)
                };
                let public = frost::round1::SigningCommitments::new(
                    frost::round1::NonceCommitment::deserialize(&bytes("hiding")?)?,
                    frost::round1::NonceCommitment::deserialize(&bytes("binding")?)?,
                );
                Ok(FrostShareResult {
                    commitment: FrostSigningCommitmentsWithNonces {
                        commitments: public,
                        nonces_ciphertext: Vec::new(),
                    },
                    signature_share: frost::round2::SignatureShare::deserialize(&bytes("share")?)?,
                })
            })
            .collect::<Result<Vec<_>>>()
            .map_err(error)
    }
    async fn prepare_claim(
        &self,
        request: PrepareClaimRequest,
    ) -> Result<PreparedClaim, SignerError> {
        let recipients=request.operator_recipients.iter().map(|r|json!({"index":r.id+1,"identifier":hex::encode(r.identifier.serialize()),"public_key":r.public_key.serialize().to_vec()})).collect::<Vec<_>>();
        let leaves=request.leaves.iter().map(|l|json!({"node":l.node,"node_raw":bitcoin::consensus::serialize(&l.node.node_tx),
            "refund_raw":l.node.refund_tx.as_ref().map(bitcoin::consensus::serialize),"sender_signature":l.sender_signature,"incoming_ciphertext":l.leaf_key_ciphertext})).collect::<Vec<_>>();
        let value=self.port.call(json!({"op":"prepare_claim","transfer_id":request.transfer_id.to_string(),"sender_identity":request.sender_identity_public_key.serialize().to_vec(),"threshold":request.threshold,"recipients":recipients,"leaves":leaves})).map_err(error)?;
        let map: std::collections::BTreeMap<String, Vec<u8>> =
            serde_json::from_value(value).map_err(|e| SignerError::Generic(e.to_string()))?;
        if map.len() != request.operator_recipients.len() {
            return Err(unsupported());
        }
        let operator_packages = request
            .operator_recipients
            .iter()
            .map(|r| -> Result<OperatorPackage> {
                Ok(OperatorPackage {
                    operator_identifier: r.identifier,
                    encrypted_package: map
                        .get(&hex::encode(r.identifier.serialize()))
                        .context("missing operator package")?
                        .clone(),
                })
            })
            .collect::<Result<Vec<_>>>()
            .map_err(error)?;
        Ok(PreparedClaim { operator_packages })
    }
    async fn prepare_transfer(
        &self,
        _: PrepareTransferRequest,
    ) -> Result<PreparedTransfer, SignerError> {
        Err(unsupported())
    }
    async fn prepare_lightning_receive(
        &self,
        _: PrepareLightningReceiveRequest,
    ) -> Result<PreparedLightningReceive, SignerError> {
        Err(unsupported())
    }
    async fn prepare_static_deposit(
        &self,
        _: PrepareStaticDepositRequest,
    ) -> Result<PreparedStaticDeposit, SignerError> {
        Err(unsupported())
    }
    async fn start_static_deposit_refund(
        &self,
        _: StartStaticDepositRefundRequest,
    ) -> Result<StartedStaticDepositRefund, SignerError> {
        Err(unsupported())
    }
    async fn sign_static_deposit_refund(
        &self,
        _: SignStaticDepositRefundRequest,
    ) -> Result<frost::Signature, SignerError> {
        Err(unsupported())
    }
    async fn prepare_static_deposit_claim(
        &self,
        _: PrepareStaticDepositClaimRequest,
    ) -> Result<PreparedStaticDepositClaim, SignerError> {
        Err(unsupported())
    }
    async fn sign_spark_invoice(
        &self,
        _: SignSparkInvoiceRequest,
    ) -> Result<SignedSparkInvoice, SignerError> {
        Err(unsupported())
    }
    async fn prepare_token_transaction(
        &self,
        _: PrepareTokenTransactionRequest,
    ) -> Result<PreparedTokenTransaction, SignerError> {
        Err(unsupported())
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    use spark::{
        operator::{
            OperatorConfig, OperatorPool, OperatorPoolConfig, rpc::DefaultConnectionManager,
        },
        services::{ClaimTransferConfig, TransferId, TransferService},
        session_store::InMemorySessionStore,
    };
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 3,
        "expected retained native config directory and transfer ID"
    );
    let config = std::path::Path::new(&args[1]);
    let raw: Value = serde_json::from_slice(&std::fs::read(config.join("operators.json"))?)?;
    let operators = raw
        .as_array()
        .context("operators missing")?
        .iter()
        .map(|o| -> Result<OperatorConfig> {
            let id = o["id"].as_u64().context("operator index missing")? as usize;
            Ok(OperatorConfig {
                id,
                identifier: frost::Identifier::try_from((id + 1) as u16)?,
                address: format!(
                    "https://{}",
                    o["address"].as_str().context("operator address missing")?
                ),
                ca_cert: Some(std::fs::read(
                    o["cert_path"]
                        .as_str()
                        .context("operator certificate missing")?,
                )?),
                identity_public_key: o["identity_public_key"]
                    .as_str()
                    .context("operator identity missing")?
                    .parse()?,
                user_agent: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let signer: Arc<dyn SparkSigner> = Arc::new(ZarkSparkSigner {
        port: Arc::new(WalletPort(Mutex::new(()))),
    });
    let pool = Arc::new(
        OperatorPool::connect(
            &OperatorPoolConfig::new(0, operators)?,
            Arc::new(DefaultConnectionManager::new()),
            Arc::new(InMemorySessionStore::default()),
            signer.clone(),
            None,
        )
        .await?,
    );
    let service = TransferService::new(signer, spark::Network::Regtest, 2, pool, None);
    let id: TransferId = args[2].parse().map_err(anyhow::Error::msg)?;
    let transfer = service
        .query_transfer(&id)
        .await?
        .context("native transfer missing")?;
    let leaves = service
        .claim_transfer(
            &transfer,
            Some(ClaimTransferConfig {
                max_retries: 1,
                base_delay_ms: 100,
                max_delay_ms: 100,
            }),
        )
        .await?;
    let mut out = io::stdout().lock();
    serde_json::to_writer(
        &mut out,
        &json!({"op":"claimed","transfer_id":id.to_string(),"leaves":leaves}),
    )?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
