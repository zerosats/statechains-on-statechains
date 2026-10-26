//! One coin's entry: a funded ordinary Spark leaf is claimed by the joint
//! identity through the unchanged SDK, then becomes a proof-gated Zark origin.
//! The signer database lives under `network`; every wallet file of this coin
//! lives under `coin`. The recovery acknowledgement is sent only after every
//! wallet record and the signer have been reopened.
use super::*;
use crate::{joint_identity::JointIdentityJournal, receive::ReceiveJournal};

/// The journals are held only for their locks. Field order is the reverse of
/// journal opening so drops keep ProcessLock nesting intact.
pub(super) struct Entered {
    _engine: Engine,
    _recovery: RecoveryJournal,
    _wallet: ReceiveJournal,
    _identity: JointIdentityJournal,
    pub leaf: String,
    pub claimed: Value,
    pub acknowledged: Value,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enter(
    suite: &Suite,
    network: &Path,
    coin: &Path,
    cluster: &ClaimCluster,
    mut controller: Controller<'_>,
    native: &mut Pipe,
    docker: &Path,
    start: &mut dyn FnMut(&mut Pipe, &[u8]) -> Result<Value>,
    stage: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Entered> {
    stage("transfer")?;
    // Returns `{transfer_id, leaf_id}` of the native transfer to the identity.
    let funded = start(native, &controller.identity.public_key()?)?;
    atomic_write(
        &coin.join("ordinary-sender.json"),
        &serde_json::to_vec(&funded)?,
    )?;
    let transfer = funded["transfer_id"]
        .as_str()
        .context("ordinary sender transfer missing")?
        .to_owned();
    let leaf = funded["leaf_id"]
        .as_str()
        .context("ordinary sender leaf missing")?
        .to_owned();
    stage("claim")?;
    let mut sdk = Pipe::sdk(docker, &transfer, &coin.join("sdk.private.log"))?;
    let claimed = loop {
        let request = sdk.next(None)?;
        if request["op"] == "claimed" {
            break request;
        }
        if request["op"] == "prepare_claim" {
            let observed = native.call_native(&json!({"op":"intermediate","directory":NATIVE,
                "transfer_id":transfer,"leaf_id":leaf,"receiver":controller.identity.public_key()?}))?;
            evidence::checked(&request, &observed, &controller.identity.public_key()?)?;
            atomic_write(
                &coin.join("native-intermediate-observation.json"),
                &serde_json::to_vec(&observed)?,
            )?;
        }
        if request["op"] == "claim_frost" {
            stage("prove_receive")?;
        }
        let response = controller
            .call(&request)
            .with_context(|| format!("wallet SDK callback {}", request["op"]))?;
        sdk.send(&json!({"ok":true,"value":response}))?;
    };
    sdk.completed()?;
    atomic_write(
        &coin.join("sdk-claimed.private.json"),
        &serde_json::to_vec(&claimed)?,
    )?;
    ensure!(
        claimed["transfer_id"] == transfer
            && claimed["leaves"].as_array().is_some_and(|v| v.len() == 1),
        "ordinary SDK claim result differs"
    );
    let observed=native.call_native(&json!({"op":"observe","directory":NATIVE,"transfer_id":transfer,"leaf_id":leaf,"receiver":controller.identity.public_key()?}))?;
    ensure!(
        observed["operators_completed"] == 3
            && observed["active_confirmations"]
                .as_u64()
                .is_some_and(|v| v > 0),
        "native funding/ownership observation incomplete"
    );
    atomic_write(
        &coin.join("native-observation.json"),
        &serde_json::to_vec(&observed)?,
    )?;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid, hashes::Hash};
    let anchor = &observed["anchor"];
    let anchor = crate::initial_exit::DepositAnchor {
        outpoint: OutPoint {
            txid: Txid::from_byte_array(bytes32(anchor, "txid")?),
            vout: anchor["vout"]
                .as_u64()
                .context("native funding vout missing")? as u32,
        },
        output: TxOut {
            value: Amount::from_sat(
                anchor["amount_sats"]
                    .as_u64()
                    .context("native funding amount missing")?,
            ),
            script_pubkey: ScriptBuf::from_bytes(bytes(anchor, "script")?),
        },
    };
    let prefix = crate::initial_exit::InitialRootLeafExitV1::new(
        bytes(&observed, "root")?,
        bytes(&observed, "cpfp_refund")?,
        bytes(&observed, "direct_from_cpfp_refund")?,
    );
    let w = controller
        .wallet
        .as_mut()
        .context("receive journal absent")?;
    ensure!(
        bytes(&observed, "user")? == w.user_key(),
        "native observed joint USER differs"
    );
    let incoming: Value =
        serde_json::from_slice(&fs::read(coin.join("native-prepare.private.json"))?)?;
    let observed_intermediate: Value = serde_json::from_slice(&fs::read(
        coin.join("native-intermediate-observation.json"),
    )?)?;
    let incoming_prefix = evidence::checked(
        &incoming,
        &observed_intermediate,
        &controller.identity.public_key()?,
    )?;
    let backing = w.received_backing(anchor, prefix, &incoming_prefix)?;
    let mut recovery = w.create_origin_recovery(
        &coin.join("wallets/recovery"),
        &backing,
        generate_secret(),
        500,
        suite.schedule(),
    )?;
    let freeze = w.freeze_origin_request(&recovery)?;
    ensure!(
        controller.engine.handle(&freeze).is_err(),
        "native receipt requirement was bypassed"
    );
    *controller
        .admission
        .approved
        .lock()
        .map_err(|_| anyhow::anyhow!("observer lock"))? =
        Some(crate::native_observation::OriginPermit::observe(
            &observation_context(&freeze),
            &recovery.recovery().frozen().context,
            &backing.encode_private()?,
            crate::native_observation::LeafQuery {
                transfer: &transfer,
                leaf: &leaf,
                receiver: &controller.identity.public_key()?,
            },
            cluster.operators.len(),
            native,
        )?);
    controller.engine.handle(&freeze)?;
    let req = recovery.prepare_request()?;
    bind_nonce_reply(&mut recovery, &controller.engine.handle(&req)?)?;
    let issuance = origin_issuance(recovery.recovery(), &suite.verifier()?)?;
    let input = w.origin_prover_toml(&recovery, &suite.verifier()?)?;
    stage("prove_origin")?;
    let proof = suite.prove(
        "deposit",
        &input,
        &issuance.encode()?,
        &coin.join("proofs/origin"),
    )?;
    let issue =
        recovery.issue_request(&issuance, &proof, &suite.verifier()?, &coin.join("scratch"))?;
    let response = controller.engine.handle(&issue)?;
    recovery.complete_issuance(
        issued_response(&response)?,
        &suite.verifier()?,
        &coin.join("scratch"),
    )?;
    drop(recovery);
    stage("finalize")?;
    // Reopen every wallet record and the actual signer before issuing the
    // recovery acknowledgement. Native identity also reopens independently.
    let admission = controller.admission.clone();
    drop(controller);
    let identity = JointIdentityJournal::open(&coin.join("wallets/identity"))?;
    let verifier = suite.receive_verifier(cluster)?;
    let wallet = ReceiveJournal::open(&coin.join("wallets/receive"), &verifier)?;
    let mut recovery = RecoveryJournal::open(&coin.join("wallets/recovery"))?;
    let engine = suite.receive_engine_joint_identity(network, cluster, false, admission)?;
    ensure!(
        engine.handle(&issue)? == response,
        "origin issue exact replay after restart differs"
    );
    let ack = recovery.saved_recovery_acknowledgement(&suite.verifier()?, &coin.join("scratch"))?;
    let acknowledged = engine.handle(&ack)?;
    ensure!(
        acknowledged["accepted"] == true,
        "origin recovery acknowledgement failed"
    );
    ensure!(
        wallet.user_key() == bytes(&observed, "user")?
            && identity.public_key()? == bytes(&observed, "owner")?,
        "reopened native identity/USER differs"
    );
    Ok(Entered {
        _engine: engine,
        _recovery: recovery,
        _wallet: wallet,
        _identity: identity,
        leaf,
        claimed,
        acknowledged,
    })
}
