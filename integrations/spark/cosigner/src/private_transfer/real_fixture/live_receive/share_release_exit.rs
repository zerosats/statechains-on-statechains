//! Terminal exit by share release from the final private owner. The signer
//! releases x_s, the wallet completes p and a stock single-key SDK send moves
//! the leaf to a fresh ordinary Spark wallet. No Zark proof is involved.
use super::exit::{timed, verify_completion};
use super::*;
use crate::share_exit::{ChainView, SendPlan, ShareExit, TxStatus};
use bitcoin::hashes::Hash;
use std::cell::RefCell;
use zark_protocol::spark_wire::{Head, HeadPhase, SignedHead};

pub(super) trait NativeCall {
    fn call(&mut self, request: &Value) -> Result<Value>;
}
impl NativeCall for Pipe {
    fn call(&mut self, request: &Value) -> Result<Value> {
        self.call_native(request)
    }
}

/// Bitcoin node view through the native fixture. A failed call or any reply
/// that is not an exact status for the requested txid is an error, never
/// `Absent`.
struct NativeChain<'a, C: NativeCall>(RefCell<&'a mut C>);
impl<C: NativeCall> ChainView for NativeChain<'_, C> {
    fn status(&self, txid: &[u8; 32]) -> Result<TxStatus> {
        let txid = bitcoin::Txid::from_byte_array(*txid).to_string();
        let reply = self
            .0
            .try_borrow_mut()?
            .call(&json!({"op":"chain_status","directory":NATIVE,"txid":txid}))?;
        ensure!(
            reply["txid"] == txid.as_str() && reply["txindex_synced"] == true,
            "chain status reply differs from the request"
        );
        match reply["status"].as_str() {
            Some("absent") => Ok(TxStatus::Absent),
            Some("mempool") => Ok(TxStatus::Mempool),
            Some("confirmed") => Ok(TxStatus::Confirmed),
            _ => anyhow::bail!("unknown chain status"),
        }
    }
}

pub(super) trait DriverPort {
    fn request(&mut self) -> Result<Value>;
    fn reply(&mut self, value: &Value) -> Result<()>;
}
impl DriverPort for Pipe {
    fn request(&mut self) -> Result<Value> {
        self.next(None)
    }
    fn reply(&mut self, value: &Value) -> Result<()> {
        self.send(value)
    }
}

/// Serves exactly `exit_send` then `seal_leaf_key` and returns the driver's
/// `sent` line. A refusal is reported to the driver before the error returns,
/// so the process exits instead of waiting on the port.
fn drive(port: &mut impl DriverPort, plan: &SendPlan, leaf: &Value) -> Result<Value> {
    for expected in ["exit_send", "seal_leaf_key"] {
        let request = port.request()?;
        let answer = if request["op"] == expected {
            plan.answer(&request, leaf)
        } else {
            Err(anyhow::anyhow!("unexpected send driver request"))
        };
        match answer {
            Ok(value) => port.reply(&json!({"ok":true,"value":value}))?,
            Err(error) => {
                port.reply(&json!({"ok":false}))?;
                return Err(error.context("send driver request refused"));
            }
        }
    }
    let sent = port.request()?;
    ensure!(
        sent["op"] == "sent" && sent["transfer_id"] == plan.transfer_uuid().as_str(),
        "SDK send result differs from the durable transfer"
    );
    Ok(sent)
}

fn claimed(received: &Value, recipient: &Value, leaf: &str) -> Result<()> {
    ensure!(
        received["operators_completed"] == 3
            && received["leaf_id"] == leaf
            && bytes(received, "owner")? == bytes(recipient, "identity")?
            && bytes(received, "user")? == bytes(recipient, "user")?,
        "ordinary recipient claim was not observed"
    );
    Ok(())
}

/// The fresh receiver must hold exactly the exited leaf on every operator.
fn receiver_balance(value: &Value, receiver: &[u8], leaf: &str) -> Result<u64> {
    ensure!(
        bytes(value, "identity")? == receiver && value["operators_agreed"] == 3,
        "receiver balance identity or operator quorum"
    );
    let leaves = value["leaves"]
        .as_array()
        .context("receiver balance leaves")?;
    ensure!(
        leaves.len() == 1 && leaves[0] == leaf,
        "fresh receiver holds other leaves"
    );
    value["available_sats"]
        .as_u64()
        .context("receiver balance amount")
}

fn head(suite: &Suite, engine: &Engine, carol: &Received) -> Result<Head> {
    let request = carol
        .material
        .owner_head_request(&carol.snapshot.certificate, carol.snapshot.revision)?;
    let signed: SignedHead = serde_json::from_value(engine.handle(&request)?["head"].clone())?;
    Ok(signed.verify(&request, &suite.config.origin_key)?.clone())
}

fn releasable(head: &Head) -> Result<()> {
    ensure!(
        head.phase == HeadPhase::Available && head.share_release && head.locked_operation.is_none(),
        "signed head does not offer share release for an idle coin"
    );
    Ok(())
}

fn terminal(before: &Head, after: &Head) -> Result<()> {
    ensure!(
        after.phase == HeadPhase::Exited
            && after.revision == before.revision + 1
            && after.locked_operation.is_none()
            && (after.coin, after.state) == (before.coin, before.state),
        "terminal head after reopen differs"
    );
    Ok(())
}

/// Where one share-release exit keeps its journal and transcripts, and the
/// ordinary Spark wallet (a named native recipient) that receives the leaf.
pub(super) struct Release<'a> {
    pub directory: PathBuf,
    pub wire_root: &'a Path,
    pub label: &'a str,
    pub send_log: PathBuf,
    pub leaf: &'a str,
    pub leaf_node: &'a Value,
    pub name: &'a str,
    pub recipient: &'a Value,
}

/// Release, verify, gate on chain, send through the stock SDK and observe the
/// recipient's claim. Nothing may re-enter Zark once the journal exists: any
/// error from here on leaves the coin for reconciliation, never for retry.
/// `check_balance` runs on the recipient's balance before the journal is
/// completed. `network` is the signer directory.
#[allow(clippy::too_many_arguments)]
pub(super) fn release(
    suite: &Suite,
    network: &Path,
    cluster: &ClaimCluster,
    admission: Arc<ObservedAdmission>,
    engine: &mut Engine,
    carol: &Received,
    native: &mut Pipe,
    docker: &Path,
    r: &Release<'_>,
    check_balance: &dyn Fn(&Value) -> Result<()>,
    stage: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let (directory, leaf, name, recipient) = (&r.directory, r.leaf, r.name, r.recipient);
    let receiver = bytes(recipient, "identity")?;
    stage("head")?;
    let before = timed("share_head", || head(suite, engine, carol))?;
    releasable(&before)?;
    let coin = carol.material.share_exit_coin(
        &carol.snapshot.recovery,
        &carol.snapshot.certificate,
        &receiver,
    )?;
    ensure!(
        coin.state == before.state && coin.capability == before.capability,
        "signed head names another coin state or owner"
    );
    let server = json!(coin.server);
    let mut exit = ShareExit::create(directory, coin)?;
    let request = carol
        .material
        .share_release_request(&mut exit, before.revision)?;
    drop(exit);
    // A crash after journaling must resend these exact bytes.
    let mut exit = ShareExit::open(directory)?;
    ensure!(
        exit.pending()?.map(|r| r.encode()).transpose()? == Some(request.encode()?),
        "journaled share release request changed on reopen"
    );
    stage("release")?;
    let response = timed("share_release", || {
        send(
            engine,
            r.wire_root,
            &format!("{}-share-release", r.label),
            &request,
        )
    })?;
    // p is stored only after it completes P with the certified X_s; nothing
    // reaches Spark before this point.
    timed("share_verify", || {
        ensure!(
            response["server"] == server,
            "release names another server point"
        );
        carol.material.accept_share_release(&mut exit, &response)
    })?;
    let native_before =
        native.call_native(&json!({"op":"native_snapshot","directory":NATIVE,"leaf_id":leaf}))?;
    // Immediately before the Spark send, after which nothing may re-enter Zark.
    stage("chain_gate")?;
    let plan = timed("chain_gate", || {
        exit.prepare_send(&NativeChain(RefCell::new(&mut *native)))
    })?;
    stage("send")?;
    timed("sdk_send", || {
        let mut driver = Pipe::sdk_send(docker, &r.send_log)?;
        drive(&mut driver, &plan, r.leaf_node)?;
        driver.completed()
    })?;
    let (transfer, transfer_id) = (plan.transfer_uuid(), plan.transfer_id);
    drop(plan);
    stage("claim")?;
    let received = timed("receiver_claim", || {
        native.call_native(
            &json!({"op":"exit_claim","directory":NATIVE,"recipient":name,
            "transfer_id":transfer,"leaf_id":leaf}),
        )
    })?;
    claimed(&received, recipient, leaf)?;
    let native_after =
        native.call_native(&json!({"op":"native_snapshot","directory":NATIVE,"leaf_id":leaf}))?;
    verify_completion(
        &native_before,
        &native_after,
        &received,
        &receiver,
        recipient,
    )?;
    stage("finalize")?;
    let balance = timed("balance", || {
        native.call_native(&json!({"op":"exit_balance","directory":NATIVE,"recipient":name}))
    })?;
    check_balance(&balance)?;
    exit.complete(&transfer_id)?;
    drop(exit);

    let after = timed("reopen_replay", || {
        *engine = suite.receive_engine_joint_identity(network, cluster, false, admission)?;
        ensure!(
            engine.handle(&request)? == response,
            "share release replay changed after reopen"
        );
        head(suite, engine, carol)
    })?;
    terminal(&before, &after)
}

#[cfg(test)]
#[path = "share_release_exit/tests.rs"]
mod tests;
