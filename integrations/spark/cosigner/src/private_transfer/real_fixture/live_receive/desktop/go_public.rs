//! Go public: a share-release exit of one whole coin into this profile's own
//! Public wallet.
//!
//! The network is marked blocked before the exit journal exists and is only
//! unblocked after the recipient's claim, the journal completion and the
//! exact release replay. A failure after the journal exists therefore leaves
//! every profile paused: once the signer has released its share, re-entering
//! Zark or retrying with new bytes is unsafe, so reconciliation is manual.
use super::super::share_release_exit::Release;
use super::super::*;
use super::{
    private::{self, leaf_node, open_received},
    public,
    session::{GO_PUBLIC, GO_PUBLIC_FROM_ENTRY, Session, Steps, refuse},
    store::{Activity, Blocked, CoinRecord, CoinState, Origin, now_ms},
};

pub(super) fn go_public(s: &mut Session, coin: &str) -> Result<()> {
    s.ensure_open()?;
    let unavailable = || refuse("no_coins", "That Incognito coin is not available.");
    let record = s.profile.coin(coin).map_err(|_| unavailable())?;
    if record.state != CoinState::Available {
        return Err(unavailable());
    }
    let steps = if record.origin == Origin::Public {
        &GO_PUBLIC_FROM_ENTRY
    } else {
        &GO_PUBLIC
    };
    let _lock = s.lock(steps)?;
    s.ensure_open()?;
    let record = s.profile.coin(coin)?;
    if record.state != CoinState::Available {
        return Err(unavailable());
    }
    let record = if record.origin == Origin::Public {
        self_handover(s, record, steps)?
    } else {
        record
    };
    exit(s, record, steps)
}

/// Hands an entered coin to this same profile and claims it at once, giving
/// it the recipient material the exit needs. An interruption resumes like any
/// other send/claim; the entered coin is never exited directly.
fn self_handover(s: &mut Session, coin: CoinRecord, steps: &Steps) -> Result<CoinRecord> {
    steps.emit("self_handover")?;
    let me = s.profile.public.clone();
    let dir = s.profile.coin_dir(&coin.id)?;
    private::start_send(s, coin, &me.profile, &me.claim_key, true, steps)?;
    let plan: private::SendPlan = super::store::read_json(&dir.join("send.json"))?;
    let (entries, _) = super::inbox::entries(&s.profile)?;
    let entry = entries
        .iter()
        .find(|e| e.name == plan.entry)
        .context("self-handover offer missing from the inbox")?;
    private::claim(s, entry, steps)
}

fn exit(s: &mut Session, mut coin: CoinRecord, steps: &Steps) -> Result<()> {
    let dir = s.profile.coin_dir(&coin.id)?;
    let leaf = coin.leaf.clone().context("coin leaf missing")?;
    let node = leaf_node(s, &coin)?;
    let recipient = public::wallet(s)?;
    let before = public::balance(s)?;
    ensure!(
        !before.leaves.contains_key(&leaf),
        "the coin's leaf is already in the Public wallet"
    );
    let carol = open_received(s, &coin)?;
    s.network.block(&Blocked {
        reason: "Moving a coin to Public".into(),
        operation: "goPublic".into(),
        profile: s.profile.name.clone(),
        coin: coin.id.clone(),
        at: now_ms(),
    })?;
    coin.state = CoinState::Exiting;
    s.profile.save_coin(&coin)?;
    let row = |coin: &CoinRecord, state: &str| Activity {
        id: format!("go-public-{}", coin.id),
        side: "transition".into(),
        kind: "goPublic".into(),
        label: "Moved to Public".into(),
        amount_sat: coin.amount_sat,
        state: state.into(),
        at: now_ms(),
        counterparty: None,
    };
    s.profile.record(row(&coin, "pending"))?;
    let identity = bytes(&recipient, "identity")?;
    let check = |balance: &Value| -> Result<()> {
        ensure!(
            bytes(balance, "identity")? == identity
                && balance["operators_agreed"] == 3
                && balance["leaves"]
                    .as_array()
                    .is_some_and(|l| l.iter().any(|v| v == leaf.as_str()))
                && balance["available_sats"].as_u64() == Some(before.total + coin.amount_sat),
            "Public balance after the exit differs from the exited leaf"
        );
        Ok(())
    };
    let admission = s.admission();
    let mut engine = s.engine(admission.clone())?;
    let mut native = s.take_native()?;
    let name = s.profile.public_name().to_owned();
    let release = Release {
        directory: dir.join("wallets/share-exit"),
        wire_root: &dir,
        label: "exit",
        send_log: dir.join(format!("sdk-send-{}.private.log", uuid())),
        leaf: &leaf,
        leaf_node: &node,
        name: &name,
        recipient: &recipient,
    };
    let result = share_release_exit::release(
        &s.suite,
        &s.network.root,
        &s.cluster,
        admission,
        &mut engine,
        &carol,
        &mut native,
        &s.docker,
        &release,
        &check,
        &mut |step| steps.emit(step),
    );
    drop(engine);
    drop(carol);
    match result {
        Ok(_) => {
            s.put_native(native);
            coin.state = CoinState::Exited;
            s.profile.save_coin(&coin)?;
            s.network.unblock(&s.profile.name, &coin.id)?;
            s.profile.record(row(&coin, "complete"))
        }
        Err(error) if !release.directory.exists() => {
            // Refused before the exit journal existed: nothing was released.
            coin.state = CoinState::Available;
            s.profile.save_coin(&coin)?;
            s.network.unblock(&s.profile.name, &coin.id)?;
            s.profile.record(row(&coin, "failed"))?;
            Err(error)
        }
        Err(error) => {
            s.network.fail_blocked(
                "A move to Public stopped part-way. Reconcile it manually before using this network again.",
            )?;
            s.profile.record(row(&coin, "interrupted"))?;
            Err(error)
        }
    }
}
