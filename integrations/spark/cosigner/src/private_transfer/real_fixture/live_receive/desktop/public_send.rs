//! Public payments of any amount: from leaves that add up exactly, or from
//! the exact leaf an SSP swap returned. A payment's transfer ID and inbox
//! entry are journaled before its transfer starts, so a resumed payment
//! repeats the same transfer and the same delivery.
use super::super::*;
use super::{
    inbox::{self, Envelope, Kind},
    public::{self, Selection},
    public_swap::{self, Purpose, State, Swap, Wallet},
    session::{PUBLIC_SEND, Session, refuse},
    store::{Activity, Profile, now_ms, read_json, write_json},
};
use anyhow::bail;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const SCHEMA: &str = "zark-public-send-v1";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum PaymentState {
    /// Journaled; the transfer may not have started.
    Prepared,
    /// The operators accepted the transfer.
    Sent,
    /// The recipient's inbox holds the notification.
    Delivered,
    /// The transfer expired before the operators saw it; nothing moved.
    Abandoned,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Payment {
    pub schema: String,
    pub transfer: String,
    /// Recipient profile and its Public identity (hex).
    pub to: String,
    pub receiver: String,
    pub amount_sat: u64,
    pub leaves: BTreeMap<String, u64>,
    pub entry: String,
    pub state: PaymentState,
    pub created_at: u64,
}

fn path(profile: &Profile, transfer: &str, create: bool) -> Result<PathBuf> {
    ensure!(public_swap::canonical_uuid(transfer), "payment transfer id");
    Ok(public_swap::journal_directory(profile, "sends", create)?.join(format!("{transfer}.json")))
}

fn save(profile: &Profile, payment: &Payment) -> Result<()> {
    write_json(&path(profile, &payment.transfer, true)?, payment)
}

pub(super) fn payments(profile: &Profile) -> Result<Vec<Payment>> {
    let mut out = Vec::new();
    let directory = public_swap::journal_directory(profile, "sends", false)?;
    if !directory.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            let payment: Payment = read_json(&path)?;
            ensure!(
                payment.schema == SCHEMA
                    && path.file_stem().is_some_and(|s| *s == *payment.transfer),
                "public payment record"
            );
            out.push(payment);
        }
    }
    out.sort_by_key(|p| p.created_at);
    Ok(out)
}

pub(super) fn unsettled(profile: &Profile) -> Result<bool> {
    Ok(payments(profile)?
        .iter()
        .any(|p| matches!(p.state, PaymentState::Prepared | PaymentState::Sent)))
}

fn activity(transfer: &str, amount: u64, to: &str, state: &str) -> Activity {
    Activity {
        id: format!("public-sent-{transfer}"),
        side: "public".into(),
        kind: "publicSent".into(),
        label: "Sent payment".into(),
        amount_sat: amount,
        state: state.into(),
        at: now_ms(),
        counterparty: Some(to.into()),
    }
}

/// One network lock covers selection, any swap, the transfer and delivery, so
/// no other window can spend the selected or swapped leaves in between.
pub(super) fn send(s: &mut Session, address: &str, amount: u64) -> Result<()> {
    let receiver = public::parse_address(address)?;
    let key = hex::encode(&receiver);
    let to = super::recipient(&s.network.profiles()?, &s.profile.name, |p| {
        p.public_identity.as_deref() == Some(key.as_str())
    })?;
    public::payment_amount(amount)?;
    s.ensure_open()?;
    let _lock = s.lock(&PUBLIC_SEND)?;
    s.ensure_open()?;
    public_swap::settle(s)?;
    let balance = public::balance(s)?;
    let transfer = uuid();
    let entry = inbox::entry_name();
    let inputs = |ids: Vec<String>| -> BTreeMap<String, u64> {
        ids.into_iter()
            .map(|id| {
                let sats = balance.leaves[&id];
                (id, sats)
            })
            .collect()
    };
    match balance.select(amount)? {
        Selection::Exact(ids) => {
            let payment = Payment {
                schema: SCHEMA.into(),
                transfer: transfer.clone(),
                to: to.profile.clone(),
                receiver: hex::encode(&receiver),
                amount_sat: amount,
                leaves: inputs(ids),
                entry,
                state: PaymentState::Prepared,
                created_at: now_ms(),
            };
            save(&s.profile, &payment)?;
            s.profile
                .record(activity(&transfer, amount, &to.profile, "pending"))?;
            continue_payment(s, payment)
        }
        Selection::Swap { inputs: ids, .. } => {
            let swap = Swap::new(
                inputs(ids),
                vec![amount],
                Purpose::Send {
                    to: to.profile.clone(),
                    receiver: hex::encode(&receiver),
                    amount_sat: amount,
                    transfer: transfer.clone(),
                    entry,
                },
            )?;
            public_swap::save(&s.profile, &swap)?;
            s.profile
                .record(activity(&transfer, amount, &to.profile, "pending"))?;
            let swap = public_swap::advance(s, swap, true, &PUBLIC_SEND)?;
            finish_swap(s, swap)
        }
    }
}

/// Continues a payment whose swap stopped: a claimed swap's exact leaf
/// becomes the journaled payment; a swap that did not happen sends nothing.
pub(super) fn finish_swap(w: &mut impl Wallet, mut swap: Swap) -> Result<()> {
    let Purpose::Send {
        to,
        receiver,
        amount_sat,
        transfer,
        entry,
    } = swap.purpose.clone()
    else {
        bail!("not a payment swap");
    };
    match swap.state {
        State::Claimed => {
            let leaf = public_swap::received_leaf(&swap, amount_sat)?;
            // The payment journal exists before the swap is marked consumed,
            // so a crash in between resumes the same payment.
            if !path(w.profile(), &transfer, false)?.exists() {
                save(
                    w.profile(),
                    &Payment {
                        schema: SCHEMA.into(),
                        transfer: transfer.clone(),
                        to,
                        receiver,
                        amount_sat,
                        leaves: [(leaf, amount_sat)].into(),
                        entry,
                        state: PaymentState::Prepared,
                        created_at: now_ms(),
                    },
                )?;
            }
            swap.state = State::Consumed;
            public_swap::save(w.profile(), &swap)?;
            let payment = read_json(&path(w.profile(), &transfer, false)?)?;
            continue_payment(w, payment)
        }
        State::Abandoned | State::Failed => {
            w.profile()
                .record(activity(&transfer, amount_sat, &to, "failed"))?;
            swap.settled = true;
            public_swap::save(w.profile(), &swap)?;
            Err(if swap.state == State::Abandoned {
                refuse(
                    "swap_failed",
                    "The SSP did not make change, so nothing was sent. Your Public balance is unchanged.",
                )
            } else {
                refuse(
                    "swap_mismatch",
                    "The SSP returned different amounts than requested, so nothing was sent. What it returned is in Public.",
                )
            })
        }
        state => bail!("payment swap is still {state:?}"),
    }
}

/// Safe to repeat after any interruption: the fixture answers a repeated
/// transfer ID with the existing transfer, and delivery reuses the entry name.
pub(super) fn continue_payment(w: &mut impl Wallet, mut payment: Payment) -> Result<()> {
    loop {
        payment.state = match payment.state {
            PaymentState::Prepared => {
                PUBLIC_SEND.emit("transfer")?;
                let sent = w.native(json!({"op":"public_transfer","directory":NATIVE,
                    "recipient":w.profile().public_name(),"receiver":hex::decode(&payment.receiver)?,
                    "transfer_id":payment.transfer,"leaf_ids":payment.leaves.keys().collect::<Vec<_>>()}))?;
                ensure!(
                    sent["transfer_id"] == payment.transfer.as_str(),
                    "payment transfer differs"
                );
                if sent["status"] == "absent" {
                    payment.state = PaymentState::Abandoned;
                    save(w.profile(), &payment)?;
                    w.profile().record(activity(
                        &payment.transfer,
                        payment.amount_sat,
                        &payment.to,
                        "failed",
                    ))?;
                    return Err(refuse(
                        "send_failed",
                        "The payment expired before Spark accepted it. Nothing was sent.",
                    ));
                }
                let leaves: BTreeMap<String, u64> =
                    serde_json::from_value(sent["leaf_sats"].clone())
                        .context("sent leaf values")?;
                ensure!(
                    sent["status"] == "sent"
                        && leaves == payment.leaves
                        && sent["amount_sats"] == payment.amount_sat,
                    "sent Public leaves differ from the payment"
                );
                PaymentState::Sent
            }
            PaymentState::Sent => {
                PUBLIC_SEND.emit("deliver")?;
                let to = w
                    .network()
                    .profiles()?
                    .into_iter()
                    .find(|p| {
                        p.profile == payment.to
                            && p.public_identity.as_deref() == Some(payment.receiver.as_str())
                    })
                    .context("payment recipient profile changed")?;
                inbox::deliver(
                    &w.network().root.join("profiles"),
                    &to,
                    &payment.entry,
                    &Envelope {
                        schema: inbox::ENVELOPE_V2.into(),
                        kind: Kind::Public,
                        id: payment.transfer.clone(),
                        from: w.profile().name.clone(),
                        amount_sat: payment.amount_sat,
                        offer: None,
                        leaf: payment
                            .leaves
                            .keys()
                            .next()
                            .context("payment leaves")?
                            .clone(),
                        leaf_node: None,
                        transfer: Some(payment.transfer.clone()),
                        leaves: Some(payment.leaves.clone()),
                    },
                )?;
                w.profile().record(activity(
                    &payment.transfer,
                    payment.amount_sat,
                    &payment.to,
                    "complete",
                ))?;
                PaymentState::Delivered
            }
            PaymentState::Delivered | PaymentState::Abandoned => return Ok(()),
        };
        save(w.profile(), &payment)?;
    }
}

pub(super) fn resume(s: &mut Session) -> Result<()> {
    for payment in payments(&s.profile)? {
        if matches!(payment.state, PaymentState::Prepared | PaymentState::Sent)
            && let Err(error) = continue_payment(s, payment)
        {
            s.log_error("public payment", &error);
        }
    }
    Ok(())
}
