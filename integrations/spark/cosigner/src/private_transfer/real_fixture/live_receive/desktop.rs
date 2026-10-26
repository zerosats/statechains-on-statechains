//! Blinded desktop wallet backend on the live regtest Spark path: ECDSA-2P
//! joint identity, additive receive, real proofs and share-release exit.
//!
//! One process per window and profile. All profiles of a network share one
//! in-process signer database, opened only under the network lock. Requests
//! and replies use the synthetic desktop worker's framing. Test-only
//! orchestration.
#[path = "desktop/atm.rs"]
mod atm;
#[path = "desktop/exit_tree.rs"]
mod exit_tree;
#[path = "desktop/go_public.rs"]
mod go_public;
#[path = "desktop/inbox.rs"]
mod inbox;
#[path = "desktop/private.rs"]
mod private;
#[path = "desktop/public.rs"]
mod public;
#[path = "desktop/public_send.rs"]
mod public_send;
#[path = "desktop/public_swap.rs"]
mod public_swap;
#[cfg(test)]
#[path = "desktop/public_tests.rs"]
mod public_tests;
#[path = "desktop/session.rs"]
mod session;
#[path = "desktop/store.rs"]
mod store;
#[cfg(test)]
#[path = "desktop/tests.rs"]
mod tests;
#[path = "desktop/view.rs"]
mod view;

use super::*;
use serde::Deserialize;
use session::{PRIVATE_SEND, Refusal, Session, emit, refuse};
use store::{CoinState, Network, NetworkConfig, Profile, PublicProfile};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: String,
    action: String,
    #[serde(default)]
    args: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Amount {
    amount_sat: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Payment {
    address: String,
    amount_sat: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoinPayment {
    address: String,
    coins: Vec<String>,
}
/// Public previews name an amount; Incognito previews name the picked coins.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviewArgs {
    side: String,
    address: String,
    #[serde(default)]
    amount_sat: Option<u64>,
    #[serde(default)]
    coins: Option<Vec<String>>,
}
/// Exactly one of an existing root bill or a denomination to withdraw.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GoPrivate {
    #[serde(default)]
    leaf: Option<String>,
    #[serde(default)]
    amount_sat: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Coin {
    coin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

fn args<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T> {
    let value = if value.is_null() {
        json!({})
    } else {
        value.clone()
    };
    serde_json::from_value(value).map_err(|_| refuse("failed", "Invalid Spark request"))
}

fn env_name(variable: &str, fallback: &str) -> Result<String> {
    let value = std::env::var(variable).unwrap_or_else(|_| fallback.into());
    ensure!(store::valid_name(&value), "invalid {variable}");
    Ok(value)
}

/// The other local profile a payment would reach. Preview refuses exactly
/// what the send would, so Confirm payment is never offered for a refused send.
fn recipient(
    profiles: &[PublicProfile],
    own: &str,
    is_to: impl Fn(&PublicProfile) -> bool,
) -> Result<PublicProfile> {
    let to = profiles.iter().find(|p| is_to(p)).ok_or_else(|| {
        refuse(
            "unknown_recipient",
            "No wallet on this regtest network uses that address.",
        )
    })?;
    if to.profile == own {
        return Err(refuse("invalid_address", "Use another wallet's address."));
    }
    Ok(to.clone())
}

fn preview(s: &mut Session, a: PreviewArgs) -> Result<Value> {
    let profiles = s.network.profiles()?;
    let own = s.profile.name.clone();
    let (amount, inputs, recipient, expected, change) =
        match (a.side.as_str(), a.amount_sat, a.coins) {
            ("public", Some(amount), None) => {
                let key = hex::encode(public::parse_address(&a.address)?);
                let to = recipient(&profiles, &own, |p| {
                    p.public_identity.as_deref() == Some(key.as_str())
                })?;
                public::payment_amount(amount)?;
                let (inputs, change) = match public::balance(s)?.select(amount)? {
                    public::Selection::Exact(inputs) => (inputs, 0),
                    public::Selection::Swap { inputs, change } => (inputs, change),
                };
                let expected = session::PUBLIC_SEND.expected_ms
                    + if change > 0 {
                        public_swap::EXPECTED_MS
                    } else {
                        0
                    };
                (amount, inputs, to.profile, expected, change)
            }
            ("incognito", None, Some(ids)) => {
                let key = hex::encode(private::parse_address(&a.address)?);
                let to = recipient(&profiles, &own, |p| p.claim_key == key)?;
                let coins = private::chosen_coins(&s.profile, &ids)?;
                let amount = coins.iter().map(|c| c.amount_sat).sum();
                let expected =
                    coins.len() as u64 * PRIVATE_SEND.expected_ms + session::CLAIM.expected_ms;
                (amount, ids, to.profile, expected, 0)
            }
            _ => return Err(refuse("failed", "Invalid Spark request")),
        };
    // `swap`: the SSP makes change first; `changeSat` returns to Public.
    Ok(
        json!({"side":a.side,"amountSat":amount,"changeSat":change,"feeSat":0,"swap":change > 0,
        "inputs":inputs,"recipient":recipient,"expectedMs":expected}),
    )
}

/// Idle work for this profile, only when the network lock is free right now:
/// resume interrupted sends, settle crashed entries, claim incoming offers.
fn background(s: &mut Session) -> Result<()> {
    if s.network.blocked()?.is_some() {
        return Ok(());
    }
    let Some(_lock) = s.network.lock()? else {
        return Ok(());
    };
    for mut coin in s.profile.coins()? {
        let outcome = match coin.state {
            CoinState::Sending => private::continue_send(s, coin.clone(), &PRIVATE_SEND),
            CoinState::Entering => {
                // This profile is single-process: an idle Entering coin crashed.
                let dir = s.profile.coin_dir(&coin.id)?;
                coin.state = if dir.join("ordinary-sender.json").exists() {
                    CoinState::Interrupted
                } else {
                    CoinState::Abandoned
                };
                s.profile.save_coin(&coin)
            }
            _ => Ok(()),
        };
        if let Err(error) = outcome {
            s.log_error("resume", &error);
        }
    }
    if let Err(error) = public_swap::resume(s) {
        s.log_error("resume", &error);
    }
    let (entries, _) = inbox::entries(&s.profile)?;
    for entry in &entries {
        let outcome = match entry.envelope.kind {
            inbox::Kind::Private => private::auto_claim(s, entry).map(|_| ()),
            inbox::Kind::Public => public::claim(s, entry),
        };
        if let Err(error) = outcome {
            s.log_error("claim", &error);
        }
    }
    Ok(())
}

fn perform(s: &mut Session, request: &Request) -> Result<Option<Value>> {
    match request.action.as_str() {
        "refresh" => {
            args::<Empty>(&request.args)?;
            background(s)?;
            Ok(None)
        }
        "publicDeposit" => {
            public::deposit(s, args::<Amount>(&request.args)?.amount_sat).map(|_| None)
        }
        "goPrivate" => {
            let cash = match args::<GoPrivate>(&request.args)? {
                GoPrivate {
                    leaf: Some(leaf),
                    amount_sat: None,
                } => atm::Cash::Leaf(leaf),
                GoPrivate {
                    leaf: None,
                    amount_sat: Some(amount),
                } => atm::Cash::Amount(amount),
                _ => return Err(refuse("failed", "Invalid Spark request")),
            };
            atm::go_private(s, cash).map(|_| None)
        }
        "preview" => preview(s, args(&request.args)?).map(Some),
        "publicSend" => {
            let a: Payment = args(&request.args)?;
            public_send::send(s, &a.address, a.amount_sat).map(|_| None)
        }
        "privateSend" => {
            let a: CoinPayment = args(&request.args)?;
            private::send(s, &a.address, &a.coins).map(|_| None)
        }
        "goPublic" => go_public::go_public(s, &args::<Coin>(&request.args)?.coin).map(|_| None),
        _ => Err(refuse("failed", "Invalid Spark request")),
    }
}

fn changes_public_leaves(action: &str) -> bool {
    matches!(
        action,
        "refresh" | "publicDeposit" | "goPrivate" | "publicSend" | "goPublic"
    )
}

fn reply(s: &mut Session, request: &Request) -> Result<Value> {
    let outcome = perform(s, request);
    // Capture the leaves after the operation, including one that failed after
    // some of them moved. A refused read leaves the previous file in place.
    if changes_public_leaves(&request.action) {
        exit_tree::remember(s);
    }
    let mut reply = json!({"snapshot": view::snapshot(s)?, "progress": ""});
    match outcome {
        Ok(Some(preview)) => reply["preview"] = preview,
        Ok(None) => {}
        Err(error) => {
            s.log_error(&request.action, &error);
            let (code, message) = match error.downcast_ref::<Refusal>() {
                Some(r) => (r.code, r.message.clone()),
                None if s.network.blocked()?.is_some() => (
                    "blocked",
                    "An operation needs reconciliation. New operations are paused on this network."
                        .into(),
                ),
                None => (
                    "failed",
                    "The operation did not complete. Your last completed balances are retained."
                        .into(),
                ),
            };
            reply["error"] = json!(message);
            reply["errorCode"] = json!(code);
        }
    }
    Ok(reply)
}

#[test]
#[ignore = "blinded desktop wallet on the live regtest Spark path; requires running acceptance services, rebuilt native helpers and pinned proof suites"]
fn serve_blinded_wallet_regtest() -> Result<()> {
    use std::io::BufRead;
    ensure!(
        std::env::var("ZARK_SPARK_DESKTOP").as_deref() == Ok("blinded-regtest"),
        "explicit blinded regtest desktop required"
    );
    let network_name = env_name("ZARK_SPARK_NETWORK", "demo")?;
    let profile_name = env_name("ZARK_PROFILE", "wallet")?;
    let docker =
        PathBuf::from(std::env::var_os("ZARK_SPARK_DOCKER").context("set ZARK_SPARK_DOCKER")?);
    ensure!(docker.is_absolute(), "ZARK_SPARK_DOCKER must be absolute");
    let mut suite = Suite::load()?;
    // Fixed before the first engine opens so every signed head agrees.
    suite.share_release = true;
    let cluster = acceptance_cluster()?;
    let config = NetworkConfig::current(&cluster.digest()?)?;
    let network = Network::open(&Network::parent(), &network_name, &mut suite, &config)?;
    let profile = Profile::open(&network, &profile_name)?;
    let mut s = Session::new(suite, cluster, docker, network, profile);
    // The saved tree is this window's offline copy. A failed read keeps the
    // previous file and still opens the window.
    exit_tree::remember(&mut s);
    emit(&json!({"snapshot": view::snapshot(&mut s)?}))?;
    let mut input = std::io::stdin().lock();
    loop {
        let mut bytes = Vec::new();
        let count = std::io::Read::take(&mut input, 16_385).read_until(b'\n', &mut bytes)?;
        if count == 0 {
            break;
        }
        ensure!(
            count <= 16_384 && bytes.last() == Some(&b'\n'),
            "Invalid request framing"
        );
        let request: Request = serde_json::from_slice(&bytes)?;
        ensure!(
            !request.id.is_empty() && request.id.len() <= 128,
            "Invalid request id"
        );
        let mut value = reply(&mut s, &request)?;
        value["id"] = json!(request.id);
        emit(&value)?;
    }
    Ok(())
}
