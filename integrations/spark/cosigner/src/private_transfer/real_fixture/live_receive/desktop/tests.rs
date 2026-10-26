use super::{
    inbox::{self, Envelope, Kind},
    private::{self, claim_coin_id},
    public,
    session::Refusal,
    store::{Blocked, CoinState, Network, NetworkConfig, Origin, Profile, PublicProfile},
    view,
};
use anyhow::Result;
use serde_json::{Value, json};
use std::path::PathBuf;
use zark_protocol::random32;

pub(super) fn parent() -> Result<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../work/zark-spark/blinded-desktop-tests")
        .join(hex::encode(random32()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn config(cluster: &str) -> NetworkConfig {
    NetworkConfig {
        schema: "zark-blinded-desktop-network-v1".into(),
        ecdsa_2p: true,
        additive_receive: true,
        share_release: true,
        suites: vec![Some("aa".into()), Some("bb".into()), None, None],
        cluster: cluster.into(),
    }
}

pub(super) fn network(parent: &std::path::Path) -> Result<Network> {
    Network::open_dir(parent, "demo", &config("c1"), &mut |_| Ok(()))
}

pub(super) fn code(error: &anyhow::Error) -> Option<&'static str> {
    error.downcast_ref::<Refusal>().map(|r| r.code)
}

#[test]
fn network_refuses_configuration_drift() -> Result<()> {
    let parent = parent()?;
    network(&parent)?;
    // Same configuration reopens; any pinned difference is refused.
    network(&parent)?;
    assert!(Network::open_dir(&parent, "demo", &config("c2"), &mut |_| Ok(())).is_err());
    let mut other = config("c1");
    other.suites[1] = Some("changed".into());
    assert!(Network::open_dir(&parent, "demo", &other, &mut |_| Ok(())).is_err());
    let mut flags = config("c1");
    flags.share_release = false;
    assert!(Network::open_dir(&parent, "demo", &flags, &mut |_| Ok(())).is_err());
    // A failed initialisation leaves no network behind.
    assert!(
        Network::open_dir(&parent, "fresh", &config("c1"), &mut |_| anyhow::bail!(
            "no"
        ))
        .is_err()
    );
    assert!(!parent.join("fresh").exists());
    for bad in ["", "Demo", "1net", "../x", "a/b"] {
        assert!(Network::open_dir(&parent, bad, &config("c1"), &mut |_| Ok(())).is_err());
    }
    Ok(())
}

#[test]
fn concurrent_creation_adopts_the_winner_and_keeps_its_pin() -> Result<()> {
    let first = parent()?;
    let winner_parent = first.clone();
    Network::open_dir(&first, "demo", &config("c1"), &mut |staging| {
        std::fs::write(staging.join("identity"), b"loser")?;
        network(&winner_parent)?;
        Ok(())
    })?;
    let names: Vec<_> = std::fs::read_dir(&first)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<Result<_, _>>()?;
    assert_eq!(names, ["demo"], "loser's staging directory remains");
    assert!(
        !first.join("demo/identity").exists(),
        "loser's identity adopted"
    );

    let other = parent()?;
    let winner_parent = other.clone();
    let raced = Network::open_dir(&other, "demo", &config("c2"), &mut |_| {
        network(&winner_parent)?;
        Ok(())
    });
    assert!(raced.is_err(), "winner with another configuration adopted");
    Ok(())
}

#[test]
fn profile_is_single_window_and_keeps_its_addresses() -> Result<()> {
    let parent = parent()?;
    let net = network(&parent)?;
    let alice = Profile::open(&net, "alice")?;
    assert!(
        Profile::open(&net, "alice").is_err(),
        "second window opened"
    );
    let claim = alice.public.claim_key.clone();
    let public = alice.public_name().to_owned();
    drop(alice);
    let mut alice = Profile::open(&net, "alice")?;
    assert_eq!(alice.public.claim_key, claim);
    assert_eq!(alice.public_name(), public);
    alice.publish_public_identity(&[2; 33])?;
    assert!(alice.publish_public_identity(&[3; 33]).is_err());
    let bob = Profile::open(&net, "bob")?;
    assert_ne!(bob.public.claim_key, claim);
    let published = net.profiles()?;
    assert_eq!(published.len(), 2);
    assert!(
        published
            .iter()
            .any(|p| p.public_identity.as_deref() == Some(&"02".repeat(33)[..]))
    );
    // A published record that no longer matches the secrets is refused.
    drop(bob);
    let path = net.root.join("profiles/bob/public.json");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    record["claim_key"] = json!(claim);
    std::fs::write(&path, serde_json::to_vec(&record)?)?;
    assert!(Profile::open(&net, "bob").is_err());
    Ok(())
}

#[test]
fn network_lock_is_exclusive_across_handles() -> Result<()> {
    let parent = parent()?;
    let net = network(&parent)?;
    let again = network(&parent)?;
    let held = net.lock()?.expect("lock");
    assert!(again.lock()?.is_none());
    drop(held);
    assert!(again.lock()?.is_some());
    Ok(())
}

#[test]
fn blocked_exit_pauses_until_its_own_completion() -> Result<()> {
    let parent = parent()?;
    let net = network(&parent)?;
    let blocked = Blocked {
        reason: "Moving a coin to Public".into(),
        operation: "goPublic".into(),
        profile: "carol".into(),
        coin: "00".repeat(16),
        at: 1,
    };
    net.block(&blocked)?;
    assert!(net.block(&blocked).is_err(), "second exit started");
    assert!(net.unblock("bob", &blocked.coin).is_err());
    assert!(net.unblock("carol", &"11".repeat(16)).is_err());
    net.fail_blocked("stopped part-way")?;
    // The block survives a restart with the failure recorded.
    let reopened = network(&parent)?;
    let saved = reopened.blocked()?.expect("still blocked");
    assert_eq!(saved.reason, "stopped part-way");
    assert_eq!(saved.profile, "carol");
    reopened.unblock("carol", &blocked.coin)?;
    assert!(net.blocked()?.is_none());
    Ok(())
}

pub(super) fn envelope(kind: Kind, from: &str) -> Envelope {
    Envelope {
        schema: "zark-blinded-desktop-envelope-v1".into(),
        kind,
        id: "c0".repeat(16),
        from: from.into(),
        amount_sat: 10_000,
        offer: (kind == Kind::Private).then(|| vec![1, 2, 3]),
        leaf: "4a1b2c3d-0000-4000-8000-000000000000".into(),
        leaf_node: Some(json!({"id":"4a1b2c3d-0000-4000-8000-000000000000"})),
        transfer: (kind == Kind::Public).then(|| "5d6e7f80-0000-4000-8000-000000000000".into()),
        leaves: None,
    }
}

#[test]
fn inbox_entries_open_only_for_their_profile() -> Result<()> {
    let parent = parent()?;
    let net = network(&parent)?;
    let alice = Profile::open(&net, "alice")?;
    let bob = Profile::open(&net, "bob")?;
    let profiles = net.root.join("profiles");
    let name = inbox::entry_name();
    inbox::deliver(
        &profiles,
        &bob.public,
        &name,
        &envelope(Kind::Private, "alice"),
    )?;
    // Redelivery under the same name replaces instead of duplicating.
    inbox::deliver(
        &profiles,
        &bob.public,
        &name,
        &envelope(Kind::Private, "alice"),
    )?;
    let (entries, unreadable) = inbox::entries(&bob)?;
    assert_eq!((entries.len(), unreadable), (1, 0));
    assert_eq!(entries[0].envelope.offer.as_deref(), Some(&[1u8, 2, 3][..]));
    let sealed = std::fs::read(profiles.join(format!("bob/inbox/{name}.sealed")))?;
    assert!(inbox::open(&alice.inbox_secret(), &sealed).is_err());
    assert!(
        !sealed.windows(5).any(|w| w == b"alice"),
        "sender name in clear"
    );
    let mut tampered = sealed.clone();
    *tampered.last_mut().expect("bytes") ^= 1;
    assert!(inbox::open(&bob.inbox_secret(), &tampered).is_err());
    // An unreadable entry is reported and retained, never deleted.
    std::fs::write(
        profiles.join(format!("bob/inbox/{}.sealed", "ab".repeat(32))),
        &tampered,
    )?;
    let (entries, unreadable) = inbox::entries(&bob)?;
    assert_eq!((entries.len(), unreadable), (1, 1));
    inbox::remove(&bob, &name)?;
    assert_eq!(inbox::entries(&bob)?.1, 1);
    assert!(
        inbox::deliver(
            &profiles,
            &bob.public,
            "../x",
            &envelope(Kind::Public, "alice")
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn addresses_and_amounts_are_strict() {
    let x_only = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    assert!(private::parse_address(&format!("zark-regtest:{x_only}")).is_ok());
    for bad in [
        format!("zark-mainnet:{x_only}"),
        format!("zark-regtest:{}", x_only.to_uppercase()),
        format!("zark-regtest:{}", &x_only[2..]),
        format!("zark-regtest:{}", "00".repeat(32)),
        x_only.to_string(),
    ] {
        let error = private::parse_address(&bad).expect_err(&bad);
        assert_eq!(code(&error), Some("invalid_address"), "{bad}");
    }
    let compressed = format!("02{x_only}");
    assert!(public::parse_address(&format!("spark-regtest:{compressed}")).is_ok());
    for bad in [
        format!("spark-regtest:04{x_only}"),
        format!("spark-regtest:{x_only}"),
        format!("zark-regtest:{compressed}"),
    ] {
        assert_eq!(
            code(&public::parse_address(&bad).expect_err(&bad)),
            Some("invalid_address")
        );
    }
    for amount in [10_000, 5_000, 2_000] {
        assert!(public::bill_amount(amount).is_ok());
    }
    for amount in [0, 1, 1_000, 1_999, 4_999, 15_000, 64_000] {
        assert_eq!(
            code(&public::bill_amount(amount).expect_err("amount")),
            Some("amount")
        );
    }
    assert_eq!(public::deposit_bills(5_000).unwrap(), [5_000]);
    assert_eq!(
        public::deposit_bills(19_000).unwrap(),
        [10_000, 5_000, 2_000, 2_000]
    );
    for amount in [1_000, 17_000, 64_000] {
        assert_eq!(
            code(&public::deposit_bills(amount).expect_err("deposit")),
            Some("amount")
        );
    }
}

#[test]
fn preview_recipients_are_other_local_profiles() {
    let profile = |name: &str, key: &str| PublicProfile {
        schema: "zark-blinded-desktop-profile-v1".into(),
        profile: name.into(),
        claim_key: key.into(),
        inbox_key: String::new(),
        public_identity: None,
    };
    let profiles = [profile("alice", "aa"), profile("bob", "bb")];
    let to = |key: &'static str| move |p: &PublicProfile| p.claim_key == key;
    assert_eq!(
        super::recipient(&profiles, "alice", to("bb"))
            .unwrap()
            .profile,
        "bob"
    );
    let own = super::recipient(&profiles, "alice", to("aa")).expect_err("own address");
    assert_eq!(code(&own), Some("invalid_address"));
    let unknown = super::recipient(&profiles, "alice", to("cc")).expect_err("unknown");
    assert_eq!(code(&unknown), Some("unknown_recipient"));
}

#[test]
fn sends_take_one_or_two_picked_available_coins() -> Result<()> {
    let parent = parent()?;
    let net = network(&parent)?;
    let bob = Profile::open(&net, "bob")?;
    // Public change of any value never becomes a coin.
    for amount in [64_000, 7_000, 3_000, 1_000] {
        assert!(
            bob.new_coin(Origin::Public, CoinState::Available, amount)
                .is_err()
        );
    }
    let big = bob
        .new_coin(Origin::Received, CoinState::Available, 10_000)?
        .id;
    let small = bob
        .new_coin(Origin::Received, CoinState::Available, 2_000)?
        .id;
    let third = bob
        .new_coin(Origin::Received, CoinState::Available, 5_000)?
        .id;
    let sent = bob.new_coin(Origin::Received, CoinState::Sent, 10_000)?.id;
    let picked = |ids: &[&String]| -> Result<Vec<u64>> {
        let ids: Vec<String> = ids.iter().map(|id| (*id).clone()).collect();
        Ok(private::chosen_coins(&bob, &ids)?
            .iter()
            .map(|c| c.amount_sat)
            .collect())
    };
    assert_eq!(picked(&[&small])?, [2_000]);
    assert_eq!(picked(&[&small, &big])?, [2_000, 10_000]);
    let missing = "ab".repeat(16);
    for bad in [
        vec![],
        vec![&big, &big],
        vec![&big, &small, &third],
        vec![&sent],
        vec![&big, &missing],
    ] {
        let error = picked(&bad).expect_err("refused pick");
        assert_eq!(code(&error), Some("no_coins"), "{bad:?}");
    }
    Ok(())
}

#[test]
fn claim_coins_are_stable_per_inbox_entry() {
    let a = inbox::entry_name();
    let b = inbox::entry_name();
    assert_eq!(claim_coin_id(&a), claim_coin_id(&a));
    assert_ne!(claim_coin_id(&a), claim_coin_id(&b));
    assert_eq!(claim_coin_id(&a).len(), 32);
}

#[test]
fn snapshot_maps_coin_states_and_blocked_network() -> Result<()> {
    let parent = parent()?;
    let net = network(&parent)?;
    let bob = Profile::open(&net, "bob")?;
    let mut available = bob.new_coin(Origin::Public, CoinState::Available, 5_000)?;
    available.revision = Some(3);
    bob.save_coin(&available)?;
    let mut sent = bob.new_coin(Origin::Received, CoinState::Sent, 10_000)?;
    sent.revision = Some(4);
    bob.save_coin(&sent)?;
    let claiming = bob.new_coin(Origin::Received, CoinState::Claiming, 2_000)?;
    let exiting = {
        let mut c = bob.new_coin(Origin::Received, CoinState::Exiting, 10_000)?;
        c.revision = Some(5);
        bob.save_coin(&c)?;
        c
    };
    let profiles = net.root.join("profiles");
    inbox::deliver(
        &profiles,
        &bob.public,
        &inbox::entry_name(),
        &envelope(Kind::Private, "alice"),
    )?;
    inbox::deliver(
        &profiles,
        &bob.public,
        &inbox::entry_name(),
        &envelope(Kind::Public, "carol"),
    )?;
    let balance = public::Balance {
        total: 12_000,
        leaves: [("l1".into(), 10_000), ("l2".into(), 2_000)].into(),
    };
    let snapshot = view::build(&net, &bob, Some(&balance))?;
    let b = &snapshot["blinded"];
    assert_eq!(snapshot.as_object().map(|s| s.len()), Some(2));
    assert_eq!(snapshot["connected"], true);
    assert_eq!(b["status"], "working");
    assert_eq!(b["denominationSat"], 2_000);
    assert_eq!(b["public"]["totalSat"], 12_000);
    assert_eq!(b["public"]["leaves"][1]["amountSat"], 2_000);
    assert_eq!(b["public"]["incoming"][0]["state"], "pending");
    assert_eq!(b["incognito"]["totalSat"], 5_000);
    let coins = b["incognito"]["coins"].as_array().expect("coins");
    assert_eq!(coins.len(), 2, "sent coins are history only");
    let ids: Vec<&Value> = coins.iter().map(|c| &c["id"]).collect();
    assert!(ids.contains(&&json!(available.id)) && ids.contains(&&json!(exiting.id)));
    assert!(
        coins
            .iter()
            .all(|c| c["canSend"] == (c["state"] == "available"))
    );
    let incoming = b["incognito"]["incoming"].as_array().expect("incoming");
    assert_eq!(incoming.len(), 2);
    assert!(
        incoming
            .iter()
            .any(|c| c["id"] == json!(claiming.id) && c["state"] == "claiming")
    );
    assert!(incoming.iter().any(|c| c["state"] == "pending"));
    assert!(
        b["incognito"]["address"]
            .as_str()
            .is_some_and(|a| a == format!("zark-regtest:{}", bob.public.claim_key))
    );
    net.block(&Blocked {
        reason: "Moving a coin to Public".into(),
        operation: "goPublic".into(),
        profile: "carol".into(),
        coin: exiting.id.clone(),
        at: 1,
    })?;
    let offline = view::build(&net, &bob, None)?;
    assert_eq!(offline["connected"], false);
    assert_eq!(offline["blinded"]["status"], "blocked");
    assert_eq!(offline["blinded"]["blocked"]["profile"], "carol");
    assert_eq!(offline["blinded"]["public"]["totalSat"], 0);
    assert!(offline["blinded"]["public"]["address"].is_null());
    // Private material never appears in the snapshot.
    let text = serde_json::to_string(&offline)?;
    assert!(
        !text.contains("\"offer\"") && !text.contains("leafNode") && !text.contains("leaf_node")
    );
    assert!(!text.contains(&hex::encode(*bob.inbox_secret())));
    assert!(!text.contains(&hex::encode(*bob.claim_secret())));
    Ok(())
}
