//! This profile's copy of the Public leaves it holds, including each leaf's
//! transactions and the parent transactions those leaves spend.
//!
//! The file is replaced only after a fresh read that all three operators
//! agree on. A missing read, or operators that disagree, leaves the previous
//! file where it is. The copy is not an exit: a later tool reads it when the
//! operators are unreachable.
use super::super::*;
use super::{
    session::Session,
    store::{self, Profile, now_ms},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt,
};

const SCHEMA: &str = "zark-public-exit-tree-v1";
/// Leaves, their transactions and a parent chain. Larger than the other
/// profile records, which are small JSON documents.
const MAX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ExitTree {
    pub schema: String,
    pub identity: String,
    pub saved_at: u64,
    pub leaves: Vec<ExitNode>,
    pub ancestors: Vec<ExitNode>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ExitNode {
    pub id: String,
    pub value: u64,
    pub status: String,
    pub owner: String,
    pub signing_key: String,
    pub verifying_key: String,
    pub vout: u16,
    pub parent_id: Option<String>,
    pub raw_tx: String,
    pub raw_refund_tx: String,
    #[serde(default)]
    pub direct_tx: Option<String>,
    #[serde(default)]
    pub direct_refund_tx: Option<String>,
    #[serde(default)]
    pub direct_from_cpfp_refund_tx: Option<String>,
}

/// Reads the operators and replaces the file when they agree. Any failure
/// keeps the previous file.
pub(super) fn remember(s: &mut Session) {
    if let Err(error) = refresh(s) {
        s.log_error("exit-tree", &error);
    }
}

fn refresh(s: &mut Session) -> Result<()> {
    if s.profile.public.public_identity.is_none() {
        super::public::wallet(s)?;
    }
    let identity = hex::decode(
        s.profile
            .public
            .public_identity
            .as_deref()
            .context("Public wallet identity")?,
    )?;
    let name = s.profile.public_name().to_owned();
    let value = s.call_native(json!({"op":"exit_tree","directory":NATIVE,"recipient":name}))?;
    store(&s.profile, &identity, &value)
}

pub(super) fn load(profile: &Profile) -> Result<Option<ExitTree>> {
    let path = profile.home.join("public-exit-tree.json");
    if !path.exists() {
        return Ok(None);
    }
    let meta = std::fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.len() <= MAX_BYTES,
        "Public exit tree shape"
    );
    let tree: ExitTree = serde_json::from_slice(&std::fs::read(&path)?)?;
    check(&tree)?;
    Ok(Some(tree))
}

/// Checks the operator reply and writes it. Returns before the write when the
/// reply is not a complete agreed tree.
pub(super) fn store(profile: &Profile, identity: &[u8], value: &Value) -> Result<()> {
    ensure!(
        value["operators_agreed"] == 3,
        "operators did not agree on the Public exit tree; the saved copy was left unchanged"
    );
    ensure!(
        bytes(value, "identity")? == identity,
        "Public exit tree identity"
    );
    let tree = ExitTree {
        schema: SCHEMA.into(),
        identity: hex::encode(identity),
        saved_at: now_ms(),
        leaves: serde_json::from_value(value["leaves"].clone())?,
        ancestors: serde_json::from_value(value["ancestors"].clone())?,
    };
    check(&tree)?;
    let path = profile.home.join("public-exit-tree.json");
    store::write_json(&path, &tree)?;
    ensure!(
        load(profile)?.as_ref() == Some(&tree),
        "Public exit tree write"
    );
    Ok(())
}

fn check(tree: &ExitTree) -> Result<()> {
    ensure!(tree.schema == SCHEMA, "Public exit tree schema");
    let identity = hex_key(&tree.identity, "Public exit tree identity")?;
    let mut nodes = BTreeMap::new();
    for node in tree.leaves.iter().chain(tree.ancestors.iter()) {
        ensure!(node_id(&node.id), "Public exit tree node");
        ensure!(
            nodes.insert(node.id.clone(), node).is_none(),
            "duplicate Public exit node"
        );
        for key in [&node.owner, &node.signing_key, &node.verifying_key] {
            hex_key(key, "Public exit tree key")?;
        }
        ensure!(
            !hex_tx(&node.raw_tx)?.is_empty() && !hex_tx(&node.raw_refund_tx)?.is_empty(),
            "Public exit tree transaction"
        );
        for tx in [
            &node.direct_tx,
            &node.direct_refund_tx,
            &node.direct_from_cpfp_refund_tx,
        ]
        .into_iter()
        .flatten()
        {
            hex_tx(tx)?;
        }
    }
    let mut reached = BTreeSet::new();
    for leaf in &tree.leaves {
        ensure!(
            leaf.status == "AVAILABLE" && hex::decode(&leaf.owner)? == identity,
            "Public exit tree leaf"
        );
        let mut parent = leaf.parent_id.clone();
        let mut path = BTreeSet::new();
        let mut depth = 0;
        while let Some(id) = parent {
            depth += 1;
            ensure!(depth <= 64, "Public exit tree too deep");
            ensure!(path.insert(id.clone()), "Public exit tree cycle");
            let node = nodes.get(&id).context("Public exit tree parent missing")?;
            if tree.leaves.iter().any(|other| other.id == id) {
                parent = node.parent_id.clone();
                continue;
            }
            // A parent already reached was checked from the leaf that found it.
            if !reached.insert(id) {
                break;
            }
            parent = node.parent_id.clone();
        }
    }
    ensure!(
        reached.len() == tree.ancestors.len(),
        "Public exit tree has an ancestor no leaf reaches"
    );
    Ok(())
}

fn node_id(id: &str) -> bool {
    let groups: Vec<_> = id.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(groups)
            .all(|(n, g)| g.len() == *n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn hex_key(value: &str, what: &str) -> Result<Vec<u8>> {
    let raw = hex_tx(value)?;
    ensure!(raw.len() == 33, "{what}");
    Ok(raw)
}

fn hex_tx(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "Public exit tree transaction"
    );
    Ok(hex::decode(value)?)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{network, parent};
    use super::*;

    fn node(id: &str, parent: Option<&str>, status: &str) -> Value {
        json!({
            "id": id,
            "value": 1000,
            "status": status,
            "owner": "02".repeat(33),
            "signing_key": "03".repeat(33),
            "verifying_key": "02".repeat(33),
            "vout": 0,
            "parent_id": parent,
            "raw_tx": "abcd",
            "raw_refund_tx": "ef01",
        })
    }

    fn reply(leaves: Vec<Value>, ancestors: Vec<Value>) -> Value {
        json!({
            "identity": vec![2u8; 33],
            "operators_agreed": 3,
            "leaves": leaves,
            "ancestors": ancestors,
        })
    }

    #[test]
    fn a_refused_tree_keeps_the_saved_copy() -> Result<()> {
        let root = parent()?;
        let net = network(&root)?;
        let mut profile = Profile::open(&net, "alice")?;
        profile.publish_public_identity(&[2; 33])?;
        let leaf = "11111111-1111-1111-1111-111111111111";
        let parent_id = "22222222-2222-2222-2222-222222222222";
        store(
            &profile,
            &[2; 33],
            &reply(
                vec![node(leaf, Some(parent_id), "AVAILABLE")],
                vec![node(parent_id, None, "SPLITTED")],
            ),
        )?;
        let saved = load(&profile)?.context("saved tree")?;
        assert_eq!(saved.leaves[0].id, leaf);
        assert_eq!(saved.ancestors[0].raw_tx, "abcd");

        let mut refused = reply(
            vec![node(leaf, Some(parent_id), "AVAILABLE")],
            vec![node(parent_id, None, "SPLITTED")],
        );
        refused["operators_agreed"] = json!(0);
        assert!(store(&profile, &[2; 33], &refused).is_err());
        let mut orphan = reply(vec![node(leaf, Some(parent_id), "AVAILABLE")], vec![]);
        assert!(store(&profile, &[2; 33], &orphan).is_err());
        orphan = reply(
            vec![node(leaf, Some(parent_id), "AVAILABLE")],
            vec![node(parent_id, None, "SPLITTED")],
        );
        assert!(store(&profile, &[3; 33], &orphan).is_err());

        let kept = load(&profile)?.context("kept tree")?;
        assert_eq!(kept, saved);
        Ok(())
    }
}
