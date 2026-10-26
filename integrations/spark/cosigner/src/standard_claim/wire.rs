//! Minimal pinned protobuf encoding; only length-delimited fields occur here.
//! Field numbers match the unchanged Spark ClaimLeafKeyTweaks / SecretShare.
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub(super) fn encode(
    leaf_id: &str,
    evaluation: &[u8; 32],
    proofs: &[Vec<u8>],
    public_shares: &BTreeMap<String, Vec<u8>>,
) -> Zeroizing<Vec<u8>> {
    let mut share = Zeroizing::new(Vec::new());
    field(&mut share, 1, evaluation);
    for proof in proofs {
        field(&mut share, 2, proof);
    }
    let mut leaf = Zeroizing::new(Vec::new());
    field(&mut leaf, 1, leaf_id.as_bytes());
    field(&mut leaf, 2, &share);
    for (id, public_share) in public_shares {
        let mut entry = Vec::new();
        field(&mut entry, 1, id.as_bytes());
        field(&mut entry, 2, public_share);
        field(&mut leaf, 3, &entry);
    }
    let mut bundle = Zeroizing::new(Vec::new());
    field(&mut bundle, 1, &leaf);
    bundle
}

fn field(out: &mut Vec<u8>, number: u8, bytes: &[u8]) {
    out.push((number << 3) | 2);
    let mut length = bytes.len();
    while length >= 128 {
        out.push((length as u8 & 127) | 128);
        length >>= 7;
    }
    out.push(length as u8);
    out.extend_from_slice(bytes);
}
