//! Signed synthetic received-root fixtures, not a native claim simulation.
use super::{PrivateBacking, backing_tests::setup};
use crate::wrapped_recovery::test_support::sign_spark;
use anyhow::Result;
use bitcoin::{
    Sequence, Transaction,
    consensus::{deserialize, serialize},
};

pub(super) fn received(delay: u32) -> Result<PrivateBacking> {
    let (keys, backing) = setup()?;
    let mut prefix = backing.prefix().clone();
    let root: Transaction = deserialize(&prefix.root_node)?;
    for (i, raw) in [&mut prefix.cpfp_refund, &mut prefix.direct_from_cpfp_refund]
        .into_iter()
        .enumerate()
    {
        let mut tx: Transaction = deserialize(raw)?;
        tx.input[0].sequence = Sequence::from_consensus((1 << 30) | (delay + i as u32 * 50));
        tx.input[0].witness.clear();
        // Independent wallet/server/operator signatures; no USER scalar sum.
        sign_spark(&keys, &mut tx, &root.output[0], [61 + i as u8; 32])?;
        *raw = serialize(&tx);
    }
    PrivateBacking::new_received_root(
        backing.anchor().clone(),
        backing.keys().clone(),
        prefix,
        delay,
        [71; 32],
    )
}

#[test]
fn received_root_roundtrip_preserves_signed_bytes_and_has_explicit_record_version() -> Result<()> {
    let (_, fresh) = setup()?;
    let old = fresh.encode_private()?;
    let old_json: serde_json::Value = serde_json::from_slice(&old)?;
    assert_eq!(old_json["version"], 1);
    assert!(old_json.get("received_root_delay").is_none());
    assert_eq!(
        PrivateBacking::decode_private(&old)?
            .encode_private()?
            .as_slice(),
        old.as_slice()
    );

    let backing = received(1900)?;
    assert_eq!(backing.validated_exit().native_delay(), 1900);
    assert!(
        PrivateBacking::new(
            backing.anchor().clone(),
            backing.keys().clone(),
            backing.prefix().clone(),
            [71; 32]
        )
        .is_err()
    );
    let bytes = backing.encode_private()?;
    let saved: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(saved["version"], 2);
    assert_eq!(saved["received_root_delay"], 1900);
    let reopened = PrivateBacking::decode_private(&bytes)?;
    assert_eq!(reopened.encode_private()?.as_slice(), bytes.as_slice());
    assert_eq!(reopened.prefix(), backing.prefix());
    for attack in 0..6 {
        let mut changed = saved.clone();
        match attack {
            0 => changed["version"] = 1.into(),
            1 => changed["received_root_delay"] = 1800.into(),
            2 => {
                changed
                    .as_object_mut()
                    .unwrap()
                    .remove("received_root_delay");
            }
            3 => changed["prefix"]["direct_from_cpfp_refund"][0] = 255.into(),
            4 => changed["received_root_delay"] = 2000.into(),
            _ => changed["received_root_delay"] = 100.into(),
        }
        assert!(
            PrivateBacking::decode_private(&serde_json::to_vec(&changed)?).is_err(),
            "attack {attack}"
        );
    }
    Ok(())
}
