use super::{Nonce, aggregate};
use crate::{
    keys::{Authority, Purpose, Scope, Share},
    signing,
};
use anyhow::Result;
use bitcoin::{
    key::TapTweak,
    secp256k1::{Message, Parity, Secp256k1, XOnlyPublicKey, schnorr::Signature},
};

fn holders(purpose: Purpose) -> Result<(Share, Share, Authority)> {
    let scope = Scope {
        deployment: [1; 32],
        coin: [2; 32],
        purpose,
    };
    let first = Share::generate(scope.clone(), 1)?;
    let second = Share::generate(scope, 2)?;
    let authority = Authority::new(first.public().clone(), second.public().clone())?;
    Ok((first, second, authority))
}

#[test]
fn independent_user_holders_sign_bip341_for_all_internal_and_output_parities() -> Result<()> {
    let mut covered = [false; 4];
    for _ in 0..128 {
        let (wallet, signer, authority) = holders(Purpose::LeafSigning)?;
        let raw = authority.public_key()?;
        let internal = XOnlyPublicKey::from_slice(&raw[1..])?;
        let (output, parity) = internal.tap_tweak(&Secp256k1::verification_only(), None);
        let first = Nonce::prepare(&wallet, &authority)?;
        let second = Nonce::prepare(&signer, &authority)?;
        let commitment = [first.commitment()?, second.commitment()?];
        let refs = [&commitment[0][..], &commitment[1][..]];
        let first = first.sign(&wallet, &authority, [7; 32], refs)?;
        let second = second.sign(&signer, &authority, [7; 32], refs)?;
        let signature = aggregate(&authority, [7; 32], refs, [&first, &second])?;
        Secp256k1::verification_only().verify_schnorr(
            &Signature::from_slice(&signature)?,
            &Message::from_digest([7; 32]),
            &output.to_x_only_public_key(),
        )?;
        assert!(
            Secp256k1::verification_only()
                .verify_schnorr(
                    &Signature::from_slice(&signature)?,
                    &Message::from_digest([7; 32]),
                    &internal
                )
                .is_err(),
            "plain identity signing is not a refund spend"
        );
        covered[2 * usize::from(raw[0] == 3) + usize::from(parity == Parity::Odd)] = true;
        if covered == [true; 4] {
            return Ok(());
        }
    }
    anyhow::bail!("USER recovery parity coverage incomplete")
}

#[test]
fn recovery_nonce_codecs_are_separate_from_identity_and_bind_exact_authority() -> Result<()> {
    let (wallet, signer, authority) = holders(Purpose::LeafSigning)?;
    let first = Nonce::prepare(&wallet, &authority)?;
    let encoded = first.encode_private()?;
    let reopened = Nonce::decode_private(&encoded, &wallet, &authority)?;
    assert_eq!(reopened.commitment()?, first.commitment()?);
    assert_eq!(*reopened.encode_private()?, *encoded);
    assert!(signing::Nonce::decode_private(&encoded, &wallet, &authority).is_err());
    assert!(Nonce::decode_private(&encoded, &signer, &authority).is_err());
    let (_, _, unrelated) = holders(Purpose::LeafSigning)?;
    assert!(Nonce::decode_private(&encoded, &wallet, &unrelated).is_err());
    let identity_nonce = signing::Nonce::prepare(&wallet, &authority)?;
    assert!(Nonce::decode_private(&identity_nonce.encode_private()?, &wallet, &authority).is_err());
    let (identity, _, identity_authority) = holders(Purpose::Identity)?;
    assert!(Nonce::prepare(&identity, &identity_authority).is_err());
    let mut tampered = encoded.to_vec();
    tampered[0] ^= 1;
    assert!(Nonce::decode_private(&tampered, &wallet, &authority).is_err());
    Ok(())
}

#[test]
fn changed_nonce_role_hash_and_contribution_cannot_produce_recovery_signature() -> Result<()> {
    let (wallet, signer, authority) = holders(Purpose::LeafSigning)?;
    let first = Nonce::prepare(&wallet, &authority)?;
    let second = Nonce::prepare(&signer, &authority)?;
    let commitments = [first.commitment()?, second.commitment()?];
    assert!(
        first
            .sign(
                &wallet,
                &authority,
                [7; 32],
                [&commitments[1], &commitments[0]]
            )
            .is_err()
    );
    let first = Nonce::prepare(&wallet, &authority)?;
    let commitments = [first.commitment()?, commitments[1].clone()];
    let refs = [&commitments[0][..], &commitments[1][..]];
    let first = first.sign(&wallet, &authority, [7; 32], refs)?;
    let second = second.sign(&signer, &authority, [7; 32], refs)?;
    assert!(aggregate(&authority, [8; 32], refs, [&first, &second]).is_err());
    assert!(aggregate(&authority, [7; 32], refs, [&second, &first]).is_err());
    assert!(aggregate(&authority, [7; 32], refs, [&first, &first]).is_err());
    assert!(aggregate(&authority, [7; 32], refs, [&[0; 32], &second]).is_err());
    Ok(())
}
