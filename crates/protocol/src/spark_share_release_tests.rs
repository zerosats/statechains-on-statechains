use super::*;
use crate::spark_lineage::Digest;

struct Fixture {
    binding: Binding,
    recipient: Scalar,
    wallet: [u8; 32],
    server: [u8; 32],
    joint: [u8; 64],
}

fn compressed(secret: &Scalar) -> [u8; 33] {
    (ProjectivePoint::GENERATOR * secret)
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn fixture() -> Result<Fixture> {
    let wallet = random_scalar();
    let server = random_scalar();
    let recipient = random_scalar();
    let binding = Binding {
        deployment: random32(),
        coin: random32(),
        intent: random32(),
        request: random32(),
        session: random32(),
        recipient: compressed(&recipient),
        server: point_bytes(ProjectivePoint::GENERATOR * server)?,
        state: random32(),
        capability: random32(),
        revision: 7,
        committed_revision: 8,
    };
    Ok(Fixture {
        binding,
        recipient,
        wallet: wallet.to_bytes().into(),
        server: server.to_bytes().into(),
        joint: point_bytes(ProjectivePoint::GENERATOR * (wallet + server))?,
    })
}

#[test]
fn sealed_share_opens_only_for_the_bound_owner_and_completes_the_joint_key() -> Result<()> {
    let f = fixture()?;
    let wire = seal(&f.binding, &f.server)?;
    assert_eq!(wire.len(), CIPHERTEXT_LEN);
    let opened = open(&f.binding, &f.recipient, &wire)?;
    assert_eq!(*opened, f.server);
    let joint = joint_secret(&f.wallet, &opened, &f.joint)?;
    assert_eq!(
        point_bytes(ProjectivePoint::GENERATOR * scalar(&*joint)?)?,
        f.joint
    );
    // A fresh ephemeral key and nonce: two seals of one share never repeat.
    assert_ne!(seal(&f.binding, &f.server)?, wire);
    assert!(open(&f.binding, &random_scalar(), &wire).is_err());
    Ok(())
}

#[test]
fn every_bound_field_and_wire_byte_is_authenticated() -> Result<()> {
    let f = fixture()?;
    let wire = seal(&f.binding, &f.server)?;
    let changes: Vec<fn(&mut Binding)> = vec![
        |b| b.deployment = random32(),
        |b| b.coin = random32(),
        |b| b.intent = random32(),
        |b| b.request = random32(),
        |b| b.session = random32(),
        |b| b.state = random32(),
        |b| b.capability = random32(),
        |b| {
            b.revision += 1;
            b.committed_revision += 1
        },
    ];
    for change in changes {
        let mut other = f.binding.clone();
        change(&mut other);
        assert!(open(&other, &f.recipient, &wire).is_err());
    }
    for index in 0..wire.len() {
        let mut tampered = wire.clone();
        tampered[index] ^= 1;
        assert!(open(&f.binding, &f.recipient, &tampered).is_err());
    }
    assert!(open(&f.binding, &f.recipient, &wire[..wire.len() - 1]).is_err());
    Ok(())
}

#[test]
fn substituted_share_or_joint_key_is_rejected_before_any_spark_use() -> Result<()> {
    let f = fixture()?;
    // The signer refuses to seal a share for another server point.
    let other: [u8; 32] = random_scalar().to_bytes().into();
    assert!(seal(&f.binding, &other).is_err());
    // An attacker who can encrypt to R still cannot make the wallet accept a
    // share that differs from the certified X_s.
    let mut forged = f.binding.clone();
    forged.server = point_bytes(ProjectivePoint::GENERATOR * scalar(&other)?)?;
    let wire = seal(&forged, &other)?;
    assert!(open(&f.binding, &f.recipient, &wire).is_err());
    // A share for the right X_s but another wallet share never yields P.
    let wrong_wallet: [u8; 32] = random_scalar().to_bytes().into();
    assert!(joint_secret(&wrong_wallet, &f.server, &f.joint).is_err());
    Ok(())
}

#[test]
fn malformed_bindings_and_recipient_points_fail_closed() -> Result<()> {
    let f = fixture()?;
    let mut stale = f.binding.clone();
    stale.committed_revision = stale.revision;
    assert!(seal(&stale, &f.server).is_err());
    let mut zero = f.binding.clone();
    zero.request = [0; 32];
    assert!(seal(&zero, &f.server).is_err());
    let mut uncompressed = f.binding.recipient;
    uncompressed[0] = 4;
    assert!(compressed_point(&uncompressed).is_err());
    assert!(compressed_point(&[2; 33]).is_err() || compressed_point(&[3; 33]).is_err());
    assert!(recipient_claim(&[1; 32], &[2; 32], &[0; 33]).is_err());
    Ok(())
}

#[test]
fn owner_signature_is_domain_separated_and_bound_to_capability() -> Result<()> {
    let f = fixture()?;
    let owner = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let session = SigningKey::from_bytes(&random_scalar().to_bytes())?;
    let session_public: Digest = session.verifying_key().to_bytes().into();
    let context = ExitContext {
        deployment: f.binding.deployment,
        coin: f.binding.coin,
        current_state: f.binding.state,
        operation: random32(),
        session: session_public,
        revision: f.binding.revision,
    };
    let capability = lineage::public_capability_commitment(
        &context.deployment,
        &context.coin,
        &owner.verifying_key().to_bytes().into(),
    )?;
    let auth = sign_owner(&context, &f.binding.recipient, &f.binding.server, &owner)?;
    verify_owner(
        &auth,
        &context,
        &f.binding.recipient,
        &f.binding.server,
        &capability,
    )?;
    let other = compressed(&random_scalar());
    assert!(verify_owner(&auth, &context, &other, &f.binding.server, &capability).is_err());
    assert!(
        verify_owner(
            &auth,
            &context,
            &f.binding.recipient,
            &f.binding.server,
            &random32()
        )
        .is_err()
    );
    let mut later = context.clone();
    later.revision += 1;
    assert!(
        verify_owner(
            &auth,
            &later,
            &f.binding.recipient,
            &f.binding.server,
            &capability
        )
        .is_err()
    );
    let native =
        OwnerAuthorization::sign_native(&context, &random32(), &[random32(), random32()], &owner)?;
    assert!(
        verify_owner(
            &native,
            &context,
            &f.binding.recipient,
            &f.binding.server,
            &capability
        )
        .is_err()
    );
    assert!(sign_owner(&context, &f.binding.recipient, &f.binding.server, &session).is_err());
    Ok(())
}
