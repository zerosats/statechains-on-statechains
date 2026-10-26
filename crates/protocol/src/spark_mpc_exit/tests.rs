use super::*;
use crate::{
    point_bytes, random_scalar, random32,
    spark_auth::{AuthBlinding, IdentityKey},
    spark_native::PlanOpening,
    spark_native_vss::Cluster,
};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::sec1::ToEncodedPoint,
    schnorr::{Signature, VerifyingKey},
};
use payload::{
    AuthorizationPayload, AuthorizedLeaf, LeafRefunds, SCHEME_ECDSA, refund_digest, uuid_string,
};

fn uuid(text: &str) -> [u8; 16] {
    hex::decode(text.replace('-', ""))
        .unwrap()
        .try_into()
        .unwrap()
}
fn compressed(p: ProjectivePoint) -> [u8; 33] {
    p.to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

#[test]
fn payload_and_refund_digest_match_pinned_go_hashstructure() {
    // Same vector as the legacy co-signer test, filled from the unmodified Go
    // common/hashstructure file; the direct flavour is absent (empty bytes).
    let leaf_id = uuid("11111111-2222-4333-8444-555555555555");
    let refunds = refund_digest(&[LeafRefunds {
        leaf_id,
        cpfp: [0x11; 32],
        direct: None,
        direct_from_cpfp: Some([0x33; 32]),
    }]);
    assert_eq!(
        hex::encode(refunds),
        "8ca3cba77e9a4725b1eb38f910557a54433736bb605349c5da372b39b75fc495"
    );
    let payload = AuthorizationPayload {
        transfer_id: uuid("22222222-2222-2222-2222-222222222222"),
        expiry: 1_800_000_000,
        positions: vec![1, 2],
        leaves: vec![AuthorizedLeaf {
            leaf_id,
            amount: 42_000,
            owner_signing: [2; 33],
            mask_commitment: [3; 33],
            receiver_identity: [4; 33],
            secret_cipher: vec![5; 129],
            signature_scheme: SCHEME_ECDSA,
            signature: vec![6; 70],
            proofs: vec![vec![[7; 33], [8; 33]], vec![[9; 33], [10; 33]]],
        }],
        refund_digest: refunds,
    };
    assert_eq!(
        hex::encode(payload.hash().unwrap()),
        "f82e7c40feefa477cff24ffec3d39ec823e827061d3e5f40d09abc45b3ef4a9c"
    );
    assert_eq!(
        uuid_string(&leaf_id),
        "11111111-2222-4333-8444-555555555555"
    );
}

#[test]
fn payload_binds_every_field_and_sorts_leaves() {
    let leaf = |id: u8| AuthorizedLeaf {
        leaf_id: [id; 16],
        amount: 1,
        owner_signing: [2; 33],
        mask_commitment: [3; 33],
        receiver_identity: [4; 33],
        secret_cipher: vec![5; 129],
        signature_scheme: SCHEME_ECDSA,
        signature: vec![6; 70],
        proofs: vec![vec![[7; 33]; 2], vec![[9; 33]; 2]],
    };
    let base = AuthorizationPayload {
        transfer_id: [1; 16],
        expiry: 9,
        positions: vec![1, 2],
        leaves: vec![leaf(1), leaf(2)],
        refund_digest: [8; 32],
    };
    let mut swapped = base.clone();
    swapped.leaves.reverse();
    assert_eq!(base.hash().unwrap(), swapped.hash().unwrap());
    let mut changes: Vec<AuthorizationPayload> = Vec::new();
    for edit in 0..8 {
        let mut p = base.clone();
        match edit {
            0 => p.expiry += 1,
            1 => p.leaves[0].amount += 1,
            2 => p.leaves[0].receiver_identity[1] ^= 1,
            3 => p.leaves[0].signature_scheme = payload::SCHEME_SCHNORR,
            4 => p.leaves[0].proofs[1][0][1] ^= 1,
            5 => p.refund_digest[0] ^= 1,
            6 => p.transfer_id[0] ^= 1,
            _ => p.leaves[0].secret_cipher[0] ^= 1,
        }
        changes.push(p);
    }
    for p in changes {
        assert_ne!(p.hash().unwrap(), base.hash().unwrap());
    }
    let mut short = base;
    short.leaves[0].proofs.pop();
    assert!(short.hash().is_err());
}

fn cluster() -> Cluster {
    Cluster {
        threshold: 2,
        operators: (1..=3u64)
            .map(|i| {
                let mut id = [0; 32];
                id[31] = i as u8;
                (
                    hex::encode(id),
                    compressed(ProjectivePoint::GENERATOR * Scalar::from(100 + i)).to_vec(),
                )
            })
            .collect(),
    }
}

struct Fixture {
    key: IdentityKey,
    server_secret: Scalar,
    plan: PlanOpening,
    cipher: Vec<u8>,
    contribution: MpcContribution,
}
fn fixture() -> Fixture {
    let server_secret = random_scalar();
    let server = point_bytes(ProjectivePoint::GENERATOR * server_secret).unwrap();
    let key = IdentityKey::new(random_scalar().to_bytes().into(), random32(), server).unwrap();
    let cipher = vec![7; SECRET_CIPHER_LEN];
    let plan = PlanOpening {
        salt: random32(),
        transfer_id: [3; 16],
        leaf_id: [4; 16],
        expiry: 1_900_000_000,
        cluster: cluster().digest().unwrap(),
        anchor_txid: [5; 32],
        anchor_vout: 0,
        amount: 64_000,
        native_delay: 2000,
        operator: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(17u64)).unwrap(),
        mask_user: point_bytes(ProjectivePoint::GENERATOR * Scalar::from(19u64)).unwrap(),
        receiver_identity: compressed(ProjectivePoint::GENERATOR * Scalar::from(23u64)),
        mask_cipher_sha256: crate::hash(&[&cipher]),
    };
    let constant: [u8; 32] = (-server_secret).to_bytes().into();
    let contribution =
        MpcContribution::prepare(&constant, plan.transfer_id, plan.leaf_id, &cluster()).unwrap();
    Fixture {
        key,
        server_secret,
        plan,
        cipher,
        contribution,
    }
}
impl Fixture {
    fn header(&self) -> TransferAuthHeader {
        TransferAuthHeader {
            scope: [1; 32],
            key_commitment: self.key.commitment(),
            server: self.key.server,
            plan: self
                .plan
                .commitment(point_bytes(self.key.joint).unwrap())
                .unwrap(),
            transfer_id: self.plan.transfer_id,
            leaf_id: self.plan.leaf_id,
            signer_proofs: self.contribution.proof_points().unwrap(),
        }
    }
    fn witness<'a>(
        &'a self,
        blinding: &'a AuthBlinding,
        signature: &'a [u8],
    ) -> TransferAuthWitness<'a> {
        TransferAuthWitness {
            key: &self.key,
            plan: &self.plan,
            secret_cipher: &self.cipher,
            leaf_signature: signature,
            wallet_proofs: [
                compressed(ProjectivePoint::GENERATOR * Scalar::from(29u64)),
                compressed(ProjectivePoint::GENERATOR * Scalar::from(31u64)),
            ],
            blinding,
        }
    }
}

#[test]
fn blind_transfer_authorization_completes_a_bip340_signature_over_the_spark_payload() {
    let f = fixture();
    let header = f.header();
    let blinding = AuthBlinding::random();
    let witness = f.witness(&blinding, &[0x30; 71]);
    let message = witness.payload(&header).unwrap().hash().unwrap();
    let commitment = witness.commitment(&header).unwrap();
    let k = random_scalar();
    let nonce = point_bytes(ProjectivePoint::GENERATOR * k).unwrap();
    let bound = blinding.bind(&f.key, &nonce, &message).unwrap();
    let statement = TransferAuthStatement {
        header: header.clone(),
        commitment,
        nonce,
        challenge: bound.challenge,
    };
    assert_eq!(statement.encode().unwrap().len(), ENCODED_LEN);
    let toml = witness.prover_toml(&statement).unwrap();
    assert!(toml.contains("signature_len = 71") && toml.contains("wallet_proofs = [["));
    let z: [u8; 32] = (k + crate::scalar(&bound.challenge).unwrap() * f.server_secret)
        .to_bytes()
        .into();
    let signature = blinding
        .finish(&f.key, &bound, &nonce, &z, &message)
        .unwrap();
    VerifyingKey::from_bytes(&f.key.compressed().unwrap()[1..])
        .unwrap()
        .verify_raw(
            &message,
            &Signature::try_from(signature.as_slice()).unwrap(),
        )
        .unwrap();
    // A wrong server contribution is rejected before release.
    let wrong: [u8; 32] = (k + Scalar::ONE).to_bytes().into();
    assert!(
        blinding
            .finish(&f.key, &bound, &nonce, &wrong, &message)
            .is_err()
    );
}

/// Writes one synthetic Prover.toml for measuring the pinned circuit.
#[test]
#[ignore = "writes a synthetic prover input to ZARK_SPARK_TRANSFER_AUTH_PROVER_OUT"]
fn write_synthetic_transfer_auth_prover_input() {
    let out =
        std::path::PathBuf::from(std::env::var_os("ZARK_SPARK_TRANSFER_AUTH_PROVER_OUT").unwrap());
    let f = fixture();
    let header = f.header();
    let blinding = AuthBlinding::random();
    let witness = f.witness(&blinding, &[0x30; 71]);
    let message = witness.payload(&header).unwrap().hash().unwrap();
    let nonce = point_bytes(ProjectivePoint::GENERATOR * random_scalar()).unwrap();
    let bound = blinding.bind(&f.key, &nonce, &message).unwrap();
    let statement = TransferAuthStatement {
        header,
        commitment: witness.commitment(&f.header()).unwrap(),
        nonce,
        challenge: bound.challenge,
    };
    std::fs::write(&out, witness.prover_toml(&statement).unwrap().as_bytes()).unwrap();
    std::fs::write(
        out.with_file_name("statement.bin"),
        statement.encode().unwrap(),
    )
    .unwrap();
}

/// Verifies a real proof for the statement written above through the pinned
/// verifier, and rejects the same proof for a changed challenge.
#[test]
#[ignore = "needs ZARK_SPARK_TRANSFER_AUTH_PROOF_DIR, ZARK_SPARK_TRANSFER_AUTH_VK, ZARK_BB and ZARK_CRS"]
fn real_transfer_auth_proof_verifies_only_its_statement() {
    let env = |name: &str| std::path::PathBuf::from(std::env::var_os(name).unwrap());
    let pin = |path: std::path::PathBuf| {
        let sha256 = crate::hash(&[&std::fs::read(&path).unwrap()]);
        crate::proof::ArtifactPin { path, sha256 }
    };
    let dir = env("ZARK_SPARK_TRANSFER_AUTH_PROOF_DIR");
    let verifier = PinnedTransferAuthVerifier::new(
        [1; 32],
        pin(env("ZARK_BB")),
        env("ZARK_CRS"),
        pin(env("ZARK_SPARK_TRANSFER_AUTH_VK")),
    )
    .unwrap();
    let statement =
        TransferAuthStatement::decode(&std::fs::read(dir.join("statement.bin")).unwrap()).unwrap();
    let proof = std::fs::read(dir.join("proof")).unwrap();
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        verifier.verify(&statement, &proof, &scratch).unwrap(),
        crate::hash(&[&statement.encode().unwrap()])
    );
    eprintln!("pinned transfer auth verify: {:?}", started.elapsed());
    let mut changed = statement.clone();
    changed.challenge[31] ^= 1;
    assert!(verifier.verify(&changed, &proof, &scratch).is_err());
}

#[test]
fn witness_rejects_plan_uuid_cipher_signature_and_key_mismatches() {
    let f = fixture();
    let blinding = AuthBlinding::random();
    let witness = f.witness(&blinding, &[0x30; 70]);
    let header = f.header();
    witness.check_header(&header).unwrap();
    for edit in 0..5 {
        let mut h = header.clone();
        match edit {
            0 => h.transfer_id[0] ^= 1,
            1 => h.leaf_id[0] ^= 1,
            2 => h.plan[0] ^= 1,
            3 => h.key_commitment[0] ^= 1,
            _ => h.server = point_bytes(ProjectivePoint::GENERATOR * Scalar::from(5u64)).unwrap(),
        }
        assert!(witness.check_header(&h).is_err());
    }
    for length in [67, 73] {
        let signature = vec![0x30; length];
        assert!(
            f.witness(&blinding, &signature)
                .check_header(&header)
                .is_err()
        );
    }
    let other = vec![8; SECRET_CIPHER_LEN];
    let mut bad = f.witness(&blinding, &[0x30; 70]);
    bad.secret_cipher = &other;
    assert!(bad.check_header(&header).is_err());
}

/// The signer's frozen plan commitment fixes receiver, amount, leaf, expiry
/// and refunds: a wallet opening with any other value cannot match it.
#[test]
fn frozen_plan_rejects_other_receiver_amount_leaf_and_expiry() {
    let f = fixture();
    let blinding = AuthBlinding::random();
    let header = f.header();
    for edit in 0..5 {
        let mut plan = f.plan.clone();
        match edit {
            0 => {
                plan.receiver_identity =
                    compressed(ProjectivePoint::GENERATOR * Scalar::from(41u64))
            }
            1 => plan.amount += 1,
            2 => plan.leaf_id[15] ^= 1,
            3 => plan.expiry += 1,
            _ => plan.native_delay += 1,
        }
        let witness = TransferAuthWitness {
            plan: &plan,
            ..f.witness(&blinding, &[0x30; 70])
        };
        assert!(witness.check_header(&header).is_err());
        assert!(witness.payload(&header).is_err());
    }
}

#[test]
fn upstream_contribution_has_exact_sealed_payload_and_pins_constant() {
    let f = fixture();
    let expected = -(ProjectivePoint::GENERATOR * f.server_secret);
    f.contribution.validate(&cluster(), &expected).unwrap();
    assert!(
        f.contribution
            .validate(&cluster(), &(ProjectivePoint::GENERATOR * f.server_secret))
            .is_err()
    );
    let mut other = cluster();
    other.operators.pop_last();
    assert!(f.contribution.validate(&other, &expected).is_err());
    let payload = sealed::sealed_payload(&[3; 16], &[4; 16], &Scalar::ONE);
    assert_eq!(payload.len(), 112);
    assert_eq!(&payload[2..38], uuid_string(&[3; 16]).as_bytes());
    assert_eq!(&payload[38..42], &[0x12, 72, 0x0a, 36]);
}
