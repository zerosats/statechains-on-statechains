//! Real proof/MPC/restart fixture on a signed SYNTHETIC root. This test does
//! not claim native Spark ingress or chain admission; the funded SDK run is
//! separate. Synthetic operators decrypt only their own native packages.
use super::*;
use crate::{
    leaf_signing::OperatorCommitments,
    receive::{ReceiveJournal, ReceiveParameters},
    standard_claim::{ClaimPlan, Operator},
};
use frost_secp256k1_tr as frost;
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet};
use zark_protocol::{
    point_bytes, scalar,
    spark_receive::{ClaimCluster, ClaimOperator, ReceivePlan},
};

#[test]
#[ignore = "requires pinned ownership/receive proof suites, Nargo, BB and CRS; synthetic native operators"]
fn real_proof_joint_receive_mpc_restart_and_dual_recovery() -> Result<()> {
    let suite = Suite::load()?;
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../work/zark-spark/real-receive-tests");
    fs::create_dir_all(&parent)?;
    let root = parent.join(hex::encode(random32()));
    private_directory(&root)?;
    for name in ["wallets", "wire", "proofs", "scratch"] {
        private_directory(&root.join(name))?;
    }
    suite.save_identity(&root)?;
    eprintln!(
        "Real receive fixture (synthetic native operators): {}",
        root.display()
    );
    let cluster = ClaimCluster {
        threshold: 2,
        operators: (1..=3u16)
            .map(|i| {
                (
                    hex::encode(Scalar::from(u64::from(i)).to_bytes()),
                    ClaimOperator {
                        index: i,
                        encryption_key: (ProjectivePoint::GENERATOR
                            * Scalar::from(u64::from(i) + 80))
                        .to_affine()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                    },
                )
            })
            .collect(),
    };
    let verifier = suite.receive_verifier(&cluster)?;
    let mut engine = suite.receive_engine(&root, &cluster, false)?;
    let coin = random32();
    let user = Zeroizing::new(random_scalar());
    let owner = Zeroizing::new(generate_secret());
    let session = Zeroizing::new(generate_secret());
    let intent = Intent {
        deployment: suite.deployment,
        coin,
        previous_state: origin_previous_state(&suite.deployment, &coin)?,
        operation: random32(),
        recipient_claim: origin_field(&suite.deployment, &coin, 0)?,
        revision: 1,
    };
    let allocate = Request::sign(
        intent.clone(),
        Command::Allocate {},
        &SigningKey::from_bytes(&session[..])?,
    )?;
    let allocated = engine.handle(&allocate)?;
    let server = super::point(&allocated, "server")?;
    let original = native::backing_at_delay(suite.deployment, coin, *user, server, 1900)?;
    let incoming = Zeroizing::new(random_scalar());
    let claim = ClaimPlan {
        deployment: suite.deployment,
        operation: intent.operation,
        transfer_id: "00000000-0000-4000-8000-000000000001".into(),
        leaf_id: "00000000-0000-4000-8000-000000000002".into(),
        incoming_user_key: (ProjectivePoint::GENERATOR * *incoming)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        joint_user_key: original.keys().user_key().to_vec(),
        threshold: 2,
        operators: cluster
            .operators
            .iter()
            .map(|(id, op)| {
                (
                    id.clone(),
                    Operator {
                        share_index: op.index,
                        encryption_key: op.encryption_key.clone(),
                    },
                )
            })
            .collect(),
    };
    use bitcoin::hashes::Hash;
    let params = ReceiveParameters {
        intent: intent.clone(),
        session: *session,
        user: user.to_bytes().into(),
        owner: *owner,
        server,
        server_salt: digest(&allocated, "server_salt")?,
        backing_salt: original.opening().salt,
        plan: ReceivePlan {
            salt: random32(),
            anchor_txid: original.anchor().outpoint.txid.to_byte_array(),
            anchor_vout: original.anchor().outpoint.vout,
            amount: 64_000,
            native_delay: 1900,
            operator: point_bytes(
                k256::PublicKey::from_sec1_bytes(original.keys().operator_key())?.to_projective(),
            )?
            .to_vec(),
            cluster: cluster.digest()?,
        },
        claim: claim.clone(),
    };
    let directory = root.join("wallets/receive");
    let mut journal = ReceiveJournal::create(
        &directory,
        &params,
        Zeroizing::new(incoming.to_bytes().into()),
        &verifier,
        cluster.clone(),
    )?;
    let prepare = journal.prepare_request()?;
    let prepared = engine.handle(&prepare)?;
    journal.bind_prepare(&prepared)?;
    let mut premature = Request::sign(
        intent.clone(),
        Command::FreezeOrigin {
            backing: journal.backing_commitment()?,
            capability: capability_commitment(&suite.deployment, &coin, &owner)?,
        },
        &SigningKey::from_bytes(&session[..])?,
    )?;
    ensure!(
        engine.handle(&premature).is_err(),
        "origin freeze before native claim signing accepted"
    );
    for id in cluster.operators.keys() {
        journal.bind_initial_frame(id, &engine.receive_initial_frame(&prepare, id)?)?;
        for step in 0..7 {
            let (request, frame) = journal.next_mpc_request(id)?;
            if step == 0 {
                drop(journal);
                journal = ReceiveJournal::open(&directory, &verifier)?;
                let (replay, exact) = journal.next_mpc_request(id)?;
                ensure!(
                    replay.encode()? == request.encode()? && exact == frame,
                    "wallet frame changed after reopen"
                );
            }
            let (response, reply) = engine.handle_receive_frame(&request, &frame)?;
            let reply = reply.context("receive frame aborted")?;
            if step == 0 {
                drop(engine);
                engine = suite.receive_engine(&root, &cluster, false)?;
                let (saved, exact) = engine.handle_receive_frame(&request, &frame)?;
                ensure!(
                    saved == response && exact.as_ref() == Some(&reply),
                    "signer frame replay changed after reopen"
                );
                let mut changed = frame.clone();
                changed[0] ^= 1;
                ensure!(
                    engine.handle_receive_frame(&request, &changed).is_err(),
                    "changed frame accepted"
                );
            }
            journal.bind_mpc_reply(&request, &response, &reply)?;
        }
        journal.finish_operator(id)?;
    }
    let packages = journal.packages()?;
    drop(journal);
    journal = ReceiveJournal::open(&directory, &verifier)?;
    ensure!(
        journal.packages()? == packages,
        "native ciphertext changed after wallet reopen"
    );
    // Native operator role: decrypt standard packets, then add the tweak to
    // its own old Shamir share. The test never sums the joint USER scalars.
    let mut operator_keys = BTreeMap::new();
    let mut vectors = BTreeMap::new();
    for (id, op) in &cluster.operators {
        let identity = Scalar::from(u64::from(op.index) + 80);
        let plain = decrypt(identity, &packages[id])?;
        ensure!(
            plain.len() == cluster.template_shape()?.0,
            "native protobuf package length"
        );
        let tweak = scalar(&plain[45..77])?;
        let old = scalar(&[77; 32])? - *incoming
            + Scalar::from(53u64) * Scalar::from(u64::from(op.index));
        let share = frost::keys::SigningShare::deserialize(&(old + tweak).to_bytes())?;
        let fid = frost::Identifier::deserialize(&hex::decode(id)?)?;
        operator_keys.insert(
            fid,
            frost::keys::KeyPackage::new(
                fid,
                share,
                frost::keys::VerifyingShare::from(share),
                frost::VerifyingKey::deserialize(original.keys().combined_key())?,
                2,
            ),
        );
        vectors.insert(id.clone(),json!({"index":op.index,"synthetic_operator_secret":hex::encode(identity.to_bytes()),"ciphertext":hex::encode(&packages[id]),"plaintext":hex::encode(plain)}));
    }
    let case = json!({"threshold":2,"leaf_id":claim.leaf_id,"incoming_user_key":hex::encode(&claim.incoming_user_key),"joint_user_key":hex::encode(&claim.joint_user_key),"operators":vectors});
    atomic_write(
        &root.join("native-claim-vector.private.json"),
        &serde_json::to_vec_pretty(
            &json!({"schema":"zark-spark/standard-claim-fixture/v1","synthetic":true,"live_ingress":false,"cases":[case]}),
        )?,
    )?;
    let mut native_nonces = Vec::new();
    let mut commitments = Vec::new();
    for _ in 0..2 {
        let mut nonces = BTreeMap::new();
        let mut public = OperatorCommitments::new();
        for (id, key) in operator_keys.iter().take(2) {
            let (n, c) = frost::round1::commit(key.signing_share(), &mut OsRng);
            nonces.insert(*id, n);
            public.insert(*id, c);
        }
        native_nonces.push(nonces);
        commitments.push(public);
    }
    journal.bind_operators([commitments[0].clone(), commitments[1].clone()])?;
    let authorization = journal.authorization()?;
    let input = journal.prover_toml()?;
    let proof = suite.prove(
        "receive",
        &input,
        &authorization.encode()?,
        &root.join("proofs/receive"),
    )?;
    let mut corrupt = proof.clone();
    corrupt[0] ^= 1;
    let bad = Request::sign(
        intent.clone(),
        Command::ReceiveIssue {
            statement: authorization.encode()?,
            proof: corrupt,
        },
        &SigningKey::from_bytes(&session[..])?,
    )?;
    ensure!(
        engine.handle(&bad).is_err(),
        "real signer accepted invalid receive proof"
    );
    let issue = journal.issue_request(proof, &verifier, &root.join("scratch"))?;
    let issued = engine.handle(&issue)?;
    drop(engine);
    engine = suite.receive_engine(&root, &cluster, false)?;
    ensure!(
        engine.handle(&issue)? == issued,
        "receive issue replay changed"
    );
    journal.bind_partials(&issued)?;
    drop(journal);
    journal = ReceiveJournal::open(&directory, &verifier)?;
    let (refunds, sighashes) = journal.expected_refunds()?;
    let mut signed = Vec::new();
    for i in 0..2 {
        let user = journal.contribution(i)?;
        let uid = frost::Identifier::derive(b"user")?;
        let mut all = commitments[i].clone();
        all.insert(uid, user.commitment);
        let groups = vec![
            commitments[i].keys().copied().collect(),
            BTreeSet::from([uid]),
        ];
        let package =
            frost::SigningPackage::new_with_participants_groups(all, Some(groups), &sighashes[i]);
        let mut shares = BTreeMap::new();
        let mut verifying = BTreeMap::new();
        for (id, nonce) in &native_nonces[i] {
            let key = &operator_keys[id];
            shares.insert(
                *id,
                frost::round2::sign_with_tweak(&package, nonce, key, Some(&[] as &[u8]))?,
            );
            verifying.insert(*id, *key.verifying_share());
        }
        shares.insert(uid, user.signature_share);
        verifying.insert(
            uid,
            frost::keys::VerifyingShare::deserialize(original.keys().user_key())?,
        );
        let signature = frost::aggregate_with_tweak(
            &package,
            &shares,
            &frost::keys::PublicKeyPackage::new(
                verifying,
                frost::VerifyingKey::deserialize(original.keys().combined_key())?,
                None,
            ),
            Some(&[] as &[u8]),
        )?;
        let mut tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&refunds[i])?;
        tx.input[0].witness = bitcoin::Witness::from_slice(&[signature.serialize()?]);
        signed.push(bitcoin::consensus::serialize(&tx));
    }
    let backing = PrivateBacking::new_received_root(
        original.anchor().clone(),
        original.keys().clone(),
        crate::initial_exit::InitialRootLeafExitV1::new(
            original.prefix().root_node.clone(),
            signed[0].clone(),
            signed[1].clone(),
        ),
        1900,
        params.backing_salt,
    )?;
    let recovery = PrivateRecovery::prepare(
        &backing,
        RecoveryParameters {
            intent: intent.clone(),
            session: allocate.session,
            server,
            server_salt: digest(&allocated, "server_salt")?,
            user: params.user,
            next_capability: capability_commitment(&suite.deployment, &coin, &owner)?,
            payout_secret: generate_secret(),
            fee: 500,
            owner_index: 1,
            schedule: suite.schedule(),
        },
    )?;
    ensure!(
        recovery.frozen().backing == journal.backing_commitment()?,
        "received backing differs from claim proof"
    );
    drop(journal);
    let mut recovery = RecoveryJournal::create(
        &root.join("wallets/recovery"),
        Predecessor::Origin,
        &backing,
        recovery,
        *session,
    )?;
    premature = Request::sign(
        intent,
        Command::FreezeOrigin {
            backing: recovery.recovery().frozen().backing,
            capability: recovery.recovery().next_capability(),
        },
        &SigningKey::from_bytes(&session[..])?,
    )?;
    engine.handle(&premature)?;
    let req = recovery.prepare_request()?;
    bind_nonce_reply(&mut recovery, &engine.handle(&req)?)?;
    let issuance = origin_issuance(recovery.recovery(), &suite.verifier()?)?;
    let input = origin_prover_toml(recovery.recovery(), &owner, &suite.verifier()?)?;
    let proof = suite.prove(
        "deposit",
        &input,
        &issuance.encode()?,
        &root.join("proofs/origin"),
    )?;
    let req =
        recovery.issue_request(&issuance, &proof, &suite.verifier()?, &root.join("scratch"))?;
    let response = engine.handle(&req)?;
    recovery.complete_issuance(
        issued_response(&response)?,
        &suite.verifier()?,
        &root.join("scratch"),
    )?;
    drop(recovery);
    let mut recovery = RecoveryJournal::open(&root.join("wallets/recovery"))?;
    let ack = recovery.saved_recovery_acknowledgement(&suite.verifier()?, &root.join("scratch"))?;
    ensure!(
        engine.handle(&ack)?["accepted"] == true,
        "origin recovery acknowledgement failed"
    );
    atomic_write(
        &root.join("public-report.json"),
        &serde_json::to_vec_pretty(
            &json!({"status":"passed","live_spark_transfer":false,"synthetic_native_operators":true,
        "real_receive_proof":true,"real_origin_proof":true,"joint_mpc_operator_packages":3,"ordinary_user_claim_refunds":2,"dual_recovery_reopened_before_ack":true,"spark_modified":false}),
        )?,
    )?;
    eprintln!(
        "PASS real receive proof/MPC/recovery fixture: {}",
        root.join("public-report.json").display()
    );
    Ok(())
}
fn decrypt(secret: Scalar, cipher: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        AesGcm,
        aead::{AeadInPlace, KeyInit, consts::U16},
    };
    let ephemeral = k256::PublicKey::from_sec1_bytes(&cipher[..65])?;
    let shared = ephemeral.to_projective() * secret;
    let mut ikm = Zeroizing::new(cipher[..65].to_vec());
    ikm.extend_from_slice(shared.to_affine().to_encoded_point(false).as_bytes());
    let mut key = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, &ikm)
        .expand(&[], &mut *key)
        .map_err(|_| anyhow::anyhow!("fixture HKDF"))?;
    let nonce: [u8; 16] = cipher[65..81].try_into()?;
    let tag: [u8; 16] = cipher[81..97].try_into()?;
    let mut plain = cipher[97..].to_vec();
    AesGcm::<aes::Aes256, U16>::new_from_slice(&*key)
        .unwrap()
        .decrypt_in_place_detached(&nonce.into(), b"", &mut plain, &tag.into())
        .map_err(|_| anyhow::anyhow!("native ECIES authentication"))?;
    Ok(plain)
}
