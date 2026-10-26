//! Additive ordinary receive tweak: one request, one released share set.
//!
//! The wallet sends u = b - x_w. The signer seals Feldman shares of
//! t = u - x_s = b - p for each operator, but never the protobuf around them:
//! leaf IDs, proofs and public shares are completed wallet-side, so operators
//! all receive the single polynomial the wallet checked against B - P.
//! The signer must erase u, t and the shares, and must not collude with the
//! incoming sender.
use super::{Coin, Engine, Stage, Workflow};
use anyhow::{Context, Result, ensure};
use k256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint};
use serde_json::{Map, Value, json};
use zark_protocol::{random_scalar, scalar, spark_ecies, spark_lineage::Digest};
use zeroize::Zeroizing;

impl Engine {
    pub(super) fn check_receive_tweak(w: &Workflow, tweak: &Digest) -> Result<()> {
        ensure!(
            w.additive && w.stage == Stage::Prepared,
            "receive tweak already released or not additive"
        );
        ensure!(scalar(tweak)? != Scalar::ZERO, "receive tweak is zero");
        Ok(())
    }

    /// Persisted state holds only the stage change; the response journal keeps
    /// sealed shares and public coefficients for exact retries.
    pub(super) fn release_receive_tweak(&self, coin: &mut Coin, tweak: &Digest) -> Result<Value> {
        let cluster = &self
            .receive
            .as_ref()
            .context("receive runtime missing")?
            .cluster;
        let (length, offset) = cluster.template_shape()?;
        let w = coin
            .receive
            .as_mut()
            .context("receive preparation missing")?;
        Self::check_receive_tweak(w, tweak)?;
        let t = Zeroizing::new(scalar(tweak)? - scalar(&coin.secret)?);
        ensure!(*t != Scalar::ZERO, "receive tweak cancels the signer share");
        let slope = loop {
            let slope = Zeroizing::new(random_scalar());
            if cluster
                .operators
                .values()
                .all(|op| *t + *slope * Scalar::from(u64::from(op.index)) != Scalar::ZERO)
            {
                break slope;
            }
        };
        let mut operators = Map::new();
        for (id, op) in &cluster.operators {
            let share = Zeroizing::new(*t + *slope * Scalar::from(u64::from(op.index)));
            let bytes = Zeroizing::new(<[u8; 32]>::from(share.to_bytes()));
            let (sealed, hash_key) =
                spark_ecies::seal_slot(&op.encryption_key, length, offset, &bytes)?;
            operators.insert(
                id.clone(),
                json!({"sealed":hex::encode(sealed),"hash_key":hex::encode(hash_key)}),
            );
        }
        let coefficients = [*t, *slope].map(|c| {
            hex::encode(
                (ProjectivePoint::GENERATOR * c)
                    .to_affine()
                    .to_encoded_point(true),
            )
        });
        w.stage = Stage::TweaksReady;
        Ok(json!({"coefficients":coefficients,"operators":operators,"tweaks_ready":true}))
    }
}
