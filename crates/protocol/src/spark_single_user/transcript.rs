//! Independent ordinary (untagged, single-USER) Spark FROST transcript.
use super::{Digest, Opening};
use crate::{
    even, hash, point, point_bytes, reduce, scalar,
    spark_native::{Participant, frost_h1, native_compressed, native_taproot},
    tagged_hash,
};
use anyhow::{Result, ensure};
use k256::ProjectivePoint;
use zeroize::Zeroizing;
pub const USER_IDENTIFIER: Digest = [
    104, 125, 166, 77, 82, 161, 108, 111, 199, 146, 198, 252, 131, 30, 193, 175, 167, 151, 169, 31,
    119, 84, 150, 104, 166, 181, 66, 31, 18, 193, 172, 119,
];
pub fn blinded_challenge(
    server: [u8; 64],
    nonce: [u8; 64],
    combined: [u8; 64],
    message: Digest,
    opening: &Opening,
    operators: &[Participant; 2],
) -> Result<Digest> {
    let server = point(&server)?;
    let a = Zeroizing::new(scalar(&opening.alpha)?);
    let b = Zeroizing::new(scalar(&opening.beta)?);
    let t = Zeroizing::new(scalar(&opening.binding)?);
    ensure!(
        *a != k256::Scalar::ZERO && *b != k256::Scalar::ZERO && *t != k256::Scalar::ZERO,
        "zero single-USER opening"
    );
    ensure!(
        operators[0].identifier < operators[1].identifier,
        "single-USER operator order"
    );
    ensure!(
        operators.iter().all(|p| p.identifier != USER_IDENTIFIER),
        "operator collides with USER"
    );
    let user = Participant {
        identifier: USER_IDENTIFIER,
        hiding: point_bytes(point(&nonce)? + ProjectivePoint::GENERATOR * *a + server * *b)?,
        binding: point_bytes(ProjectivePoint::GENERATOR * *t)?,
    };
    let mut all = vec![&operators[0], &operators[1], &user];
    all.sort_by_key(|p| p.identifier);
    let mut list = Vec::new();
    for p in &all {
        ensure!(
            scalar(&p.identifier)? != k256::Scalar::ZERO,
            "zero single-USER operator id"
        );
        list.extend_from_slice(&p.identifier);
        list.extend_from_slice(&native_compressed(point(&p.hiding)?)?);
        list.extend_from_slice(&native_compressed(point(&p.binding)?)?);
    }
    let (output, coefficient) = native_taproot(point(&combined)?)?;
    let h4 = hash(&[b"FROST-secp256k1-SHA256-TR-v1msg", &message]);
    let h5 = hash(&[b"FROST-secp256k1-SHA256-TR-v1com", &list]);
    let mut total = ProjectivePoint::IDENTITY;
    for p in all {
        let preimage = [
            native_compressed(output)?.as_slice(),
            h4.as_slice(),
            h5.as_slice(),
            p.identifier.as_slice(),
        ]
        .concat();
        total += point(&p.hiding)? + point(&p.binding)? * frost_h1(&preimage);
    }
    let (r, sign) = even(total)?;
    let e = reduce(tagged_hash(
        "BIP0340/challenge",
        &[
            &point_bytes(r)?[..32],
            &point_bytes(output)?[..32],
            &message,
        ],
    ));
    Ok((*b + sign * e * coefficient).to_bytes().into())
}
