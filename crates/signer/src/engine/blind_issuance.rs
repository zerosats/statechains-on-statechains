//! Blinded-response arithmetic after the engine has authorized a frozen request.
//!
//! This private primitive neither authorizes issuance nor persists it. Its caller
//! must bind every member to the proof-verified successor state and commit the
//! whole response before release. Keeping the arithmetic here avoids introducing
//! a clear-message signing path for backing-specific recovery variants.
use anyhow::{Context, Result, ensure};
use k256::ProjectivePoint;
use zark_protocol::{handoff::Digest, point_bytes, scalar};
use zeroize::{Zeroize, Zeroizing};

/// Borrowed fields from a statement already matched against frozen preparation.
pub(super) struct FrozenResponse<'a> {
    pub nonce_point: &'a [u8],
    pub nonce_commitment: &'a Digest,
    pub blinded_challenge: &'a Digest,
}

/// Compute a complete response set before consuming any nonce.
///
/// The transaction/checkpoint boundary remains with `Engine`. A malformed later
/// member must not consume an earlier member's nonce. Equal or opposite nonces
/// across variants are forbidden: either reuse can reveal the signing share.
pub(super) fn issue<const N: usize>(
    share: &Digest,
    nonces: [&mut Option<Digest>; N],
    frozen: [FrozenResponse<'_>; N],
) -> Result<[Digest; N]> {
    ensure!(N > 0, "empty blind response set");
    let secret = Zeroizing::new(scalar(share)?);
    let mut responses = Zeroizing::new([[0; 32]; N]);
    for index in 0..N {
        let nonce = Zeroizing::new(scalar(
            nonces[index].as_ref().context("frozen nonce missing")?,
        )?);
        let binding = &frozen[index];
        let public = point_bytes(ProjectivePoint::GENERATOR * *nonce)?;
        ensure!(
            public.as_slice() == binding.nonce_point,
            "blind response nonce differs from frozen point"
        );
        ensure!(
            *binding.nonce_commitment != [0; 32],
            "zero blind response nonce commitment"
        );
        for previous in &frozen[..index] {
            ensure!(
                previous.nonce_point[..32] != binding.nonce_point[..32],
                "blind response variants reuse a nonce"
            );
            ensure!(
                previous.nonce_commitment != binding.nonce_commitment,
                "blind response variants reuse a nonce commitment"
            );
        }
        let partial = Zeroizing::new(*nonce + scalar(binding.blinded_challenge)? * *secret);
        responses[index] = partial.to_bytes().into();
    }
    // All fallible validation and arithmetic precede consumption. The engine's
    // retained response, rather than a new nonce calculation, serves exact retry.
    for slot in nonces {
        slot.as_mut()
            .expect("all frozen nonces validated")
            .zeroize();
        *slot = None;
    }
    Ok(*responses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;

    fn number(value: u64) -> Digest {
        Scalar::from(value).to_bytes().into()
    }

    fn public(secret: Digest) -> [u8; 64] {
        point_bytes(ProjectivePoint::GENERATOR * scalar(&secret).unwrap()).unwrap()
    }

    fn binding<'a>(
        point: &'a [u8; 64],
        commitment: &'a Digest,
        challenge: &'a Digest,
    ) -> FrozenResponse<'a> {
        FrozenResponse {
            nonce_point: point,
            nonce_commitment: commitment,
            blinded_challenge: challenge,
        }
    }

    #[test]
    fn two_variants_match_blind_equations_and_consume_all_nonces() -> Result<()> {
        let share = number(7);
        let mut first = Some(number(11));
        let mut second = Some(number(13));
        let points = [public(first.unwrap()), public(second.unwrap())];
        let challenges = [number(17), number(19)];
        let commitments = [[1; 32], [2; 32]];
        let partials = issue(
            &share,
            [&mut first, &mut second],
            [
                binding(&points[0], &commitments[0], &challenges[0]),
                binding(&points[1], &commitments[1], &challenges[1]),
            ],
        )?;
        for index in 0..2 {
            assert_eq!(
                ProjectivePoint::GENERATOR * scalar(&partials[index])?,
                zark_protocol::point(&points[index])?
                    + zark_protocol::point(&public(share))? * scalar(&challenges[index])?
            );
        }
        assert!(first.is_none() && second.is_none());
        assert!(
            issue(
                &share,
                [&mut first],
                [binding(&points[0], &commitments[0], &challenges[0])]
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn invalid_later_challenge_leaves_entire_nonce_set_untouched() {
        let mut first = Some(number(11));
        let mut second = Some(number(13));
        let before = [first, second];
        let points = [public(first.unwrap()), public(second.unwrap())];
        assert!(
            issue(
                &number(7),
                [&mut first, &mut second],
                [
                    binding(&points[0], &[1; 32], &number(17)),
                    binding(&points[1], &[2; 32], &[255; 32]),
                ],
            )
            .is_err()
        );
        assert_eq!([first, second], before);
    }

    #[test]
    fn repeated_or_opposite_nonces_and_duplicate_commitments_are_rejected() {
        for (other, commitment) in [
            (number(11), [2; 32]),
            ((-Scalar::from(11u64)).to_bytes().into(), [2; 32]),
            (number(13), [1; 32]),
        ] {
            let mut first = Some(number(11));
            let mut second = Some(other);
            let before = [first, second];
            let points = [public(first.unwrap()), public(second.unwrap())];
            assert!(
                issue(
                    &number(7),
                    [&mut first, &mut second],
                    [
                        binding(&points[0], &[1; 32], &number(17)),
                        binding(&points[1], &commitment, &number(19)),
                    ],
                )
                .is_err()
            );
            assert_eq!([first, second], before);
        }
    }

    #[test]
    fn frozen_point_mismatch_does_not_consume_nonce() {
        let mut nonce = Some(number(11));
        assert!(
            issue(
                &number(7),
                [&mut nonce],
                [binding(&public(number(13)), &[1; 32], &number(17))],
            )
            .is_err()
        );
        assert_eq!(nonce, Some(number(11)));
    }

    #[test]
    fn zero_challenges_and_zero_partials_preserve_existing_arithmetic() -> Result<()> {
        // A canonical challenge and response may be zero. The state/proof layer
        // controls authority validity; arithmetic must not add new exclusions.
        for (share, nonce, challenge, expected) in [
            (number(7), number(11), number(0), number(11)),
            (
                number(7),
                (-Scalar::from(119u64)).to_bytes().into(),
                number(17),
                number(0),
            ),
            (number(0), number(11), number(17), number(11)),
        ] {
            let point = public(nonce);
            let mut slot = Some(nonce);
            let [partial] = issue(&share, [&mut slot], [binding(&point, &[1; 32], &challenge)])?;
            assert_eq!(partial, expected);
            assert!(slot.is_none());
        }
        Ok(())
    }
}
