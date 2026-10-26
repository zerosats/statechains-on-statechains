//! Current owner keys, independent of historical component shares or PoPs.
use crate::{initial_exit::NativeLeafKeys, leaf_signing::OperatorCommitments, signing_session};
use anyhow::{Result, ensure};
use frost_core::two_group::{self, SignerGroup, TwoGroupSigningPackage};
use frost_secp256k1_tr::{
    self as frost,
    keys::{EvenY, Tweak},
};
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use zark_protocol::{handoff::Digest, hash, point, point_bytes, scalar};
use zeroize::Zeroizing;

/// Wallet-only checked current USER decomposition. The server input is only a
/// public point; no API accepts the server's scalar. This type deliberately has
/// no serialization or Debug implementation.
pub struct CurrentUserKey {
    native: NativeLeafKeys,
    user: Zeroizing<Scalar>,
    server: ProjectivePoint,
    binding: Digest,
    combined: frost::VerifyingKey,
    output: frost::VerifyingKey,
}

impl CurrentUserKey {
    pub fn new(native: NativeLeafKeys, server: [u8; 64], user: [u8; 32]) -> Result<Self> {
        let user = Zeroizing::new(user);
        let user = Zeroizing::new(scalar(&user[..])?);
        ensure!(*user != Scalar::ZERO, "zero native wallet share");
        let server = point(&server)?;
        let wallet = ProjectivePoint::GENERATOR * *user;
        let native_user = k256::PublicKey::from_sec1_bytes(native.user_key())?.to_projective();
        // Equality precedes any even-y normalization. An x-only comparison
        // would accept the wrong additive decomposition and native key parity.
        ensure!(
            wallet + server == native_user,
            "current native USER decomposition differs"
        );
        let combined = frost::VerifyingKey::deserialize(native.combined_key())?;
        let output = *frost::keys::PublicKeyPackage::new(BTreeMap::new(), combined, None)
            .tweak(Some(&[] as &[u8]))
            .verifying_key();
        let scope = native.scope();
        let binding = hash(&[
            b"ZARK/spark/current-native-user/v1",
            &scope.deployment,
            &scope.coin,
            &[scope.purpose as u8],
            native.user_key(),
            native.operator_key(),
            native.combined_key(),
            &point_bytes(wallet)?,
            &point_bytes(server)?,
        ]);
        Ok(Self {
            native,
            user,
            server,
            binding,
            combined,
            output,
        })
    }

    pub fn native_keys(&self) -> &NativeLeafKeys {
        &self.native
    }
    pub fn server_point(&self) -> Result<[u8; 64]> {
        point_bytes(self.server)
    }
    pub fn wallet_point(&self) -> Result<[u8; 64]> {
        point_bytes(ProjectivePoint::GENERATOR * *self.user)
    }
    pub fn output_key(&self) -> Result<Vec<u8>> {
        Ok(self.output.serialize()?)
    }
    pub(crate) fn binding(&self) -> Digest {
        self.binding
    }
    pub(super) fn wallet_scalar(&self) -> Scalar {
        *self.user
    }

    pub fn verify_partials(
        &self,
        sighash: Digest,
        operators: OperatorCommitments,
        users: [&[u8]; 2],
        partials: [&[u8]; 2],
    ) -> Result<()> {
        crate::leaf_signing::verify_additive_user_partials(
            self.combined,
            self.output,
            [ProjectivePoint::GENERATOR * *self.user, self.server],
            sighash,
            operators,
            users,
            partials,
        )
    }

    fn participant_package(&self) -> Result<frost::keys::KeyPackage> {
        // Spark secondary participant 1 has lambda=2, so additive wallet u
        // is encoded as u/2. Neither USER participant carries the TapTweak.
        let encoded = Zeroizing::new(*self.user * Scalar::from(2u64).invert().unwrap());
        let share = frost::keys::SigningShare::deserialize(&encoded.to_bytes())?;
        let raw = frost::keys::KeyPackage::new(
            frost::Identifier::try_from(1u16)?,
            share,
            frost::keys::VerifyingShare::from(share),
            self.combined,
            2,
        )
        .into_even_y(Some(self.combined.has_even_y()));
        Ok(frost::keys::KeyPackage::new(
            *raw.identifier(),
            *raw.signing_share(),
            *raw.verifying_share(),
            self.output,
            2,
        ))
    }
}

/// Wallet nonce, consumed on success or error. Exact private bytes can be
/// retained by a wallet journal before releasing its public commitment.
pub struct WalletNonce {
    binding: Digest,
    inner: frost::round1::SigningNonces,
    public: frost::round1::SigningCommitments,
}

impl WalletNonce {
    pub fn prepare(key: &CurrentUserKey) -> Result<Self> {
        let package = key.participant_package()?;
        let (inner, public) = frost::round1::commit(package.signing_share(), &mut OsRng);
        Ok(Self {
            binding: key.binding(),
            inner,
            public,
        })
    }
    pub fn commitment(&self) -> Result<Vec<u8>> {
        Ok(self.public.serialize()?)
    }
    /// Private prover inputs; never part of a signer/operator request.
    pub fn private_scalars(&self) -> Result<Zeroizing<[[u8; 32]; 2]>> {
        let hiding = Zeroizing::new(self.inner.hiding().serialize());
        let binding = Zeroizing::new(self.inner.binding().serialize());
        Ok(Zeroizing::new([
            hiding.as_slice().try_into()?,
            binding.as_slice().try_into()?,
        ]))
    }
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        signing_session::encode(
            "blind-native-wallet",
            1,
            self.binding,
            &self.inner,
            &self.commitment()?,
        )
    }
    pub fn decode_private(bytes: &[u8], key: &CurrentUserKey) -> Result<Self> {
        let (inner, public) =
            signing_session::decode(bytes, "blind-native-wallet", 1, key.binding())?;
        let public = signing_session::check_public(&inner, &public)?;
        Ok(Self {
            binding: key.binding(),
            inner,
            public,
        })
    }
    pub fn sign(
        self,
        key: &CurrentUserKey,
        sighash: Digest,
        operators: OperatorCommitments,
        users: [&[u8]; 2],
    ) -> Result<Digest> {
        ensure!(
            self.binding == key.binding(),
            "native wallet nonce key changed"
        );
        let secondary = (1u16..=2)
            .zip(users)
            .map(|(id, bytes)| {
                Ok((
                    frost::Identifier::try_from(id)?,
                    frost::round1::SigningCommitments::deserialize(bytes)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(
            secondary.get(&frost::Identifier::try_from(1u16)?) == Some(&self.public),
            "native wallet nonce commitment replaced"
        );
        let transcript = TwoGroupSigningPackage::<frost::Secp256K1Sha256TR>::new(
            operators, secondary, &sighash,
        )?;
        two_group::sign(
            &transcript,
            &self.inner,
            &key.participant_package()?,
            SignerGroup::Secondary,
        )?
        .serialize()
        .try_into()
        .map_err(|_| anyhow::anyhow!("native wallet partial length"))
    }
}
