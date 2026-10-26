//! Exact pinned Spark `MpcSubmission.AuthorizationPayload` and
//! `MpcRefundSighashesDigest` bytes (common/hashstructure). Integers are
//! length-prefixed 8-byte big-endian values, including protobuf `uint32` enums.
use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};

pub type Digest = [u8; 32];
/// `common.SignatureScheme` values carried inside the payload.
pub const SCHEME_ECDSA: u64 = 1;
pub const SCHEME_SCHNORR: u64 = 2;

/// One leaf's BIP-341 refund sighashes. An absent flavour hashes as empty bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafRefunds {
    pub leaf_id: [u8; 16],
    pub cpfp: Digest,
    pub direct: Option<Digest>,
    pub direct_from_cpfp: Option<Digest>,
}

/// One authorized leaf exactly as `ParseMpcSubmission` exposes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedLeaf {
    pub leaf_id: [u8; 16],
    pub amount: u64,
    pub owner_signing: [u8; 33],
    pub mask_commitment: [u8; 33],
    pub receiver_identity: [u8; 33],
    pub secret_cipher: Vec<u8>,
    pub signature_scheme: u64,
    pub signature: Vec<u8>,
    /// One coefficient-commitment vector per submission position, in position order.
    pub proofs: Vec<Vec<[u8; 33]>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationPayload {
    pub transfer_id: [u8; 16],
    pub expiry: u64,
    pub positions: Vec<u64>,
    pub leaves: Vec<AuthorizedLeaf>,
    pub refund_digest: Digest,
}

impl AuthorizationPayload {
    pub fn hash(&self) -> Result<Digest> {
        ensure!(
            !self.positions.is_empty() && !self.leaves.is_empty(),
            "empty Spark MPC authorization"
        );
        let mut hash = StructuredHash::new("send authorization v1");
        hash.bytes(&self.transfer_id);
        hash.uint(self.expiry);
        hash.uint(self.positions.len() as u64);
        for position in &self.positions {
            hash.uint(*position);
        }
        hash.uint(self.leaves.len() as u64);
        let mut leaves: Vec<_> = self.leaves.iter().collect();
        leaves.sort_by_key(|leaf| uuid_string(&leaf.leaf_id));
        for leaf in leaves {
            ensure!(
                leaf.proofs.len() == self.positions.len(),
                "Spark MPC commitment vectors differ from positions"
            );
            hash.bytes(uuid_string(&leaf.leaf_id).as_bytes());
            hash.uint(leaf.amount);
            hash.bytes(&leaf.owner_signing);
            hash.bytes(&leaf.mask_commitment);
            hash.bytes(&leaf.receiver_identity);
            hash.bytes(&leaf.secret_cipher);
            hash.uint(leaf.signature_scheme);
            hash.bytes(&leaf.signature);
            for vector in &leaf.proofs {
                hash.uint(vector.len() as u64);
                for proof in vector {
                    hash.bytes(proof);
                }
            }
        }
        hash.bytes(&self.refund_digest);
        Ok(hash.finish())
    }
}

/// Leaves enter sorted by their UUID string, independent of input order.
pub fn refund_digest(leaves: &[LeafRefunds]) -> Digest {
    let mut sorted: Vec<_> = leaves.iter().collect();
    sorted.sort_by_key(|leaf| uuid_string(&leaf.leaf_id));
    let mut hash = StructuredHash::new("refund sighashes v1");
    hash.uint(sorted.len() as u64);
    for leaf in sorted {
        hash.bytes(uuid_string(&leaf.leaf_id).as_bytes());
        hash.bytes(&leaf.cpfp);
        hash.bytes(leaf.direct.as_ref().map_or(&[][..], |v| v));
        hash.bytes(leaf.direct_from_cpfp.as_ref().map_or(&[][..], |v| v));
    }
    hash.finish()
}

/// Go `uuid.UUID.String()`: lowercase, hyphenated 8-4-4-4-12.
pub fn uuid_string(raw: &[u8; 16]) -> String {
    let h = hex::encode(raw);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

struct StructuredHash(Sha256);
impl StructuredHash {
    fn new(version: &str) -> Self {
        let mut tag = Sha256::new();
        for component in ["spark", "transfer mpc", version] {
            tag.update((component.len() as u64).to_be_bytes());
            tag.update(component.as_bytes());
        }
        let tag: Digest = tag.finalize().into();
        let mut hash = Sha256::new();
        hash.update(tag);
        hash.update(tag);
        Self(hash)
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
    }
    fn uint(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    fn finish(self) -> Digest {
        self.0.finalize().into()
    }
}
