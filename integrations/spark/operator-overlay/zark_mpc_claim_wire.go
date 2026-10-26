// Installed only by the explicit, source-pinned Zark claim-v1 overlay.
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/keys"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"google.golang.org/protobuf/encoding/protowire"
)

const zarkClaimMagic = "ZARK-MPC-CLAIM-v1\x00"
const zarkClaimMarkerField protowire.Number = 50001
const zarkClaimMaxBytes = 1024 * 1024

type zarkClaimScope struct {
	Deployment [32]byte `json:"deployment"`
	Coin       [32]byte `json:"coin"`
	Purpose    string   `json:"purpose"`
}
type zarkClaimPublicShare struct {
	Scope     zarkClaimScope `json:"scope"`
	Position  uint16         `json:"position"`
	PublicKey string         `json:"public_key"`
	Proof     string         `json:"proof_of_possession"`
}
type zarkClaimContext struct {
	Scope           zarkClaimScope `json:"scope"`
	Operation       [32]byte       `json:"operation"`
	TransferID      string         `json:"transfer_id"`
	LeafID          string         `json:"leaf_id"`
	Amount          uint64         `json:"amount_sats"`
	Receiver        []byte         `json:"receiver_identity"`
	Incoming        []byte         `json:"incoming_user_key"`
	Operator        []byte         `json:"operator_key"`
	Backing         []byte         `json:"backing_key"`
	BackingTx       [32]byte       `json:"backing_tx_digest"`
	DirectBackingTx [32]byte       `json:"direct_backing_tx_digest"`
	Refunds         struct {
		CPFP           []byte `json:"cpfp"`
		Direct         []byte `json:"direct"`
		DirectFromCPFP []byte `json:"direct_from_cpfp"`
	} `json:"refunds"`
	Cluster struct {
		Threshold uint64            `json:"threshold"`
		Operators map[string][]byte `json:"operators"`
	} `json:"cluster"`
}
type zarkClaimTranscript struct {
	Claim     zarkClaimContext `json:"claim"`
	Authority struct {
		Members []zarkClaimPublicShare `json:"members"`
	} `json:"authority"`
}
type zarkClaimContribution struct {
	Position uint16            `json:"position"`
	Binding  [32]byte          `json:"binding"`
	Proofs   [][]byte          `json:"proofs"`
	Sealed   map[string][]byte `json:"sealed_shares"`
}
type zarkClaimEnvelope struct {
	Transcript    []byte `json:"transcript"`
	Contributions []struct {
		Body      []byte `json:"body"`
		Signature []byte `json:"signature"`
	} `json:"contributions"`
}
type zarkDecodedClaim struct {
	transcript    zarkClaimTranscript
	envelope      zarkClaimEnvelope
	contributions [2]zarkClaimContribution
	public        keys.Public
	proofs        [][]byte
	binding       [32]byte
	marker        []byte
}

func zarkHash(domain string, raw []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(raw)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
func zarkPoint(raw []byte) (keys.Public, error) {
	key, err := keys.ParsePublicKey(raw)
	if err != nil || len(raw) != 33 || !bytes.Equal(key.Serialize(), raw) {
		return keys.Public{}, fmt.Errorf("invalid Zark claim point")
	}
	return key, nil
}
func zarkVerify(public keys.Public, digest [32]byte, raw []byte) error {
	signature, err := schnorr.ParseSignature(raw)
	if err != nil || !signature.Verify(digest[:], public.ToBTCEC()) {
		return fmt.Errorf("invalid Zark claim holder signature")
	}
	return nil
}
func zarkSum(first, second keys.Public) (keys.Public, error) {
	return zarkPoint(first.Add(second).Serialize())
}

func decodeZarkClaim(config *so.Config, raw []byte) (*zarkDecodedClaim, error) {
	if len(raw) > zarkClaimMaxBytes || !bytes.HasPrefix(raw, []byte(zarkClaimMagic)) {
		return nil, fmt.Errorf("invalid Zark claim envelope")
	}
	var out zarkDecodedClaim
	if err := zarkJSON(raw[len(zarkClaimMagic):], &out.envelope); err != nil {
		return nil, err
	}
	if err := zarkJSON(out.envelope.Transcript, &out.transcript); err != nil {
		return nil, err
	}
	claim := &out.transcript.Claim
	if claim.Scope.Purpose != "leaf_signing" || claim.Scope.Deployment == [32]byte{} || claim.Scope.Coin == [32]byte{} || claim.Operation == [32]byte{} || claim.BackingTx == [32]byte{} || claim.DirectBackingTx == [32]byte{} || claim.Amount == 0 || claim.Amount > 2100000000000000 {
		return nil, fmt.Errorf("invalid Zark claim scope")
	}
	for _, id := range []string{claim.TransferID, claim.LeafID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, fmt.Errorf("noncanonical Zark claim UUID")
		}
	}
	incoming, err := zarkPoint(claim.Incoming)
	if err != nil {
		return nil, err
	}
	operator, err := zarkPoint(claim.Operator)
	if err != nil {
		return nil, err
	}
	backing, err := zarkPoint(claim.Backing)
	if err != nil || !operator.Add(incoming).Equals(backing) {
		return nil, fmt.Errorf("Zark claim backing key mismatch")
	}
	if _, err := zarkPoint(claim.Receiver); err != nil {
		return nil, err
	}
	if config == nil || config.Threshold < 2 || config.Threshold > uint64(len(config.SigningOperatorMap)) || len(config.SigningOperatorMap) > 16 || claim.Cluster.Threshold != config.Threshold || len(claim.Cluster.Operators) != len(config.SigningOperatorMap) {
		return nil, fmt.Errorf("Zark claim cluster changed")
	}
	identities := map[string]bool{}
	for id, configured := range config.SigningOperatorMap {
		index := new(big.Int).SetUint64(configured.ID + 1).FillBytes(make([]byte, 32))
		if hex.EncodeToString(index) != id || configured.Identifier != id || !bytes.Equal(claim.Cluster.Operators[id], configured.IdentityPublicKey.Serialize()) || identities[string(claim.Cluster.Operators[id])] {
			return nil, fmt.Errorf("Zark claim operator changed")
		}
		identities[string(claim.Cluster.Operators[id])] = true
	}
	if len(out.transcript.Authority.Members) != 2 || len(out.envelope.Contributions) != 2 {
		return nil, fmt.Errorf("Zark claim requires both holders")
	}
	out.binding = zarkHash("ZARK/spark/mpc-claim/transcript/v1", out.envelope.Transcript)
	var members [2]keys.Public
	for i, member := range out.transcript.Authority.Members {
		rawPublic, err := hex.DecodeString(member.PublicKey)
		if err != nil || hex.EncodeToString(rawPublic) != member.PublicKey || member.Scope != claim.Scope || member.Position != uint16(i+1) {
			return nil, fmt.Errorf("invalid Zark claim member")
		}
		members[i], err = zarkPoint(rawPublic)
		if err != nil {
			return nil, err
		}
		possession := append([]byte{}, claim.Scope.Deployment[:]...)
		possession = append(possession, claim.Scope.Coin[:]...)
		possession = append(possession, 1, 0, byte(i+1))
		possession = append(possession, rawPublic...)
		proof, err := hex.DecodeString(member.Proof)
		if err != nil || hex.EncodeToString(proof) != member.Proof {
			return nil, fmt.Errorf("invalid Zark possession encoding")
		}
		if err := zarkVerify(members[i], zarkHash("ZARK/spark/regtest/key-possession/v1", possession), proof); err != nil {
			return nil, err
		}
		signed := out.envelope.Contributions[i]
		if err := zarkJSON(signed.Body, &out.contributions[i]); err != nil {
			return nil, err
		}
		contribution := &out.contributions[i]
		if contribution.Position != uint16(i+1) || contribution.Binding != out.binding || len(contribution.Proofs) != int(config.Threshold) || len(contribution.Sealed) != len(config.SigningOperatorMap) {
			return nil, fmt.Errorf("Zark claim contribution domain mismatch")
		}
		if err := zarkVerify(members[i], zarkHash("ZARK/spark/mpc-claim/contribution/v1", signed.Body), signed.Signature); err != nil {
			return nil, err
		}
		for _, proof := range contribution.Proofs {
			if _, err := zarkPoint(proof); err != nil {
				return nil, err
			}
		}
		expected := members[i].Neg()
		if i == 0 {
			expected = incoming.Sub(members[i])
		}
		if !bytes.Equal(expected.Serialize(), contribution.Proofs[0]) {
			return nil, fmt.Errorf("Zark claim constant mismatch")
		}
		for id := range config.SigningOperatorMap {
			cipher := contribution.Sealed[id]
			if len(cipher) != 195 || cipher[0] != 4 {
				return nil, fmt.Errorf("invalid Zark claim encrypted evaluation")
			}
		}
	}
	out.public, err = zarkSum(members[0], members[1])
	if err != nil {
		return nil, err
	}
	out.proofs = make([][]byte, config.Threshold)
	for i := range out.proofs {
		first, _ := zarkPoint(out.contributions[0].Proofs[i])
		second, _ := zarkPoint(out.contributions[1].Proofs[i])
		sum, err := zarkSum(first, second)
		if err != nil {
			return nil, err
		}
		out.proofs[i] = sum.Serialize()
	}
	tweak, _ := zarkPoint(out.proofs[0])
	if !incoming.Sub(out.public).Equals(tweak) {
		return nil, fmt.Errorf("Zark claim combined tweak mismatch")
	}
	if _, err := zarkSum(operator, tweak); err != nil {
		return nil, err
	}
	out.marker = protowire.AppendTag(nil, zarkClaimMarkerField, protowire.BytesType)
	digest := sha256.Sum256(raw)
	out.marker = protowire.AppendBytes(out.marker, digest[:])
	return &out, nil
}

func decryptZarkClaim(config *so.Config, raw []byte) (*pb.ClaimLeafKeyTweaks, error) {
	decoded, err := decodeZarkClaim(config, raw)
	if err != nil {
		return nil, err
	}
	id := config.Identifier
	configured := config.SigningOperatorMap[id]
	if configured == nil || configured.ID != config.Index || !configured.IdentityPublicKey.Equals(config.IdentityPrivateKey.Public()) {
		return nil, fmt.Errorf("Zark claim local operator mismatch")
	}
	modulus := secp256k1.S256().N
	combined := new(big.Int)
	for _, contribution := range decoded.contributions {
		plaintext, err := eciesgo.Decrypt(eciesgo.NewPrivateKeyFromBytes(config.IdentityPrivateKey.Serialize()), contribution.Sealed[id])
		if err != nil {
			return nil, fmt.Errorf("Zark claim decryption failed")
		}
		defer clear(plaintext)
		if len(plaintext) != 98 || !bytes.Equal(plaintext[:32], decoded.binding[:]) || binary.BigEndian.Uint16(plaintext[32:34]) != contribution.Position || hex.EncodeToString(plaintext[34:66]) != id {
			return nil, fmt.Errorf("Zark claim decrypted evaluation domain mismatch")
		}
		value := new(big.Int).SetBytes(plaintext[66:])
		defer value.SetInt64(0)
		if value.Sign() == 0 || value.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("noncanonical Zark claim evaluation")
		}
		if err := secretsharing.ValidateShare(&secretsharing.VerifiableSecretShare{FieldModulus: modulus, Threshold: int(config.Threshold), Index: new(big.Int).SetUint64(config.Index + 1), Share: value, Proofs: contribution.Proofs}); err != nil {
			return nil, fmt.Errorf("invalid Zark claim evaluation: %w", err)
		}
		combined.Add(combined, value).Mod(combined, modulus)
	}
	defer combined.SetInt64(0)
	if combined.Sign() == 0 {
		return nil, fmt.Errorf("zero Zark claim combined evaluation")
	}
	publicShares := make(map[string][]byte, len(config.SigningOperatorMap))
	for id, operator := range config.SigningOperatorMap {
		public, err := secretsharing.EvaluatePolynomialCommitment(decoded.proofs, new(big.Int).SetUint64(operator.ID+1), modulus)
		if err != nil {
			return nil, err
		}
		if _, err := zarkPoint(public.Serialize()); err != nil {
			return nil, err
		}
		publicShares[id] = public.Serialize()
	}
	tweak := &pb.ClaimLeafKeyTweak{LeafId: decoded.transcript.Claim.LeafID, SecretShareTweak: &pb.SecretShare{SecretShare: combined.FillBytes(make([]byte, 32)), Proofs: decoded.proofs}, PubkeySharesTweak: publicShares}
	tweak.ProtoReflect().SetUnknown(decoded.marker)
	if err := validateClaimLeafKeyTweak(config, tweak); err != nil {
		return nil, err
	}
	return &pb.ClaimLeafKeyTweaks{LeavesToReceive: []*pb.ClaimLeafKeyTweak{tweak}}, nil
}

// Reject duplicate object keys as well as unknown struct fields. Two parsers
// must not assign different meanings to the same signed transcript bytes.
func zarkJSON(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > zarkClaimMaxBytes {
		return fmt.Errorf("invalid Zark claim JSON size")
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("Zark claim JSON nesting")
		}
		token, err := tokens.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delimiter == '{' {
			seen := map[string]bool{}
			for tokens.More() {
				token, err := tokens.Token()
				if err != nil {
					return err
				}
				name, ok := token.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate Zark claim JSON key")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		} else if delimiter == '[' {
			for tokens.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("invalid Zark claim JSON token")
		}
		_, err = tokens.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return fmt.Errorf("trailing Zark claim JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
