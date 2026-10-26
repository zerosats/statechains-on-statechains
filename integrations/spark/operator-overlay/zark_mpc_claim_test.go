package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func zarkTestSecret(t *testing.T, n int64) keys.Private {
	t.Helper()
	key, err := keys.ParsePrivateKey(big.NewInt(n).FillBytes(make([]byte, 32)))
	require.NoError(t, err)
	return key
}
func zarkTestSign(t *testing.T, key keys.Private, digest [32]byte) []byte {
	t.Helper()
	signature, err := schnorr.Sign(key.ToBTCEC(), digest[:])
	require.NoError(t, err)
	return signature.Serialize()
}
func zarkTestConfig(t *testing.T, index uint64) *so.Config {
	t.Helper()
	operators := map[string]*so.SigningOperator{}
	for n := uint64(0); n < 3; n++ {
		id := hex.EncodeToString(new(big.Int).SetUint64(n + 1).FillBytes(make([]byte, 32)))
		operators[id] = &so.SigningOperator{ID: n, Identifier: id, IdentityPublicKey: zarkTestSecret(t, int64(n+11)).Public()}
	}
	id := hex.EncodeToString(new(big.Int).SetUint64(index + 1).FillBytes(make([]byte, 32)))
	return &so.Config{Index: index, Identifier: id, IdentityPrivateKey: zarkTestSecret(t, int64(index+11)), SigningOperatorMap: operators, Threshold: 2}
}

func zarkTestEnvelope(t *testing.T, config *so.Config) ([]byte, *zarkClaimTranscript) {
	t.Helper()
	var transcript zarkClaimTranscript
	claim := &transcript.Claim
	claim.Scope = zarkClaimScope{Deployment: [32]byte{1}, Coin: [32]byte{2}, Purpose: "leaf_signing"}
	claim.Operation = [32]byte{3}
	claim.TransferID = "11111111-1111-4111-8111-111111111111"
	claim.LeafID = "22222222-2222-4222-8222-222222222222"
	claim.Amount = 42000
	claim.Receiver = zarkTestSecret(t, 31).Public().Serialize()
	claim.Incoming = zarkTestSecret(t, 17).Public().Serialize()
	claim.Operator = zarkTestSecret(t, 51).Public().Serialize()
	claim.Backing = zarkTestSecret(t, 68).Public().Serialize()
	claim.BackingTx = sha256.Sum256([]byte("synthetic backing"))
	claim.DirectBackingTx = sha256.Sum256([]byte("synthetic direct backing"))
	claim.Refunds.CPFP = []byte("synthetic cpfp")
	claim.Refunds.Direct = []byte("synthetic direct")
	claim.Refunds.DirectFromCPFP = []byte("synthetic direct from cpfp")
	claim.Cluster.Threshold = 2
	claim.Cluster.Operators = map[string][]byte{}
	for id, operator := range config.SigningOperatorMap {
		claim.Cluster.Operators[id] = operator.IdentityPublicKey.Serialize()
	}
	secrets := []keys.Private{zarkTestSecret(t, 3), zarkTestSecret(t, 5)}
	for i, secret := range secrets {
		public := secret.Public().Serialize()
		payload := append([]byte{}, claim.Scope.Deployment[:]...)
		payload = append(payload, claim.Scope.Coin[:]...)
		payload = append(payload, 1, 0, byte(i+1))
		payload = append(payload, public...)
		transcript.Authority.Members = append(transcript.Authority.Members, zarkClaimPublicShare{Scope: claim.Scope, Position: uint16(i + 1), PublicKey: hex.EncodeToString(public), Proof: hex.EncodeToString(zarkTestSign(t, secret, zarkHash("ZARK/spark/regtest/key-possession/v1", payload)))})
	}
	encoded, err := json.Marshal(transcript)
	require.NoError(t, err)
	envelope := zarkClaimEnvelope{Transcript: encoded}
	binding := zarkHash("ZARK/spark/mpc-claim/transcript/v1", encoded)
	for i, secret := range secrets {
		constant := big.NewInt(14)
		if i == 1 {
			constant.Sub(secp256k1.S256().N, big.NewInt(5))
		}
		coefficient := big.NewInt(int64(19 + 4*i))
		key, err := keys.ParsePrivateKey(constant.FillBytes(make([]byte, 32)))
		require.NoError(t, err)
		contribution := zarkClaimContribution{Position: uint16(i + 1), Binding: binding, Proofs: [][]byte{key.Public().Serialize(), zarkTestSecret(t, coefficient.Int64()).Public().Serialize()}, Sealed: map[string][]byte{}}
		for id, operator := range config.SigningOperatorMap {
			value := new(big.Int).Mul(coefficient, new(big.Int).SetUint64(operator.ID+1))
			value.Add(value, constant).Mod(value, secp256k1.S256().N)
			payload := append([]byte{}, binding[:]...)
			payload = binary.BigEndian.AppendUint16(payload, uint16(i+1))
			rawID, err := hex.DecodeString(id)
			require.NoError(t, err)
			payload = append(payload, rawID...)
			payload = append(payload, value.FillBytes(make([]byte, 32))...)
			public, err := eciesgo.NewPublicKeyFromBytes(operator.IdentityPublicKey.Serialize())
			require.NoError(t, err)
			contribution.Sealed[id], err = eciesgo.Encrypt(public, payload)
			require.NoError(t, err)
		}
		body, err := json.Marshal(contribution)
		require.NoError(t, err)
		envelope.Contributions = append(envelope.Contributions, struct {
			Body      []byte `json:"body"`
			Signature []byte `json:"signature"`
		}{body, zarkTestSign(t, secret, zarkHash("ZARK/spark/mpc-claim/contribution/v1", body))})
	}
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	return append([]byte(zarkClaimMagic), raw...), &transcript
}

func TestZarkMpcClaimIndependentVssAndExactTranscript(t *testing.T) {
	config := zarkTestConfig(t, 0)
	raw, transcript := zarkTestEnvelope(t, config)
	for n := uint64(0); n < 3; n++ {
		config := zarkTestConfig(t, n)
		tweaks, err := decryptZarkClaim(config, raw)
		require.NoError(t, err)
		// P1(x)=14+19x, P2(x)=-5+23x; their sum has constant 9.
		require.Equal(t, new(big.Int).SetUint64(9+42*(n+1)).FillBytes(make([]byte, 32)), tweaks.LeavesToReceive[0].SecretShareTweak.SecretShare)
		marker, err := zarkClaimAppliedMarker(tweaks.LeavesToReceive[0])
		require.NoError(t, err)
		saved := &pb.ClaimLeafKeyTweak{}
		require.NoError(t, proto.Unmarshal(marker, saved))
		require.Nil(t, saved.SecretShareTweak)
		require.Equal(t, tweaks.LeavesToReceive[0].ProtoReflect().GetUnknown(), saved.ProtoReflect().GetUnknown())
	}
	leaf := &ent.TreeNode{ID: uuid.MustParse(transcript.Claim.LeafID), Value: 42000, RawTx: []byte("synthetic backing"), DirectTx: []byte("synthetic direct backing"), OwnerSigningPubkey: zarkTestSecret(t, 17).Public(), VerifyingPubkey: zarkTestSecret(t, 68).Public()}
	leaf.Edges.SigningKeyshare = &ent.SigningKeyshare{PublicKey: zarkTestSecret(t, 51).Public()}
	transferLeaf := &ent.TransferLeaf{}
	transferLeaf.Edges.Leaf = leaf
	packages := map[string][]byte{}
	for id := range config.SigningOperatorMap {
		packages[id] = raw
	}
	pkg := &pb.ClaimPackage{KeyTweakPackage: packages}
	for i, refund := range [][]byte{transcript.Claim.Refunds.CPFP, transcript.Claim.Refunds.Direct, transcript.Claim.Refunds.DirectFromCPFP} {
		job := &pb.UserSignedTxSigningJob{LeafId: leaf.ID.String(), SigningPublicKey: zarkTestSecret(t, 8).Public().Serialize(), RawTx: refund}
		if i == 0 {
			pkg.LeavesToClaim = []*pb.UserSignedTxSigningJob{job}
		} else if i == 1 {
			pkg.DirectLeavesToClaim = []*pb.UserSignedTxSigningJob{job}
		} else {
			pkg.DirectFromCpfpLeavesToClaim = []*pb.UserSignedTxSigningJob{job}
		}
	}
	check := func(applied bool) error {
		return validateZarkClaimPrepare(config, uuid.MustParse(transcript.Claim.TransferID), zarkTestSecret(t, 31).Public(), pkg, []*ent.TransferLeaf{transferLeaf}, applied)
	}
	require.NoError(t, check(false))
	tweaked, err := decryptZarkClaim(config, raw)
	require.NoError(t, err)
	transferLeaf.KeyTweak, err = proto.Marshal(tweaked.LeavesToReceive[0])
	require.NoError(t, err)
	require.NoError(t, check(false))
	pkg.DirectLeavesToClaim[0].RawTx = []byte("substituted")
	require.Error(t, check(false))
	pkg.DirectLeavesToClaim[0].RawTx = transcript.Claim.Refunds.Direct
	different, _ := zarkTestEnvelope(t, config)
	for id := range packages {
		packages[id] = different
	}
	require.Error(t, check(false))
	for id := range packages {
		packages[id] = raw
	}
	marker, err := zarkClaimAppliedMarker(tweaked.LeavesToReceive[0])
	require.NoError(t, err)
	transferLeaf.KeyTweak = marker
	leaf.OwnerSigningPubkey = zarkTestSecret(t, 8).Public()
	leaf.Edges.SigningKeyshare.PublicKey = zarkTestSecret(t, 60).Public()
	require.NoError(t, check(true))
	transferLeaf.KeyTweak = nil
	require.Error(t, check(true))
}

func TestZarkMpcClaimRejectsMutationAndDuplicateFields(t *testing.T) {
	config := zarkTestConfig(t, 0)
	raw, _ := zarkTestEnvelope(t, config)
	for _, mutate := range []func(*zarkClaimEnvelope){
		func(e *zarkClaimEnvelope) {
			e.Contributions[0], e.Contributions[1] = e.Contributions[1], e.Contributions[0]
		},
		func(e *zarkClaimEnvelope) {
			e.Transcript = append(e.Transcript[:len(e.Transcript)-1], []byte(`,"claim":{}}`)...)
		},
		func(e *zarkClaimEnvelope) { e.Contributions[0].Signature[0] ^= 1 },
		func(e *zarkClaimEnvelope) {
			var c zarkClaimContribution
			require.NoError(t, json.Unmarshal(e.Contributions[0].Body, &c))
			c.Sealed[config.Identifier][100] ^= 1
			e.Contributions[0].Body, _ = json.Marshal(c)
		},
	} {
		var envelope zarkClaimEnvelope
		require.NoError(t, json.Unmarshal(raw[len(zarkClaimMagic):], &envelope))
		mutate(&envelope)
		encoded, err := json.Marshal(envelope)
		require.NoError(t, err)
		_, err = decryptZarkClaim(config, append([]byte(zarkClaimMagic), encoded...))
		require.Error(t, err)
	}
	require.Error(t, zarkJSON([]byte(`{"claim":{},"claim":{}}`), &zarkClaimTranscript{}))
	packages := map[string][]byte{}
	for id := range config.SigningOperatorMap {
		packages[id] = raw
	}
	packages[config.Identifier] = []byte("legacy")
	_, err := zarkClaimPackage(config, packages)
	require.Error(t, err)
}

func TestZarkMpcClaimRejectsAuthenticatedBadEvaluation(t *testing.T) {
	testConfig := zarkTestConfig(t, 0)
	wire, _ := zarkTestEnvelope(t, testConfig)
	for _, wrongDomain := range []bool{false, true} {
		var envelope zarkClaimEnvelope
		require.NoError(t, json.Unmarshal(wire[len(zarkClaimMagic):], &envelope))
		var contribution zarkClaimContribution
		require.NoError(t, json.Unmarshal(envelope.Contributions[0].Body, &contribution))
		payload := append([]byte{}, contribution.Binding[:]...)
		if wrongDomain {
			payload[0] ^= 1
		}
		payload = binary.BigEndian.AppendUint16(payload, 1)
		id, err := hex.DecodeString(testConfig.Identifier)
		require.NoError(t, err)
		payload = append(payload, id...)
		// This is canonical and nonzero but disagrees with the committed VSS
		// evaluation. A malicious holder can still sign the enclosing body.
		payload = append(payload, big.NewInt(7).FillBytes(make([]byte, 32))...)
		key, err := eciesgo.NewPublicKeyFromBytes(testConfig.IdentityPrivateKey.Public().Serialize())
		require.NoError(t, err)
		contribution.Sealed[testConfig.Identifier], err = eciesgo.Encrypt(key, payload)
		require.NoError(t, err)
		envelope.Contributions[0].Body, err = json.Marshal(contribution)
		require.NoError(t, err)
		envelope.Contributions[0].Signature = zarkTestSign(t, zarkTestSecret(t, 3), zarkHash("ZARK/spark/mpc-claim/contribution/v1", envelope.Contributions[0].Body))
		encoded, err := json.Marshal(envelope)
		require.NoError(t, err)
		encoded = append([]byte(zarkClaimMagic), encoded...)
		_, err = decodeZarkClaim(testConfig, encoded)
		require.NoError(t, err, "public commitment/signature validation alone cannot inspect encrypted evaluations")
		_, err = decryptZarkClaim(testConfig, encoded)
		require.Error(t, err)
	}
}

// Optional Rust-produced fixture independently checks FROST Schnorr proofs,
// Spark ECIES ABI, fixed role/slot binding, and the VSS scalar evaluation.
func TestZarkMpcClaimRustInterop(t *testing.T) {
	path := os.Getenv("ZARK_MPC_CLAIM_VECTOR")
	if path == "" {
		t.Skip("set ZARK_MPC_CLAIM_VECTOR to the isolated Rust test output")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var vector struct {
		Wire        []byte            `json:"wire"`
		Evaluations map[string]string `json:"evaluations"`
	}
	require.NoError(t, json.Unmarshal(raw, &vector))
	for i := uint64(0); i < 3; i++ {
		config := zarkTestConfig(t, i)
		decoded, err := decryptZarkClaim(config, vector.Wire)
		require.NoError(t, err)
		require.Equal(t, vector.Evaluations[config.Identifier], hex.EncodeToString(decoded.LeavesToReceive[0].SecretShareTweak.SecretShare))
	}
	require.True(t, bytes.HasPrefix(vector.Wire, []byte(zarkClaimMagic)))
}
