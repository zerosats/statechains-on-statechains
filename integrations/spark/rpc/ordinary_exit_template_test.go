// Native protobuf templates are evaluated inside the confidential encryption
// MPC. The helper sees only public coefficients and a zero share placeholder.
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/testing/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func ordinaryExitLeafPayload(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	leaf, err := uuid.Parse(r.LeafID)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, leaf)
	require.Equal(t, leaf.String(), r.LeafID)
	transfer, err := uuid.Parse(r.TransferID)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, transfer)
	require.Equal(t, transfer.String(), r.TransferID)
	require.Len(t, r.MaskCipher, 129)
	require.Equal(t, byte(4), r.MaskCipher[0])
	payload := append(append([]byte(r.LeafID), []byte(r.TransferID)...), r.MaskCipher...)
	digest := sha256.Sum256(payload)
	return blob(digest[:])
}

func ordinaryExitTweakTemplate(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	ordinaryExitLeafPayload(t, r)
	require.Len(t, r.Coefficients, 2)
	require.GreaterOrEqual(t, len(r.Signature), 8)
	require.LessOrEqual(t, len(r.Signature), 72)
	c0, err := keys.ParsePublicKey(r.Coefficients[0])
	require.NoError(t, err)
	c1, err := keys.ParsePublicKey(r.Coefficients[1])
	require.NoError(t, err)
	publicShares := make(map[string][]byte)
	point := c0
	for i := 1; i <= 3; i++ {
		point = point.Add(c1)
		publicShares[fmt.Sprintf("%064x", i)] = point.Serialize()
	}
	_, found := publicShares[r.Operator]
	require.True(t, found, "ordinary operator ID must be one of the three pinned fixture operators")
	pack := &pb.SendLeafKeyTweaks{LeavesToSend: []*pb.SendLeafKeyTweak{{LeafId: r.LeafID,
		SecretShareTweak:  &pb.SecretShare{SecretShare: make([]byte, 32), Proofs: [][]byte{r.Coefficients[0], r.Coefficients[1]}},
		PubkeySharesTweak: publicShares, SecretCipher: r.MaskCipher, Sig: &pb.SendLeafKeyTweak_Signature{Signature: r.Signature}}}}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(pack)
	require.NoError(t, err)
	// The scalar's field header is unique; protobuf explicitly retains a bytes
	// field of 32 zeros. Fail closed if another field ever creates ambiguity.
	needle := append([]byte{0x0a, 0x20}, make([]byte, 32)...)
	require.Equal(t, 1, bytes.Count(raw, needle), "native scalar placeholder is ambiguous")
	offset := bytes.Index(raw, needle) + 2
	var checked pb.SendLeafKeyTweaks
	require.NoError(t, proto.Unmarshal(raw, &checked))
	require.Len(t, checked.GetLeavesToSend(), 1)
	require.Equal(t, make([]byte, 32), checked.GetLeavesToSend()[0].GetSecretShareTweak().GetSecretShare())
	return map[string]any{"template": blob(raw), "scalar_offset": offset}
}

func ordinaryExitStatus(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	record := ordinaryLoadRecipient(t, r)
	identity, err := keys.ParsePrivateKey(record.Identity)
	require.NoError(t, err)
	cfg := ordinaryConfig(t, r.Directory, identity)
	token, err := wallet.AuthenticateWithServer(t.Context(), cfg)
	require.NoError(t, err)
	ctx := wallet.ContextWithToken(t.Context(), token)
	conn, err := cfg.NewCoordinatorGRPCConnection()
	require.NoError(t, err)
	defer conn.Close()
	response, err := pb.NewSparkServiceClient(conn).QueryTransfersById(ctx, &pb.QueryTransfersByIdRequest{TransferIds: []string{r.TransferID}, Network: pb.Network_REGTEST})
	require.NoError(t, err)
	if len(response.GetTransfers()) == 0 {
		return map[string]any{"found": false}
	}
	require.Len(t, response.GetTransfers(), 1)
	tr := response.GetTransfers()[0]
	require.Equal(t, r.TransferID, tr.GetId())
	require.Equal(t, identity.Public().Serialize(), tr.GetReceiverIdentityPublicKey())
	require.Len(t, tr.GetLeaves(), 1)
	require.Equal(t, r.LeafID, tr.GetLeaves()[0].GetLeaf().GetId())
	return map[string]any{"found": true, "status": tr.GetStatus().String()}
}

func TestOrdinaryExitTemplateCarriesOnlyCombinedPublicMaterial(t *testing.T) {
	identity := keys.GeneratePrivateKey()
	r := ordinaryRequest{LeafID: uuid.NewString(), TransferID: uuid.NewString(), MaskCipher: append([]byte{4}, make([]byte, 128)...),
		Coefficients: []blob{keys.GeneratePrivateKey().Public().Serialize(), keys.GeneratePrivateKey().Public().Serialize()}, Operator: fmt.Sprintf("%064x", 1)}
	digest := ordinaryExitLeafPayload(t, r).(blob)
	r.Signature = ecdsa.Sign(identity.ToBTCEC(), digest).Serialize()
	result := ordinaryExitTweakTemplate(t, r).(map[string]any)
	raw := result["template"].(blob)
	offset := result["scalar_offset"].(int)
	require.Equal(t, make([]byte, 32), []byte(raw[offset:offset+32]))
	var pack pb.SendLeafKeyTweaks
	require.NoError(t, proto.Unmarshal(raw, &pack))
	leaf := pack.GetLeavesToSend()[0]
	require.Equal(t, r.LeafID, leaf.GetLeafId())
	require.Equal(t, []byte(r.MaskCipher), leaf.GetSecretCipher())
	require.Equal(t, []byte(r.Signature), leaf.GetSignature())
	require.Equal(t, []byte(r.Coefficients[0]), leaf.GetSecretShareTweak().GetProofs()[0])
	require.Len(t, leaf.GetPubkeySharesTweak(), 3)
	// Distinct public operator evaluations use the aggregate polynomial; no
	// individual signer coefficient or private share enters this template.
	c0, err := keys.ParsePublicKey(r.Coefficients[0])
	require.NoError(t, err)
	c1, err := keys.ParsePublicKey(r.Coefficients[1])
	require.NoError(t, err)
	point := c0
	for i := 1; i <= 3; i++ {
		point = point.Add(c1)
		require.Equal(t, point.Serialize(), leaf.GetPubkeySharesTweak()[fmt.Sprintf("%064x", i)])
	}
}
