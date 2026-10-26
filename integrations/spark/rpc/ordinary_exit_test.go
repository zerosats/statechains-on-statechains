// Ordinary Spark exit adapter. Only public USER material and already completed
// contributions cross this pipe. The recipient's own keys remain fixture-local.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pc "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/testing/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ordinaryExitPacket struct {
	TransferID string          `json:"transfer_id"`
	LeafID     string          `json:"leaf_id"`
	Amount     uint64          `json:"amount_sats"`
	Expiry     uint64          `json:"expiry_unix_seconds"`
	Sender     blob            `json:"sender_identity"`
	Receiver   blob            `json:"receiver_identity"`
	UserKey    blob            `json:"user_key"`
	Packages   map[string]blob `json:"key_tweak_package"`
	Refunds    []claimRefund   `json:"refunds"`
	Signature  blob            `json:"signature"`
}

func (p *ordinaryExitPacket) packageFor(s settings) (*pb.TransferPackage, uuid.UUID, error) {
	id, err := uuid.Parse(p.TransferID)
	if err != nil || id == uuid.Nil || id.String() != p.TransferID {
		return nil, uuid.Nil, fmt.Errorf("ordinary exit transfer UUID")
	}
	leaf, err := uuid.Parse(p.LeafID)
	if err != nil || leaf == uuid.Nil || leaf.String() != p.LeafID {
		return nil, uuid.Nil, fmt.Errorf("ordinary exit leaf UUID")
	}
	if !bytes.Equal(p.Sender, s.Owner) || !ordinaryDenomination(p.Amount) || len(p.Refunds) != 2 || len(p.Packages) != len(s.Operators) {
		return nil, uuid.Nil, fmt.Errorf("ordinary root exit coverage")
	}
	for _, point := range []blob{p.Sender, p.Receiver, p.UserKey} {
		if _, err := keys.ParsePublicKey(point); err != nil {
			return nil, uuid.Nil, err
		}
	}
	packages := make(map[string][]byte)
	for op := range s.Operators {
		cipher := p.Packages[op]
		if len(cipher) < 129 || len(cipher) > 16384 || cipher[0] != 4 {
			return nil, uuid.Nil, fmt.Errorf("ordinary native ECIES package")
		}
		packages[op] = cipher
	}
	jobs := make([]*pb.UserSignedTxSigningJob, 2)
	for i, refund := range p.Refunds {
		if len(refund.Raw) == 0 || len(refund.Raw) > 16384 || len(refund.Partial) != 32 || len(refund.Operators) != 2 {
			return nil, uuid.Nil, fmt.Errorf("ordinary USER refund shape")
		}
		operators := make(map[string]*pc.SigningCommitment)
		for op, nonce := range refund.Operators {
			if _, found := s.Operators[op]; !found {
				return nil, uuid.Nil, fmt.Errorf("ordinary unknown signing operator")
			}
			for _, point := range []blob{nonce.Hiding, nonce.Binding} {
				if _, err := keys.ParsePublicKey(point); err != nil {
					return nil, uuid.Nil, err
				}
			}
			operators[op] = nonce.proto()
		}
		for _, point := range []blob{refund.User.Hiding, refund.User.Binding} {
			if _, err := keys.ParsePublicKey(point); err != nil {
				return nil, uuid.Nil, err
			}
		}
		jobs[i] = &pb.UserSignedTxSigningJob{LeafId: p.LeafID, SigningPublicKey: p.UserKey, RawTx: refund.Raw,
			SigningCommitments: &pb.SigningCommitments{SigningCommitments: operators}, SigningNonceCommitment: refund.User.proto(), UserSignature: refund.Partial}
	}
	return &pb.TransferPackage{LeavesToSend: jobs[:1], DirectFromCpfpLeavesToSend: jobs[1:], KeyTweakPackage: packages,
		HashVariant: pb.HashVariant_HASH_VARIANT_V2}, id, nil
}

func ordinaryExitPayload(t *testing.T, c *client, p *ordinaryExitPacket) any {
	t.Helper()
	require.NotNil(t, p)
	pack, id, err := p.packageFor(c.config)
	require.NoError(t, err)
	return blob(common.GetTransferPackageSigningPayload(id, pack))
}

// Every mutation is durably frozen before RPC; retries must reuse identical
// protobuf bytes. File equality makes uncertainty explicit instead of replacing
// a native operation or generating fresh keys after an interrupted response.
func ordinaryFreeze(t *testing.T, name string, raw []byte) {
	t.Helper()
	if saved, err := os.ReadFile(name); err == nil {
		require.Equal(t, saved, raw, "ordinary operation retry changed")
		return
	} else {
		require.True(t, os.IsNotExist(err))
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = f.Write(raw)
	require.NoError(t, err)
	require.NoError(t, f.Sync())
	require.NoError(t, f.Close())
	d, err := os.Open(filepath.Dir(name))
	require.NoError(t, err)
	require.NoError(t, d.Sync())
	require.NoError(t, d.Close())
}

func ordinaryExitSubmit(t *testing.T, c *client, r ordinaryRequest) any {
	t.Helper()
	require.NotNil(t, r.ExitPacket)
	p := r.ExitPacket
	pack, id, err := p.packageFor(c.config)
	require.NoError(t, err)
	sender, err := keys.ParsePublicKey(p.Sender)
	require.NoError(t, err)
	sig, err := ecdsa.ParseDERSignature(p.Signature)
	require.NoError(t, err)
	require.True(t, sender.Verify(sig, common.GetTransferPackageSigningPayload(id, pack)), "ordinary package authentication")
	require.Greater(t, p.Expiry, uint64(time.Now().Unix()), "ordinary exit expired; retain for reconciliation")
	pack.UserSignature = p.Signature
	req := &pb.StartTransferRequest{TransferId: p.TransferID, OwnerIdentityPublicKey: p.Sender, ReceiverIdentityPublicKey: p.Receiver,
		ExpiryTime: timestamppb.New(time.Unix(int64(p.Expiry), 0)), TransferPackage: pack}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	require.NoError(t, err)
	ordinaryFreeze(t, filepath.Join(r.Directory, "ordinary-exit-"+id.String()+".request.pb"), raw)
	ctx, cancel, err := c.rpcContext(c.config.Coordinator)
	require.NoError(t, err)
	defer cancel()
	response, err := pb.NewSparkServiceClient(c.conns[c.config.Coordinator]).StartTransferV2(ctx, req)
	require.NoError(t, err)
	require.Equal(t, p.TransferID, response.GetTransfer().GetId())
	return map[string]any{"transfer_id": p.TransferID, "status": response.GetTransfer().GetStatus().String(), "request_sha256": fmt.Sprintf("%x", sha256.Sum256(raw))}
}

type ordinaryRecipient struct {
	Identity blob `json:"identity"`
	User     blob `json:"user"`
}

// A named recipient is a fresh wallet per share-release fixture; the unnamed
// one is the retained native-exit recipient.
func ordinaryRecipientPath(r ordinaryRequest) string {
	if r.Recipient != "" {
		return filepath.Join(r.Directory, "ordinary-share-exit-recipients", r.Recipient+".private.json")
	}
	return filepath.Join(r.Directory, "ordinary-exit-recipient.private.json")
}
func ordinaryExitRecipient(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	name := ordinaryRecipientPath(r)
	err := os.Mkdir(filepath.Dir(name), 0700)
	require.True(t, err == nil || os.IsExist(err))
	if _, err := os.Stat(name); os.IsNotExist(err) {
		record := ordinaryRecipient{Identity: blob(keys.GeneratePrivateKey().Serialize()), User: blob(keys.GeneratePrivateKey().Serialize())}
		raw, err := json.Marshal(record)
		require.NoError(t, err)
		ordinaryFreeze(t, name, raw)
	}
	record := ordinaryLoadRecipient(t, r)
	identity, err := keys.ParsePrivateKey(record.Identity)
	require.NoError(t, err)
	user, err := keys.ParsePrivateKey(record.User)
	require.NoError(t, err)
	return map[string]any{"identity": blob(identity.Public().Serialize()), "user": blob(user.Public().Serialize())}
}
func ordinaryLoadRecipient(t *testing.T, r ordinaryRequest) ordinaryRecipient {
	t.Helper()
	raw, err := os.ReadFile(ordinaryRecipientPath(r))
	require.NoError(t, err)
	var record ordinaryRecipient
	require.NoError(t, json.Unmarshal(raw, &record))
	return record
}

func ordinaryExitClaim(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	record := ordinaryLoadRecipient(t, r)
	identity, err := keys.ParsePrivateKey(record.Identity)
	require.NoError(t, err)
	user, err := keys.ParsePrivateKey(record.User)
	require.NoError(t, err)
	cfg := ordinaryConfig(t, r.Directory, identity)
	token, err := wallet.AuthenticateWithServer(t.Context(), cfg)
	require.NoError(t, err)
	ctx := wallet.ContextWithToken(t.Context(), token)
	conn, err := cfg.NewCoordinatorGRPCConnection()
	require.NoError(t, err)
	defer conn.Close()
	rpc := pb.NewSparkServiceClient(conn)
	response, err := rpc.QueryTransfersById(ctx, &pb.QueryTransfersByIdRequest{TransferIds: []string{r.TransferID}, Network: pb.Network_REGTEST})
	require.NoError(t, err)
	require.Len(t, response.GetTransfers(), 1)
	tr := response.GetTransfers()[0]
	require.Equal(t, r.TransferID, tr.GetId())
	require.Equal(t, identity.Public().Serialize(), tr.GetReceiverIdentityPublicKey())
	require.Len(t, tr.GetLeaves(), 1)
	require.Equal(t, r.LeafID, tr.GetLeaves()[0].GetLeaf().GetId())
	if tr.GetStatus() != pb.TransferStatus_TRANSFER_STATUS_COMPLETED {
		_, savedErr := os.Stat(filepath.Join(r.Directory, "ordinary-exit-"+r.TransferID+".claim.pb"))
		if os.IsNotExist(savedErr) {
			require.Equal(t, pb.TransferStatus_TRANSFER_STATUS_SENDER_KEY_TWEAKED, tr.GetStatus())
		} else {
			require.NoError(t, savedErr)
			require.NotEqual(t, pb.TransferStatus_TRANSFER_STATUS_EXPIRED, tr.GetStatus())
			require.NotEqual(t, pb.TransferStatus_TRANSFER_STATUS_RETURNED, tr.GetStatus())
		}
		masks, err := wallet.VerifyPendingTransfer(ctx, cfg, tr)
		require.NoError(t, err)
		claim := ordinaryFrozenClaim(t, ctx, r.Directory, r.TransferID, cfg, tr, masks, user)
		response, err := rpc.ClaimTransfer(ctx, claim)
		require.NoError(t, err)
		completed := response.GetTransfer()
		require.Equal(t, pb.TransferStatus_TRANSFER_STATUS_COMPLETED, completed.GetStatus())
	}
	r.Receiver = identity.Public().Serialize()
	result := ordinaryObserve(t, r).(map[string]any)
	require.Equal(t, blob(user.Public().Serialize()), result["user"])
	return result
}

// A test-only independent observer reads public native state from all three
// operators. The complete leaf fingerprint catches hidden native mutations as
// well as counting completed transfers; no operator key material is selected.
func ordinaryNativeSnapshot(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	leafID, err := uuid.Parse(r.LeafID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	counts := []int{}
	fingerprints := []string{}
	for i := 0; i < 3; i++ {
		reader := db.NewPostgresEntClientForIntegrationTest(t, fmt.Sprintf("postgresql://postgres@127.0.0.1:54329/sparkoperator_%d?sslmode=disable", i))
		defer reader.Close()
		count, err := reader.Transfer.Query().Where(transfer.StatusEQ("COMPLETED")).Count(ctx)
		require.NoError(t, err)
		counts = append(counts, count)
		node, err := reader.TreeNode.Query().Where(treenode.IDEQ(leafID)).Select(treenode.FieldID, treenode.FieldValue, treenode.FieldStatus, treenode.FieldRawTx, treenode.FieldRawRefundTx,
			treenode.FieldDirectFromCpfpRefundTx, treenode.FieldDirectTx, treenode.FieldDirectRefundTx, treenode.FieldOwnerIdentityPubkey, treenode.FieldOwnerSigningPubkey, treenode.FieldVerifyingPubkey).Only(ctx)
		require.NoError(t, err)
		// Use explicitly selected stable public facts, excluding Ent's internals.
		raw, err := json.Marshal([]any{node.ID.String(), node.Value, string(node.Status), node.RawTx, node.RawRefundTx, node.DirectFromCpfpRefundTx, node.DirectTx, node.DirectRefundTx, node.OwnerIdentityPubkey.Serialize(), node.OwnerSigningPubkey.Serialize(), node.VerifyingPubkey.Serialize()})
		require.NoError(t, err)
		digest := sha256.Sum256(raw)
		fingerprints = append(fingerprints, hex.EncodeToString(digest[:]))
	}
	require.Equal(t, fingerprints[0], fingerprints[1])
	require.Equal(t, fingerprints[0], fingerprints[2])
	require.Equal(t, counts[0], counts[1])
	require.Equal(t, counts[0], counts[2])
	return map[string]any{"completed_transfers": counts, "public_leaf_sha256": fingerprints}
}

func ordinaryRootCommitments(t *testing.T, c *client, r ordinaryRequest) any {
	t.Helper()
	ctx, cancel, err := c.rpcContext(c.config.Coordinator)
	require.NoError(t, err)
	defer cancel()
	response, err := pb.NewSparkServiceClient(c.conns[c.config.Coordinator]).GetSigningCommitments(ctx, &pb.GetSigningCommitmentsRequest{NodeIds: []string{r.LeafID}, Count: 2})
	require.NoError(t, err)
	require.Len(t, response.GetSigningCommitments(), 2)
	rows := []map[string]commitment{}
	for _, row := range response.GetSigningCommitments() {
		out := make(map[string]commitment)
		for id, nonce := range row.GetSigningNonceCommitments() {
			_, ok := c.config.Operators[id]
			require.True(t, ok)
			out[id] = commitment{Hiding: nonce.GetHiding(), Binding: nonce.GetBinding()}
		}
		require.Len(t, out, 2)
		rows = append(rows, out)
	}
	return rows
}
