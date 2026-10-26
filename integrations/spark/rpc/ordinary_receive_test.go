// Fund a fresh ordinary Spark root and send it to a PUBLIC receiver identity.
// No Zark USER scalar, dealer import, timelock mutation or operator extension.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/btcnetwork"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/transferleaf"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	sparktesting "github.com/lightsparkdev/spark/testing"
	"github.com/lightsparkdev/spark/testing/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ordinaryRequest struct {
	Op           string              `json:"op"`
	Directory    string              `json:"directory"`
	Receiver     blob                `json:"receiver"`
	TransferID   string              `json:"transfer_id"`
	LeafID       string              `json:"leaf_id"`
	Settings     *settings           `json:"settings,omitempty"`
	Operator     string              `json:"operator,omitempty"`
	Signature    blob                `json:"signature,omitempty"`
	ExitPacket   *ordinaryExitPacket `json:"packet,omitempty"`
	MaskCipher   blob                `json:"mask_cipher,omitempty"`
	Coefficients []blob              `json:"coefficients,omitempty"`
	Recipient    string              `json:"recipient,omitempty"`
	Txid         string              `json:"txid,omitempty"`
	Amount       uint64              `json:"amount_sats,omitempty"`
	LeafIDs      []string            `json:"leaf_ids,omitempty"`
	Sender       blob                `json:"sender,omitempty"`
	SwapID       string              `json:"swap_id,omitempty"`
	Targets      []uint64            `json:"targets,omitempty"`
	Ladder       map[string]int      `json:"ladder,omitempty"`
}

func ordinaryConfig(t *testing.T, directory string, identity keys.Private) *wallet.TestWalletConfig {
	t.Helper()
	t.Setenv("NUM_SPARK_OPERATORS", "3")
	var signer struct {
		Args []string `json:"args"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "signer-0.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &signer))
	require.Len(t, signer.Args, 2)
	return &wallet.TestWalletConfig{Network: btcnetwork.Regtest, SigningOperators: sparktesting.GetAllSigningOperators(t), CoordinatorIdentifier: fmt.Sprintf("%064x", 1),
		IdentityPrivateKey: identity, Threshold: 2, FrostGRPCConnectionFactory: &sparktesting.TestGRPCConnectionFactory{}, FrostSignerAddress: "unix://" + signer.Args[1],
		CoordinatorDatabaseURI: "postgresql://postgres@127.0.0.1:54329/sparkoperator_0?sslmode=disable"}
}
func ordinaryBegin(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	receiver, err := keys.ParsePublicKey(r.Receiver)
	require.NoError(t, err)
	id, err := uuid.Parse(r.TransferID)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, id)
	identity, user, temporary := keys.GeneratePrivateKey(), keys.GeneratePrivateKey(), keys.GeneratePrivateKey()
	cfg := ordinaryConfig(t, r.Directory, identity)
	client, err := sparktesting.InitBitcoinClient()
	if err == sparktesting.ErrClientAlreadyInitialized && client != nil {
		err = nil
	}
	require.NoError(t, err)
	faucet := sparktesting.GetFaucetInstance(client)
	require.NoError(t, faucet.MineBlocks(101))
	leaf, err := wallet.CreateNewTree(cfg, faucet, user, 10000)
	require.NoError(t, err)
	require.Empty(t, leaf.GetParentNodeId())
	require.Empty(t, leaf.GetDirectTx())
	require.Empty(t, leaf.GetDirectRefundTx())
	token, err := wallet.AuthenticateWithServer(t.Context(), cfg)
	require.NoError(t, err)
	ctx := wallet.ContextWithToken(t.Context(), token)
	conn, err := cfg.NewCoordinatorGRPCConnection()
	require.NoError(t, err)
	defer conn.Close()
	rpc := pb.NewSparkServiceClient(conn)
	pack, err := wallet.CreateTransferPackage(ctx, id, cfg, rpc, []wallet.LeafKeyTweak{{Leaf: leaf, SigningPrivKey: user, NewSigningPrivKey: temporary}}, receiver)
	require.NoError(t, err)
	expires := time.Now().Add(time.Hour)
	directory := filepath.Join(r.Directory, "ordinary-joint-receives")
	err = os.Mkdir(directory, 0700)
	require.True(t, err == nil || os.IsExist(err))
	// Retain the ordinary sender's exact package and its own keys BEFORE send.
	// A duplicate operation is recovery work; it never creates a new package.
	raw, err := json.Marshal(map[string]any{"identity": blob(identity.Serialize()), "user": blob(user.Serialize()), "temporary": blob(temporary.Serialize()), "leaf_id": leaf.GetId(), "package": pack, "expires": expires})
	require.NoError(t, err)
	f, err := os.OpenFile(filepath.Join(directory, id.String()+".private.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = f.Write(raw)
	require.NoError(t, err)
	require.NoError(t, f.Sync())
	require.NoError(t, f.Close())
	d, err := os.Open(directory)
	require.NoError(t, err)
	require.NoError(t, d.Sync())
	require.NoError(t, d.Close())
	sent, err := rpc.StartTransferV2(ctx, &pb.StartTransferRequest{TransferId: id.String(), OwnerIdentityPublicKey: identity.Public().Serialize(), ReceiverIdentityPublicKey: receiver.Serialize(),
		ExpiryTime: timestamppb.New(expires), TransferPackage: pack})
	require.NoError(t, err)
	require.Equal(t, id.String(), sent.GetTransfer().GetId())
	return map[string]any{"transfer_id": id.String(), "leaf_id": leaf.GetId(), "amount_sats": leaf.GetValue(), "sender_key_reconstructed_joint_user": false}
}
func ordinaryObserve(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	id, err := uuid.Parse(r.LeafID)
	require.NoError(t, err)
	transferID, err := uuid.Parse(r.TransferID)
	require.NoError(t, err)
	var rootRaw, refundRaw, directRaw, intermediateRefund, intermediateDirect []byte
	var user, combined, owner keys.Public
	var value uint64
	for i := 0; i < 3; i++ {
		reader := db.NewPostgresEntClientForIntegrationTest(t, fmt.Sprintf("postgresql://postgres@127.0.0.1:54329/sparkoperator_%d?sslmode=disable", i))
		defer reader.Close()
		tr, err := reader.Transfer.Get(ctx, transferID)
		require.NoError(t, err)
		require.Equal(t, "COMPLETED", string(tr.Status))
		// The completed transfer and queried leaf must be the same operation;
		// two unrelated rows with individually valid states are insufficient.
		linked, err := reader.TransferLeaf.Query().Where(
			transferleaf.HasTransferWith(transfer.IDEQ(transferID)),
			transferleaf.HasLeafWith(treenode.IDEQ(id)),
		).Select(transferleaf.FieldID, transferleaf.FieldIntermediateRefundTx,
			transferleaf.FieldIntermediateDirectFromCpfpRefundTx, transferleaf.FieldIntermediateDirectRefundTx).Only(ctx)
		require.NoError(t, err)
		require.Empty(t, linked.IntermediateDirectRefundTx)
		require.Equal(t, []byte(r.Receiver), tr.ReceiverIdentityPubkey.Serialize())
		node, err := reader.TreeNode.Query().Where(treenode.IDEQ(id)).Select(treenode.FieldID, treenode.FieldValue, treenode.FieldStatus, treenode.FieldRawTx, treenode.FieldRawRefundTx,
			treenode.FieldDirectFromCpfpRefundTx, treenode.FieldDirectTx, treenode.FieldDirectRefundTx, treenode.FieldOwnerIdentityPubkey, treenode.FieldOwnerSigningPubkey, treenode.FieldVerifyingPubkey).Only(ctx)
		require.NoError(t, err)
		require.Equal(t, "AVAILABLE", string(node.Status))
		require.True(t, ordinaryDenomination(node.Value), "observed leaf denomination")
		require.Empty(t, node.DirectTx)
		require.Empty(t, node.DirectRefundTx)
		if i == 0 {
			value = node.Value
			intermediateRefund, intermediateDirect = linked.IntermediateRefundTx, linked.IntermediateDirectFromCpfpRefundTx
			rootRaw, refundRaw, directRaw = node.RawTx, node.RawRefundTx, node.DirectFromCpfpRefundTx
			user, combined, owner = node.OwnerSigningPubkey, node.VerifyingPubkey, node.OwnerIdentityPubkey
		} else {
			require.True(t, bytes.Equal(intermediateRefund, linked.IntermediateRefundTx) && bytes.Equal(intermediateDirect, linked.IntermediateDirectFromCpfpRefundTx))
			require.True(t, bytes.Equal(rootRaw, node.RawTx) && bytes.Equal(refundRaw, node.RawRefundTx) && bytes.Equal(directRaw, node.DirectFromCpfpRefundTx))
			require.True(t, user.Equals(node.OwnerSigningPubkey) && combined.Equals(node.VerifyingPubkey) && owner.Equals(node.OwnerIdentityPubkey))
			require.Equal(t, value, node.Value)
		}
	}
	require.Equal(t, []byte(r.Receiver), owner.Serialize())
	root, err := common.TxFromRawTxBytes(rootRaw)
	require.NoError(t, err)
	require.Len(t, root.TxIn, 1)
	client, err := sparktesting.InitBitcoinClient()
	if err == sparktesting.ErrClientAlreadyInitialized && client != nil {
		err = nil
	}
	require.NoError(t, err)
	anchor := root.TxIn[0].PreviousOutPoint
	utxo, err := client.GetTxOut(&anchor.Hash, anchor.Index, true)
	require.NoError(t, err)
	require.NotNil(t, utxo)
	require.Greater(t, utxo.Confirmations, int64(0))
	amount, err := btcutil.NewAmount(utxo.Value)
	require.NoError(t, err)
	script, err := hex.DecodeString(utxo.ScriptPubKey.Hex)
	require.NoError(t, err)
	return map[string]any{"transfer_id": r.TransferID, "leaf_id": r.LeafID, "amount_sats": value, "operators_completed": 3, "active_confirmations": utxo.Confirmations, "active_block": utxo.BestBlock,
		"anchor":              map[string]any{"txid": blob(anchor.Hash[:]), "vout": anchor.Index, "amount_sats": int64(amount), "script": blob(script)},
		"intermediate_refund": blob(intermediateRefund), "intermediate_direct": blob(intermediateDirect),
		"root": blob(rootRaw), "cpfp_refund": blob(refundRaw), "direct_from_cpfp_refund": blob(directRaw), "user": blob(user.Serialize()), "combined": blob(combined.Serialize()), "owner": blob(owner.Serialize())}
}

// Test-only evidence: native RPC responses intentionally remove direct
// witnesses. Read public signed transaction columns, never operator secrets.
func ordinaryIntermediate(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	leafID, err := uuid.Parse(r.LeafID)
	require.NoError(t, err)
	transferID, err := uuid.Parse(r.TransferID)
	require.NoError(t, err)
	var rootRaw, refundRaw, directRaw []byte
	for i := 0; i < 3; i++ {
		reader := db.NewPostgresEntClientForIntegrationTest(t, fmt.Sprintf("postgresql://postgres@127.0.0.1:54329/sparkoperator_%d?sslmode=disable", i))
		defer reader.Close()
		tr, err := reader.Transfer.Get(ctx, transferID)
		require.NoError(t, err)
		require.Equal(t, "SENDER_KEY_TWEAKED", string(tr.Status))
		require.True(t, time.Now().Before(tr.ExpiryTime), "pending transfer expired; do not replace it automatically")
		require.Equal(t, []byte(r.Receiver), tr.ReceiverIdentityPubkey.Serialize())
		entry, err := reader.TransferLeaf.Query().Where(
			transferleaf.HasTransferWith(transfer.IDEQ(transferID)),
			transferleaf.HasLeafWith(treenode.IDEQ(leafID)),
		).Select(transferleaf.FieldID, transferleaf.FieldIntermediateRefundTx,
			transferleaf.FieldIntermediateDirectFromCpfpRefundTx, transferleaf.FieldIntermediateDirectRefundTx).Only(ctx)
		require.NoError(t, err)
		require.Empty(t, entry.IntermediateDirectRefundTx)
		node, err := reader.TreeNode.Query().Where(treenode.IDEQ(leafID)).Select(
			treenode.FieldID, treenode.FieldRawTx, treenode.FieldValue, treenode.FieldDirectTx, treenode.FieldDirectRefundTx).Only(ctx)
		require.NoError(t, err)
		require.True(t, ordinaryDenomination(node.Value), "intermediate leaf denomination")
		require.Empty(t, node.DirectTx)
		require.Empty(t, node.DirectRefundTx)
		if i == 0 {
			rootRaw, refundRaw, directRaw = node.RawTx, entry.IntermediateRefundTx, entry.IntermediateDirectFromCpfpRefundTx
		} else {
			require.True(t, bytes.Equal(rootRaw, node.RawTx) && bytes.Equal(refundRaw, entry.IntermediateRefundTx) && bytes.Equal(directRaw, entry.IntermediateDirectFromCpfpRefundTx))
		}
	}
	return map[string]any{"transfer_id": r.TransferID, "leaf_id": r.LeafID, "receiver": r.Receiver, "operators_agreed": 3,
		"root": blob(rootRaw), "cpfp_refund": blob(refundRaw), "direct_from_cpfp_refund": blob(directRaw)}
}
func TestOrdinaryReceiveNativeFixture(t *testing.T) {
	if os.Getenv("ZARK_SPARK_ORDINARY_RECEIVE_FIXTURE") != "1" {
		t.Skip("explicit funded regtest fixture only")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 128*1024)
	var native *client
	defer func() {
		if native != nil {
			native.close()
		}
	}()
	for scanner.Scan() {
		var r ordinaryRequest
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &r))
		if r.Recipient != "" {
			require.Regexp(t, "^[0-9a-f]{64}$", r.Recipient)
		}
		var value any
		switch r.Op {
		case "begin":
			value = ordinaryBegin(t, r)
		case "observe":
			value = ordinaryObserve(t, r)
		case "intermediate":
			value = ordinaryIntermediate(t, r)
		case "exit_recipient":
			value = ordinaryExitRecipient(t, r)
		case "public_fund":
			value = ordinaryPublicFund(t, r)
		case "public_transfer":
			value = ordinaryPublicTransfer(t, r)
		case "public_claim":
			value = ordinaryPublicClaim(t, r)
		case "public_leaf_shape":
			value = ordinaryPublicLeafShape(t, r)
		case "public_swap_begin":
			value = ordinaryPublicSwapBegin(t, r)
		case "public_swap_status":
			value = ordinaryPublicSwapStatus(t, r)
		case "public_swap_request":
			value = ordinaryPublicSwapRequest(t, r)
		case "ssp_ladder":
			value = ordinarySSPLadder(t, r)
		case "native_snapshot":
			value = ordinaryNativeSnapshot(t, r)
		case "exit_leaf_payload":
			value = ordinaryExitLeafPayload(t, r)
		case "exit_tweak_template":
			value = ordinaryExitTweakTemplate(t, r)
		case "exit_status":
			value = ordinaryExitStatus(t, r)
		case "exit_configure":
			require.Nil(t, native)
			require.NotNil(t, r.Settings)
			var err error
			native, err = newClient(*r.Settings)
			require.NoError(t, err)
			value = "ordinary-native-exit-v1"
		case "exit_challenge":
			require.NotNil(t, native)
			var err error
			value, err = native.challenge(r.Operator)
			require.NoError(t, err)
		case "exit_authenticate":
			require.NotNil(t, native)
			require.NoError(t, native.authenticate(r.Operator, r.Signature))
		case "exit_commitments":
			require.NotNil(t, native)
			value = ordinaryRootCommitments(t, native, r)
		case "exit_signing_payload":
			require.NotNil(t, native)
			value = ordinaryExitPayload(t, native, r.ExitPacket)
		case "exit_submit":
			require.NotNil(t, native)
			value = ordinaryExitSubmit(t, native, r)
		case "exit_claim":
			value = ordinaryExitClaim(t, r)
		case "exit_balance":
			value = ordinaryExitBalance(t, r)
		case "exit_tree":
			value = ordinaryExitTree(t, r)
		case "chain_status":
			value = ordinaryChainStatus(t, r)
		default:
			t.Fatal("unknown ordinary receive operation")
		}
		raw, err := json.Marshal(map[string]any{"ok": true, "value": value})
		require.NoError(t, err)
		fmt.Printf("ZARK_FIXTURE_REPLY %s\n", raw)
	}
	require.NoError(t, scanner.Err())
}
