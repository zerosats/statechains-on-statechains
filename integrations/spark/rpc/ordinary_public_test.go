// A desktop profile's Public wallet is a named ordinary recipient: the same
// fixture-held identity and leaf-signing key that exit_claim and exit_balance
// use. These operations fund it from the faucet, send any of its leaves to
// another identity (a Public wallet, the SSP or a Zark joint identity) and
// claim what it receives.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/transferleaf"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	sparktesting "github.com/lightsparkdev/spark/testing"
	"github.com/lightsparkdev/spark/testing/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Whole leaf values the desktop moves into Incognito. Smaller leaves leave
// Spark's direct refund (value - 955) at or below the recovery proofs' fee +
// dust floor. Public leaves may hold any value.
func ordinaryDenomination(value uint64) bool {
	return value == 10000 || value == 5000 || value == 2000
}

func ordinaryPublicKeys(t *testing.T, r ordinaryRequest) (keys.Private, keys.Private) {
	t.Helper()
	require.NotEmpty(t, r.Recipient, "public wallet name")
	record := ordinaryLoadRecipient(t, r)
	identity, err := keys.ParsePrivateKey(record.Identity)
	require.NoError(t, err)
	user, err := keys.ParsePrivateKey(record.User)
	require.NoError(t, err)
	return identity, user
}

// An authenticated coordinator session of the Public wallet.
type ordinaryPublic struct {
	identity, user keys.Private
	cfg            *wallet.TestWalletConfig
	ctx            context.Context
	conn           so.OperatorClientConn
	rpc            pb.SparkServiceClient
}

func ordinaryPublicOpen(t *testing.T, r ordinaryRequest) *ordinaryPublic {
	t.Helper()
	identity, user := ordinaryPublicKeys(t, r)
	cfg := ordinaryConfig(t, r.Directory, identity)
	token, err := wallet.AuthenticateWithServer(t.Context(), cfg)
	require.NoError(t, err)
	conn, err := cfg.NewCoordinatorGRPCConnection()
	require.NoError(t, err)
	return &ordinaryPublic{identity: identity, user: user, cfg: cfg, ctx: wallet.ContextWithToken(t.Context(), token), conn: conn, rpc: pb.NewSparkServiceClient(conn)}
}

func (p *ordinaryPublic) close() { p.conn.Close() }

// The transfer this wallet sent or received, or nil when the operators do not know it.
func (p *ordinaryPublic) transfer(t *testing.T, id string) *pb.Transfer {
	t.Helper()
	response, err := p.rpc.QueryTransfersById(p.ctx, &pb.QueryTransfersByIdRequest{TransferIds: []string{id}, Network: pb.Network_REGTEST})
	require.NoError(t, err)
	require.LessOrEqual(t, len(response.GetTransfers()), 1)
	if len(response.GetTransfers()) == 0 {
		return nil
	}
	tr := response.GetTransfers()[0]
	require.Equal(t, id, tr.GetId())
	return tr
}

// The named AVAILABLE leaves, each signed by the wallet's fixed leaf key and
// handed to a fresh temporary key.
func (p *ordinaryPublic) tweaks(t *testing.T, ids []string) []wallet.LeafKeyTweak {
	t.Helper()
	nodes := map[string]*pb.TreeNode{}
	for offset := int64(0); ; offset += 100 {
		page, err := wallet.QueryNodes(p.ctx, p.cfg, false, 100, offset)
		require.NoError(t, err)
		for id, node := range page {
			nodes[id] = node
		}
		if len(page) < 100 {
			break
		}
	}
	tweaks := []wallet.LeafKeyTweak{}
	for _, id := range ids {
		leaf := nodes[id]
		require.NotNil(t, leaf, "public leaf is not owned by this wallet")
		require.Equal(t, "AVAILABLE", leaf.GetStatus())
		require.Equal(t, p.user.Public().Serialize(), leaf.GetOwnerSigningPublicKey())
		tweaks = append(tweaks, wallet.LeafKeyTweak{Leaf: leaf, SigningPrivKey: p.user, NewSigningPrivKey: keys.GeneratePrivateKey()})
	}
	return tweaks
}

// One to 32 distinct canonical leaf UUIDs, from `leaf_ids` or the older single `leaf_id`.
func ordinaryLeafIDs(t *testing.T, r ordinaryRequest) []string {
	t.Helper()
	ids := r.LeafIDs
	if r.LeafID != "" {
		require.Empty(t, ids, "leaf_id and leaf_ids together")
		ids = []string{r.LeafID}
	}
	require.True(t, len(ids) >= 1 && len(ids) <= 32, "public leaf count")
	for i, id := range ids {
		parsed, err := uuid.Parse(id)
		require.NoError(t, err)
		require.True(t, parsed != uuid.Nil && parsed.String() == id, "canonical leaf UUID")
		require.False(t, slices.Contains(ids[:i], id), "duplicate leaf")
	}
	return ids
}

func ordinaryLeafSats(tweaks []wallet.LeafKeyTweak) (map[string]uint64, uint64) {
	sats := map[string]uint64{}
	var total uint64
	for _, tweak := range tweaks {
		sats[tweak.Leaf.GetId()] = tweak.Leaf.GetValue()
		total += tweak.Leaf.GetValue()
	}
	return sats, total
}

// The new root leaf is signed by the wallet's fixed leaf key, exactly like a
// leaf it later receives through exit_claim.
func ordinaryPublicFund(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	require.True(t, ordinaryDenomination(r.Amount), "public fund denomination")
	identity, user := ordinaryPublicKeys(t, r)
	cfg := ordinaryConfig(t, r.Directory, identity)
	client, err := sparktesting.InitBitcoinClient()
	if err == sparktesting.ErrClientAlreadyInitialized && client != nil {
		err = nil
	}
	require.NoError(t, err)
	faucet := sparktesting.GetFaucetInstance(client)
	require.NoError(t, faucet.MineBlocks(101))
	leaf, err := wallet.CreateNewTree(cfg, faucet, user, int64(r.Amount))
	require.NoError(t, err)
	require.Empty(t, leaf.GetParentNodeId())
	require.Empty(t, leaf.GetDirectTx())
	require.Empty(t, leaf.GetDirectRefundTx())
	return map[string]any{"leaf_id": leaf.GetId(), "amount_sats": leaf.GetValue(), "identity": blob(identity.Public().Serialize())}
}

type ordinaryPublicSend struct {
	Sender      string            `json:"sender"`
	Temporaries []blob            `json:"temporaries"`
	LeafIDs     []string          `json:"leaf_ids"`
	LeafSats    map[string]uint64 `json:"leaf_sats"`
	Receiver    blob              `json:"receiver"`
	Request     blob              `json:"request"`
	Expires     time.Time         `json:"expires"`
}

// Sends AVAILABLE leaves of any value in one transfer. The exact
// StartTransferV2 request is frozen before it is sent, so the transfer ID is
// idempotent: a repeated call reports the existing transfer, re-sends the
// frozen bytes while they are unexpired, or reports `absent` once they have
// expired and can no longer be accepted. It never builds a second package.
func ordinaryPublicTransfer(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	p := ordinaryPublicOpen(t, r)
	defer p.close()
	receiver, err := keys.ParsePublicKey(r.Receiver)
	require.NoError(t, err)
	require.False(t, receiver.Equals(p.identity.Public()), "public transfer to itself")
	id, err := uuid.Parse(r.TransferID)
	require.NoError(t, err)
	require.True(t, id != uuid.Nil && id.String() == r.TransferID)
	ids := ordinaryLeafIDs(t, r)
	directory := filepath.Join(r.Directory, "ordinary-public-transfers")
	name := filepath.Join(directory, id.String()+".private.json")
	if raw, err := os.ReadFile(name); err == nil {
		var saved ordinaryPublicSend
		require.NoError(t, json.Unmarshal(raw, &saved))
		require.NotEmpty(t, saved.Request, "legacy public transfer record; reconcile it manually")
		require.True(t, saved.Sender == r.Recipient && slices.Equal(saved.LeafIDs, ids) && bytes.Equal(saved.Receiver, r.Receiver), "public transfer retry changed")
		if tr := p.transfer(t, id.String()); tr != nil {
			require.Equal(t, p.identity.Public().Serialize(), tr.GetSenderIdentityPublicKey())
			require.Equal(t, receiver.Serialize(), tr.GetReceiverIdentityPublicKey())
			return ordinaryPublicSent(id.String(), ids, saved.LeafSats, "sent")
		}
		if !time.Now().Before(saved.Expires) {
			return ordinaryPublicSent(id.String(), ids, saved.LeafSats, "absent")
		}
		var request pb.StartTransferRequest
		require.NoError(t, proto.Unmarshal(saved.Request, &request))
		sent, err := p.rpc.StartTransferV2(p.ctx, &request)
		require.NoError(t, err)
		require.Equal(t, id.String(), sent.GetTransfer().GetId())
		return ordinaryPublicSent(id.String(), ids, saved.LeafSats, "sent")
	} else {
		require.True(t, os.IsNotExist(err))
	}
	tweaks := p.tweaks(t, ids)
	pack, err := wallet.CreateTransferPackage(p.ctx, id, p.cfg, p.rpc, tweaks, receiver)
	require.NoError(t, err)
	expires := time.Now().Add(time.Hour)
	request := &pb.StartTransferRequest{TransferId: id.String(), OwnerIdentityPublicKey: p.identity.Public().Serialize(), ReceiverIdentityPublicKey: receiver.Serialize(),
		ExpiryTime: timestamppb.New(expires), TransferPackage: pack}
	frozen, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	require.NoError(t, err)
	temporaries := []blob{}
	for _, tweak := range tweaks {
		temporaries = append(temporaries, blob(tweak.NewSigningPrivKey.Serialize()))
	}
	sats, _ := ordinaryLeafSats(tweaks)
	raw, err := json.Marshal(ordinaryPublicSend{Sender: r.Recipient, Temporaries: temporaries, LeafIDs: ids, LeafSats: sats, Receiver: r.Receiver, Request: frozen, Expires: expires})
	require.NoError(t, err)
	err = os.Mkdir(directory, 0700)
	require.True(t, err == nil || os.IsExist(err))
	ordinaryFreeze(t, name, raw)
	sent, err := p.rpc.StartTransferV2(p.ctx, request)
	require.NoError(t, err)
	require.Equal(t, id.String(), sent.GetTransfer().GetId())
	return ordinaryPublicSent(id.String(), ids, sats, "sent")
}

func ordinaryPublicSent(id string, ids []string, sats map[string]uint64, status string) map[string]any {
	var total uint64
	for _, value := range sats {
		total += value
	}
	value := map[string]any{"transfer_id": id, "leaf_ids": ids, "leaf_sats": sats, "amount_sats": total, "status": status}
	if len(ids) == 1 {
		value["leaf_id"] = ids[0]
	}
	return value
}

// Claims an incoming transfer of any leaves into the Public wallet and reports
// what all three operators agree it now owns. This is the Public-only claim:
// it accepts split (non-root) leaves, as an ordinary Spark wallet does, so it
// checks no on-chain anchor. Incognito entry never uses it; that path keeps
// ordinaryObserve's root-shape and confirmed-anchor checks.
func ordinaryPublicClaim(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	p := ordinaryPublicOpen(t, r)
	defer p.close()
	id, err := uuid.Parse(r.TransferID)
	require.NoError(t, err)
	require.True(t, id != uuid.Nil && id.String() == r.TransferID)
	tr := p.transfer(t, id.String())
	require.NotNil(t, tr, "incoming public transfer is unknown to the operators")
	require.Equal(t, p.identity.Public().Serialize(), tr.GetReceiverIdentityPublicKey())
	if len(r.Sender) > 0 {
		require.Equal(t, []byte(r.Sender), tr.GetSenderIdentityPublicKey(), "incoming public transfer sender")
	}
	ids := []string{}
	for _, item := range tr.GetLeaves() {
		ids = append(ids, item.GetLeaf().GetId())
	}
	require.NotEmpty(t, ids)
	if r.LeafID != "" || len(r.LeafIDs) > 0 {
		want := ordinaryLeafIDs(t, r)
		require.ElementsMatch(t, want, ids, "incoming public transfer leaves")
	}
	if tr.GetStatus() != pb.TransferStatus_TRANSFER_STATUS_COMPLETED {
		_, savedErr := os.Stat(filepath.Join(r.Directory, "ordinary-exit-"+id.String()+".claim.pb"))
		if os.IsNotExist(savedErr) {
			require.Equal(t, pb.TransferStatus_TRANSFER_STATUS_SENDER_KEY_TWEAKED, tr.GetStatus())
		} else {
			require.NoError(t, savedErr)
			require.NotEqual(t, pb.TransferStatus_TRANSFER_STATUS_EXPIRED, tr.GetStatus())
			require.NotEqual(t, pb.TransferStatus_TRANSFER_STATUS_RETURNED, tr.GetStatus())
		}
		masks, err := wallet.VerifyPendingTransfer(p.ctx, p.cfg, tr)
		require.NoError(t, err)
		claim := ordinaryFrozenClaim(t, p.ctx, r.Directory, id.String(), p.cfg, tr, masks, p.user)
		response, err := p.rpc.ClaimTransfer(p.ctx, claim)
		require.NoError(t, err)
		require.Equal(t, pb.TransferStatus_TRANSFER_STATUS_COMPLETED, response.GetTransfer().GetStatus())
	}
	sats := ordinaryPublicObserve(t, id, p.identity.Public(), p.user.Public(), ids)
	var total uint64
	for _, value := range sats {
		total += value
	}
	return map[string]any{"transfer_id": id.String(), "leaf_ids": ids, "leaf_sats": sats, "amount_sats": total, "operators_completed": 3,
		"owner": blob(p.identity.Public().Serialize()), "sender": blob(tr.GetSenderIdentityPublicKey())}
}

// Every operator must report the transfer COMPLETED to `owner` and each of its
// leaves AVAILABLE to `owner` under the wallet's leaf key, with equal values.
func ordinaryPublicObserve(t *testing.T, id uuid.UUID, owner, user keys.Public, ids []string) map[string]uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var agreed map[string]uint64
	for i := 0; i < 3; i++ {
		reader := db.NewPostgresEntClientForIntegrationTest(t, fmt.Sprintf("postgresql://postgres@127.0.0.1:54329/sparkoperator_%d?sslmode=disable", i))
		defer reader.Close()
		tr, err := reader.Transfer.Get(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "COMPLETED", string(tr.Status))
		require.True(t, owner.Equals(tr.ReceiverIdentityPubkey))
		sats := map[string]uint64{}
		for _, leaf := range ids {
			leafID, err := uuid.Parse(leaf)
			require.NoError(t, err)
			linked, err := reader.TransferLeaf.Query().Where(transferleaf.HasTransferWith(transfer.IDEQ(id)), transferleaf.HasLeafWith(treenode.IDEQ(leafID))).Exist(ctx)
			require.NoError(t, err)
			require.True(t, linked, "claimed leaf is not part of the transfer")
			node, err := reader.TreeNode.Query().Where(treenode.IDEQ(leafID)).Select(treenode.FieldID, treenode.FieldValue, treenode.FieldStatus,
				treenode.FieldOwnerIdentityPubkey, treenode.FieldOwnerSigningPubkey).Only(ctx)
			require.NoError(t, err)
			require.Equal(t, "AVAILABLE", string(node.Status))
			require.True(t, owner.Equals(node.OwnerIdentityPubkey) && user.Equals(node.OwnerSigningPubkey), "claimed leaf owner")
			sats[leaf] = node.Value
		}
		if i == 0 {
			agreed = sats
		} else {
			require.Equal(t, agreed, sats, "operators disagree on claimed leaf values")
		}
	}
	return agreed
}

// Public facts about one Public leaf that Incognito entry will check: tree
// position, transaction shape and the root's on-chain anchor. The wallet uses
// them to refuse a leaf before moving it; entry still applies its own checks.
func ordinaryPublicLeafShape(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	identity, _ := ordinaryPublicKeys(t, r)
	leafID, err := uuid.Parse(r.LeafID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var first []any
	for i := 0; i < 3; i++ {
		reader := db.NewPostgresEntClientForIntegrationTest(t, fmt.Sprintf("postgresql://postgres@127.0.0.1:54329/sparkoperator_%d?sslmode=disable", i))
		defer reader.Close()
		node, err := reader.TreeNode.Query().Where(treenode.IDEQ(leafID)).Select(treenode.FieldID, treenode.FieldValue, treenode.FieldStatus, treenode.FieldRawTx,
			treenode.FieldRawRefundTx, treenode.FieldDirectTx, treenode.FieldDirectRefundTx, treenode.FieldOwnerIdentityPubkey).Only(ctx)
		require.NoError(t, err)
		child, err := reader.TreeNode.Query().Where(treenode.IDEQ(leafID), treenode.HasParent()).Exist(ctx)
		require.NoError(t, err)
		facts := []any{node.Value, string(node.Status), node.RawTx, node.RawRefundTx, len(node.DirectTx) > 0, len(node.DirectRefundTx) > 0, child, node.OwnerIdentityPubkey.Serialize()}
		if i == 0 {
			first = facts
		} else {
			require.Equal(t, first, facts, "operators disagree on the Public leaf")
		}
	}
	require.Equal(t, identity.Public().Serialize(), first[7], "leaf is not owned by this Public wallet")
	root, err := common.TxFromRawTxBytes(first[2].([]byte))
	require.NoError(t, err)
	refund, err := common.TxFromRawTxBytes(first[3].([]byte))
	require.NoError(t, err)
	shape := map[string]any{"leaf_id": r.LeafID, "amount_sats": first[0], "status": first[1], "parent": first[6], "direct": first[4].(bool) || first[5].(bool),
		"node_inputs": len(root.TxIn), "node_outputs": len(root.TxOut), "refund_inputs": len(refund.TxIn), "anchor_confirmations": 0}
	if len(root.TxIn) > 0 && len(root.TxOut) > 0 && len(refund.TxIn) > 0 {
		hash := root.TxHash()
		shape["node_sequence"] = root.TxIn[0].Sequence
		shape["node_output_sats"] = root.TxOut[0].Value
		shape["refund_sequence"] = refund.TxIn[0].Sequence
		shape["refund_spends_node"] = refund.TxIn[0].PreviousOutPoint.Hash == hash && refund.TxIn[0].PreviousOutPoint.Index == 0
		if !first[6].(bool) {
			client, err := sparktesting.InitBitcoinClient()
			if err == sparktesting.ErrClientAlreadyInitialized && client != nil {
				err = nil
			}
			require.NoError(t, err)
			anchor := root.TxIn[0].PreviousOutPoint
			utxo, err := client.GetTxOut(&anchor.Hash, anchor.Index, true)
			require.NoError(t, err)
			if utxo != nil {
				shape["anchor_confirmations"] = utxo.Confirmations
			}
		}
	}
	return shape
}
