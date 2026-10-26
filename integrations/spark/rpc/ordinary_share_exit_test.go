// Test-only observations for the share-release exit: the wallet's chain gate
// and the fresh ordinary recipient's balance. Neither touches private keys
// beyond the recipient's own public identity.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/keys"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	sparktesting "github.com/lightsparkdev/spark/testing"
	"github.com/stretchr/testify/require"
)

// Absence is reported only from a synced txindex and the node's own
// "no such transaction" code. Every other failure stops the fixture, so an
// unavailable node can never read as absent to the wallet's gate.
func ordinaryChainStatus(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	raw, err := hex.DecodeString(r.Txid)
	require.NoError(t, err)
	require.True(t, len(raw) == 32 && hex.EncodeToString(raw) == r.Txid, "chain status txid encoding")
	client, err := sparktesting.InitBitcoinClient()
	if err == sparktesting.ErrClientAlreadyInitialized && client != nil {
		err = nil
	}
	require.NoError(t, err)
	info, err := client.RawRequest("getindexinfo", []json.RawMessage{json.RawMessage(`"txindex"`)})
	require.NoError(t, err)
	var index struct {
		Txindex *struct {
			Synced bool `json:"synced"`
		} `json:"txindex"`
	}
	require.NoError(t, json.Unmarshal(info, &index))
	require.True(t, index.Txindex != nil && index.Txindex.Synced, "txindex unavailable; absence is unknown")
	txid, err := json.Marshal(r.Txid)
	require.NoError(t, err)
	found, err := client.RawRequest("getrawtransaction", []json.RawMessage{txid, json.RawMessage(`true`)})
	status := "absent"
	if err != nil {
		var rpcErr *btcjson.RPCError
		require.True(t, errors.As(err, &rpcErr) && rpcErr.Code == btcjson.ErrRPCInvalidAddressOrKey, "chain query failed: %v", err)
	} else {
		var tx struct {
			Txid          string `json:"txid"`
			Confirmations int64  `json:"confirmations"`
		}
		require.NoError(t, json.Unmarshal(found, &tx))
		require.Equal(t, r.Txid, tx.Txid)
		status = "mempool"
		if tx.Confirmations > 0 {
			status = "confirmed"
		}
	}
	return map[string]any{"txid": r.Txid, "status": status, "txindex_synced": true}
}

// Available leaves owned by the recipient identity, which all three operators
// must report identically. Operators apply a new tree or transfer one after
// another, so a read may briefly disagree; only lasting disagreement fails.
func ordinaryExitBalance(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	record := ordinaryLoadRecipient(t, r)
	identity, err := keys.ParsePrivateKey(record.Identity)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	readers := make([]*ent.Client, 3)
	for i := range readers {
		readers[i] = db.NewPostgresEntClientForIntegrationTest(t, fmt.Sprintf("postgresql://postgres@127.0.0.1:54329/sparkoperator_%d?sslmode=disable", i))
		defer readers[i].Close()
	}
	read := func(reader *ent.Client) ([]string, map[string]uint64, uint64) {
		nodes, err := reader.TreeNode.Query().Where(treenode.OwnerIdentityPubkeyEQ(identity.Public()), treenode.StatusEQ("AVAILABLE")).
			Select(treenode.FieldID, treenode.FieldValue).All(ctx)
		require.NoError(t, err)
		ids := []string{}
		values := map[string]uint64{}
		var sum uint64
		for _, node := range nodes {
			ids = append(ids, node.ID.String())
			values[node.ID.String()] = node.Value
			sum += node.Value
		}
		sort.Strings(ids)
		return ids, values, sum
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		leaves, values, total := read(readers[0])
		agreed := true
		for _, reader := range readers[1:] {
			ids, other, sum := read(reader)
			agreed = agreed && sum == total && slices.Equal(ids, leaves) && maps.Equal(other, values)
		}
		if agreed {
			return map[string]any{"identity": blob(identity.Public().Serialize()), "available_sats": total, "leaves": leaves, "leaf_sats": values, "operators_agreed": 3}
		}
		require.True(t, time.Now().Before(deadline), "operators disagree on the recipient's available leaves")
		time.Sleep(250 * time.Millisecond)
	}
}

// One Public leaf, or a parent it spends, with the transactions an offline
// exit needs. Optional transactions are omitted when the operator has none.
type exitNode struct {
	ID                     string  `json:"id"`
	Value                  uint64  `json:"value"`
	Status                 string  `json:"status"`
	Owner                  string  `json:"owner"`
	SigningKey             string  `json:"signing_key"`
	VerifyingKey           string  `json:"verifying_key"`
	Vout                   int16   `json:"vout"`
	ParentID               *string `json:"parent_id"`
	RawTx                  string  `json:"raw_tx"`
	RawRefundTx            string  `json:"raw_refund_tx"`
	DirectTx               *string `json:"direct_tx,omitempty"`
	DirectRefundTx         *string `json:"direct_refund_tx,omitempty"`
	DirectFromCpfpRefundTx *string `json:"direct_from_cpfp_refund_tx,omitempty"`
}

func exitHex(raw []byte) *string {
	if len(raw) == 0 {
		return nil
	}
	value := hex.EncodeToString(raw)
	return &value
}

func describeExitNode(t *testing.T, ctx context.Context, node *ent.TreeNode) exitNode {
	t.Helper()
	parent, err := node.QueryParent().Select(treenode.FieldID).Only(ctx)
	var parentID *string
	if ent.IsNotFound(err) {
		err = nil
	} else if err == nil {
		id := parent.ID.String()
		parentID = &id
	}
	require.NoError(t, err)
	return exitNode{
		ID: node.ID.String(), Value: node.Value, Status: string(node.Status),
		Owner:        hex.EncodeToString(node.OwnerIdentityPubkey.Serialize()),
		SigningKey:   hex.EncodeToString(node.OwnerSigningPubkey.Serialize()),
		VerifyingKey: hex.EncodeToString(node.VerifyingPubkey.Serialize()),
		Vout:         node.Vout, ParentID: parentID,
		RawTx: hex.EncodeToString(node.RawTx), RawRefundTx: hex.EncodeToString(node.RawRefundTx),
		DirectTx: exitHex(node.DirectTx), DirectRefundTx: exitHex(node.DirectRefundTx),
		DirectFromCpfpRefundTx: exitHex(node.DirectFromCpfpRefundTx),
	}
}

// Available leaves of this Public wallet, plus every ancestor, read from all
// three operators. Lasting disagreement returns operators_agreed 0 and no
// nodes, so the wallet keeps the file it already has. A brief lag while the
// operators apply a transfer one after another is retried, same as the balance.
func ordinaryExitTree(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	record := ordinaryLoadRecipient(t, r)
	identity, err := keys.ParsePrivateKey(record.Identity)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	readers := make([]*ent.Client, 3)
	for i := range readers {
		readers[i] = db.NewPostgresEntClientForIntegrationTest(t, fmt.Sprintf("postgresql://postgres@127.0.0.1:54329/sparkoperator_%d?sslmode=disable", i))
		defer readers[i].Close()
	}
	read := func(reader *ent.Client) ([]exitNode, []exitNode) {
		available, err := reader.TreeNode.Query().Where(
			treenode.OwnerIdentityPubkeyEQ(identity.Public()), treenode.StatusEQ("AVAILABLE"),
		).All(ctx)
		require.NoError(t, err)
		leaves := make([]exitNode, 0, len(available))
		held := map[uuid.UUID]bool{}
		for _, node := range available {
			held[node.ID] = true
			leaves = append(leaves, describeExitNode(t, ctx, node))
		}
		ancestors := []exitNode{}
		seen := map[uuid.UUID]bool{}
		for _, node := range available {
			current := node
			for depth := 0; depth < 64; depth++ {
				parent, err := current.QueryParent().Only(ctx)
				if ent.IsNotFound(err) {
					break
				}
				require.NoError(t, err)
				if held[parent.ID] || seen[parent.ID] {
					break
				}
				seen[parent.ID] = true
				ancestors = append(ancestors, describeExitNode(t, ctx, parent))
				current = parent
			}
		}
		sort.Slice(leaves, func(i, j int) bool { return leaves[i].ID < leaves[j].ID })
		sort.Slice(ancestors, func(i, j int) bool { return ancestors[i].ID < ancestors[j].ID })
		return leaves, ancestors
	}
	same := func(a, b []exitNode) bool {
		left, err := json.Marshal(a)
		require.NoError(t, err)
		right, err := json.Marshal(b)
		require.NoError(t, err)
		return bytes.Equal(left, right)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		leaves, ancestors := read(readers[0])
		agreed := true
		for _, reader := range readers[1:] {
			otherLeaves, otherAncestors := read(reader)
			agreed = agreed && same(leaves, otherLeaves) && same(ancestors, otherAncestors)
		}
		if agreed {
			return map[string]any{
				"identity": blob(identity.Public().Serialize()), "operators_agreed": 3,
				"leaves": leaves, "ancestors": ancestors,
			}
		}
		if !time.Now().Before(deadline) {
			return map[string]any{"operators_agreed": 0}
		}
		time.Sleep(250 * time.Millisecond)
	}
}
