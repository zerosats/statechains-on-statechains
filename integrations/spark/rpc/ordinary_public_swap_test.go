// Public wallet leaf swaps with the SSP, following the Breez SDK's Swap V3
// flow (services/swap.rs): an adaptor-signed primary transfer to the SSP,
// InitiateSwapPrimaryTransfer, then the SSP's request_swap, whose counter
// transfer the wallet claims with public_claim. Each external request is
// frozen before it is sent so an interrupted swap is resumed with identical
// bytes and never repeated with a new transfer ID. The fixture reports what
// the SSP and the operators said; the desktop decides whether it is acceptable.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	"github.com/lightsparkdev/spark/common/sighash"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent/predicate"
	"github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/transferleaf"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	sparktesting "github.com/lightsparkdev/spark/testing"
	"github.com/lightsparkdev/spark/testing/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The Breez SDK's SWAP_EXPIRY_DURATION: the primary transfer is short lived
// and carries no direct transactions.
const ordinarySwapExpiry = 2 * time.Minute

type ordinarySwap struct {
	Swap        string            `json:"swap"`
	Sender      string            `json:"sender"`
	SSP         blob              `json:"ssp"`
	TransferID  string            `json:"transfer_id"`
	LeafIDs     []string          `json:"leaf_ids"`
	LeafSats    map[string]uint64 `json:"leaf_sats"`
	Total       uint64            `json:"total"`
	Adaptor     blob              `json:"adaptor"`
	Temporaries []blob            `json:"temporaries"`
	Nodes       []blob            `json:"nodes"`
	Request     blob              `json:"request"`
	Expires     time.Time         `json:"expires"`
}

type ordinarySwapLeaf struct {
	LeafID    string `json:"leaf_id"`
	RawRefund string `json:"raw_unsigned_refund_transaction"`
	Signature string `json:"adaptor_added_signature,omitempty"`
}

func ordinarySwapPath(t *testing.T, r ordinaryRequest, suffix string) string {
	t.Helper()
	id, err := uuid.Parse(r.SwapID)
	require.NoError(t, err)
	require.True(t, id != uuid.Nil && id.String() == r.SwapID, "canonical swap UUID")
	return filepath.Join(r.Directory, "ordinary-public-swaps", id.String()+suffix)
}

func ordinarySwapLoad(t *testing.T, r ordinaryRequest) *ordinarySwap {
	t.Helper()
	raw, err := os.ReadFile(ordinarySwapPath(t, r, ".private.json"))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	var saved ordinarySwap
	require.NoError(t, json.Unmarshal(raw, &saved))
	require.True(t, saved.Swap == r.SwapID && saved.Sender == r.Recipient, "public swap record belongs to another swap")
	return &saved
}

// The SSP's base URL, from the stack's own SSP launch record.
func ordinarySSPURL(t *testing.T, r ordinaryRequest) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.Directory, "ssp.json"))
	require.NoError(t, err)
	var launch struct {
		Env map[string]string `json:"env"`
	}
	require.NoError(t, json.Unmarshal(raw, &launch))
	url := launch.Env["SSP_PUBLIC_URL"]
	require.NotEmpty(t, url, "SSP_PUBLIC_URL")
	return url
}

func ordinarySSPIdentity(t *testing.T, base string) keys.Public {
	t.Helper()
	response, err := http.Get(base + "/identity")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var body struct {
		Identity string `json:"identityPublicKey"`
	}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	raw, err := hex.DecodeString(body.Identity)
	require.NoError(t, err)
	identity, err := keys.ParsePublicKey(raw)
	require.NoError(t, err)
	return identity
}

// One GraphQL call. SSP-reported errors are returned, not fatal: the desktop
// decides whether a swap can be retried.
func ordinarySSPCall(t *testing.T, base, token, operation, query string, variables any) (map[string]any, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"operationName": operation, "query": query, "variables": variables})
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, base+"/graphql/spark/rc", bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 90 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err.Error()
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	var reply struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, fmt.Sprintf("SSP HTTP %d: %s", response.StatusCode, raw)
	}
	if len(reply.Errors) > 0 {
		return nil, reply.Errors[0].Message
	}
	return reply.Data, ""
}

// The SDK's SSP authentication: sign sha256 of the decoded challenge.
func ordinarySSPSession(t *testing.T, base string, identity keys.Private) (string, string) {
	t.Helper()
	public := hex.EncodeToString(identity.Public().Serialize())
	data, failure := ordinarySSPCall(t, base, "", "GetChallenge",
		"mutation GetChallenge($input: GetChallengeInput!) { get_challenge(input: $input) { protected_challenge } }",
		map[string]any{"input": map[string]any{"public_key": public}})
	if failure != "" {
		return "", failure
	}
	challenge, _ := data["get_challenge"].(map[string]any)["protected_challenge"].(string)
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	require.NoError(t, err)
	digest := sha256.Sum256(decoded)
	signature := ecdsa.Sign(identity.ToBTCEC(), digest[:]).Serialize()
	data, failure = ordinarySSPCall(t, base, "", "VerifyChallenge",
		"mutation VerifyChallenge($input: VerifyChallengeInput!) { verify_challenge(input: $input) { session_token } }",
		map[string]any{"input": map[string]any{"identity_public_key": public, "protected_challenge": challenge, "signature": hex.EncodeToString(signature)}})
	if failure != "" {
		return "", failure
	}
	token, _ := data["verify_challenge"].(map[string]any)["session_token"].(string)
	require.NotEmpty(t, token)
	return token, ""
}

// Freezes and submits the primary transfer of `leaf_ids` to the SSP. A
// repeated call never builds another package: it reports the frozen swap and
// re-submits its exact request only while the operators have not seen it and
// it is unexpired.
func ordinaryPublicSwapBegin(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	p := ordinaryPublicOpen(t, r)
	defer p.close()
	ids := ordinaryLeafIDs(t, r)
	saved := ordinarySwapLoad(t, r)
	if saved == nil {
		base := ordinarySSPURL(t, r)
		ssp := ordinarySSPIdentity(t, base)
		tweaks := p.tweaks(t, ids)
		adaptor := keys.GeneratePrivateKey()
		pack, transferID, err := wallet.GenerateTransferPackageForSwapV3(p.ctx, p.cfg, ssp, tweaks, p.rpc, adaptor.Public())
		require.NoError(t, err)
		expires := time.Now().Add(ordinarySwapExpiry)
		request := &pb.InitiateSwapPrimaryTransferRequest{
			Transfer: &pb.StartTransferRequest{TransferId: transferID.String(), OwnerIdentityPublicKey: p.identity.Public().Serialize(),
				ReceiverIdentityPublicKey: ssp.Serialize(), ExpiryTime: timestamppb.New(expires), TransferPackage: pack},
			AdaptorPublicKeys: &pb.AdaptorPublicKeyPackage{AdaptorPublicKey: adaptor.Public().Serialize()},
		}
		frozen, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
		require.NoError(t, err)
		sats, total := ordinaryLeafSats(tweaks)
		record := ordinarySwap{Swap: r.SwapID, Sender: r.Recipient, SSP: ssp.Serialize(), TransferID: transferID.String(), LeafIDs: ids, LeafSats: sats,
			Total: total, Adaptor: adaptor.Serialize(), Request: frozen, Expires: expires}
		for _, tweak := range tweaks {
			record.Temporaries = append(record.Temporaries, blob(tweak.NewSigningPrivKey.Serialize()))
			node, err := proto.MarshalOptions{Deterministic: true}.Marshal(tweak.Leaf)
			require.NoError(t, err)
			record.Nodes = append(record.Nodes, blob(node))
		}
		raw, err := json.Marshal(record)
		require.NoError(t, err)
		name := ordinarySwapPath(t, r, ".private.json")
		err = os.Mkdir(filepath.Dir(name), 0700)
		require.True(t, err == nil || os.IsExist(err))
		ordinaryFreeze(t, name, raw)
		saved = &record
	} else {
		require.True(t, slices.Equal(saved.LeafIDs, ids), "public swap retry changed its leaves")
	}
	if tr := p.transfer(t, saved.TransferID); tr != nil {
		return ordinarySwapReply(saved, tr.GetStatus().String())
	}
	if !time.Now().Before(saved.Expires) {
		return ordinarySwapReply(saved, "absent")
	}
	var request pb.InitiateSwapPrimaryTransferRequest
	require.NoError(t, proto.Unmarshal(saved.Request, &request))
	response, err := p.rpc.InitiateSwapPrimaryTransfer(p.ctx, &request)
	require.NoError(t, err)
	require.Equal(t, saved.TransferID, response.GetTransfer().GetId())
	ordinarySwapAdaptorLeaves(t, r, p, saved, &request, response)
	return ordinarySwapReply(saved, response.GetTransfer().GetStatus().String())
}

// Reports a swap without submitting anything.
func ordinaryPublicSwapStatus(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	saved := ordinarySwapLoad(t, r)
	if saved == nil {
		return map[string]any{"swap_id": r.SwapID, "frozen": false}
	}
	p := ordinaryPublicOpen(t, r)
	defer p.close()
	status := "absent"
	if tr := p.transfer(t, saved.TransferID); tr != nil {
		status = tr.GetStatus().String()
	}
	return ordinarySwapReply(saved, status)
}

func ordinarySwapReply(saved *ordinarySwap, status string) map[string]any {
	return map[string]any{"swap_id": saved.Swap, "frozen": true, "transfer_id": saved.TransferID, "status": status, "expired": !time.Now().Before(saved.Expires),
		"leaf_ids": saved.LeafIDs, "leaf_sats": saved.LeafSats, "amount_sats": saved.Total, "ssp": saved.SSP}
}

// The SDK sends the SSP each leaf's refund with the adaptor-added signature,
// aggregated from the user's frozen FROST share and the operators' shares in
// the Initiate response. They are frozen beside the swap.
func ordinarySwapAdaptorLeaves(t *testing.T, r ordinaryRequest, p *ordinaryPublic, saved *ordinarySwap, request *pb.InitiateSwapPrimaryTransferRequest, response *pb.InitiateSwapPrimaryTransferResponse) {
	t.Helper()
	jobs := map[string]*pb.UserSignedTxSigningJob{}
	for _, job := range request.GetTransfer().GetTransferPackage().GetLeavesToSend() {
		jobs[job.GetLeafId()] = job
	}
	nodes := map[string]*pb.TreeNode{}
	for _, raw := range saved.Nodes {
		var node pb.TreeNode
		require.NoError(t, proto.Unmarshal(raw, &node))
		nodes[node.GetId()] = &node
	}
	adaptor, err := keys.ParsePrivateKey(saved.Adaptor)
	require.NoError(t, err)
	conn, err := p.cfg.NewFrostGRPCConnection()
	require.NoError(t, err)
	defer conn.Close()
	frost := pbfrost.NewFrostServiceClient(conn)
	leaves := []ordinarySwapLeaf{}
	for _, result := range response.GetSigningResults() {
		job, node := jobs[result.GetLeafId()], nodes[result.GetLeafId()]
		require.True(t, job != nil && node != nil, "signing result for an unknown leaf")
		refund, err := common.TxFromRawTxBytes(job.GetRawTx())
		require.NoError(t, err)
		parent, err := common.TxFromRawTxBytes(node.GetNodeTx())
		require.NoError(t, err)
		hash, err := sighash.FromTx(refund, 0, parent.TxOut[node.GetVout()])
		require.NoError(t, err)
		signing := result.GetRefundTxSigningResult()
		aggregated, err := frost.AggregateFrost(p.ctx, &pbfrost.AggregateFrostRequest{Message: hash.Serialize(), SignatureShares: signing.GetSignatureShares(),
			PublicShares: signing.GetPublicKeys(), VerifyingKey: result.GetVerifyingKey(), Commitments: signing.GetSigningNonceCommitments(),
			UserCommitments: job.GetSigningNonceCommitment(), UserPublicKey: job.GetSigningPublicKey(), UserSignatureShare: job.GetUserSignature(),
			AdaptorPublicKey: adaptor.Public().Serialize()})
		require.NoError(t, err)
		leaves = append(leaves, ordinarySwapLeaf{LeafID: result.GetLeafId(), RawRefund: hex.EncodeToString(job.GetRawTx()), Signature: hex.EncodeToString(aggregated.GetSignature())})
	}
	raw, err := json.Marshal(leaves)
	require.NoError(t, err)
	ordinaryFreeze(t, ordinarySwapPath(t, r, ".leaves.json"), raw)
}

// Asks the SSP to settle a submitted primary transfer as `targets` plus the
// change. Retries reuse the same external transfer ID, which the SSP maps to
// one deterministic counter transfer. The reply carries the SSP's numbers
// unchanged; the desktop checks them and then the claimed leaves themselves.
func ordinaryPublicSwapRequest(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	saved := ordinarySwapLoad(t, r)
	require.NotNil(t, saved, "public swap was never frozen")
	require.True(t, len(r.Targets) >= 1 && len(r.Targets) <= 32, "swap target count")
	base := ordinarySSPURL(t, r)
	if ssp := ordinarySSPIdentity(t, base); !bytes.Equal(ssp.Serialize(), saved.SSP) {
		return map[string]any{"error": "SSP identity changed during the swap"}
	}
	identity, _ := ordinaryPublicKeys(t, r)
	token, failure := ordinarySSPSession(t, base, identity)
	if failure != "" {
		return map[string]any{"error": failure}
	}
	var request pb.InitiateSwapPrimaryTransferRequest
	require.NoError(t, proto.Unmarshal(saved.Request, &request))
	leaves := []ordinarySwapLeaf{}
	if raw, err := os.ReadFile(ordinarySwapPath(t, r, ".leaves.json")); err == nil {
		require.NoError(t, json.Unmarshal(raw, &leaves))
	} else {
		// The Initiate response was lost. The operators aggregated the
		// adaptor signatures themselves; the SSP gets the refunds alone.
		require.True(t, os.IsNotExist(err))
		for _, job := range request.GetTransfer().GetTransferPackage().GetLeavesToSend() {
			leaves = append(leaves, ordinarySwapLeaf{LeafID: job.GetLeafId(), RawRefund: hex.EncodeToString(job.GetRawTx())})
		}
	}
	adaptor, err := keys.ParsePrivateKey(saved.Adaptor)
	require.NoError(t, err)
	input := map[string]any{"adaptor_pubkey": hex.EncodeToString(adaptor.Public().Serialize()), "total_amount_sats": saved.Total, "target_amount_sats": r.Targets,
		"fee_sats": 0, "user_leaves": leaves, "user_outbound_transfer_external_id": saved.TransferID}
	data, failure := ordinarySSPCall(t, base, token, "RequestSwap",
		"mutation RequestSwap($input: RequestLeavesSwapInput!) { request_swap(input: $input) { request { id status total_amount { original_value } target_amount { original_value } fee { original_value } inbound_transfer { spark_id } } } }",
		map[string]any{"input": input})
	if failure != "" {
		return map[string]any{"error": failure}
	}
	swap, _ := data["request_swap"].(map[string]any)["request"].(map[string]any)
	require.NotNil(t, swap, "request_swap reply")
	amount := func(field string) any {
		value, _ := swap[field].(map[string]any)
		return value["original_value"]
	}
	inbound, _ := swap["inbound_transfer"].(map[string]any)
	return map[string]any{"swap_id": saved.Swap, "request_id": swap["id"], "status": swap["status"], "total_amount_sats": amount("total_amount"),
		"target_amount_sats": amount("target_amount"), "fee_sats": amount("fee"), "inbound_transfer_id": inbound["spark_id"], "ssp": saved.SSP}
}

// Test-only SSP liquidity: tops the SSP up to `ladder` (denomination ->
// count) whole root leaves that Incognito entry accepts. They are faucet-funded
// trees under throwaway keys, transferred to the SSP like any deposit.
func ordinarySSPLadder(t *testing.T, r ordinaryRequest) any {
	t.Helper()
	require.NotEmpty(t, r.Ladder)
	base := ordinarySSPURL(t, r)
	ssp := ordinarySSPIdentity(t, base)
	client, err := sparktesting.InitBitcoinClient()
	if err == sparktesting.ErrClientAlreadyInitialized && client != nil {
		err = nil
	}
	require.NoError(t, err)
	faucet := sparktesting.GetFaucetInstance(client)
	held, created := map[string]int{}, map[string]int{}
	for name, want := range r.Ladder {
		value, err := strconv.ParseUint(name, 10, 64)
		require.NoError(t, err)
		require.True(t, ordinaryDenomination(value) && want >= 0 && want <= 16, "ladder denomination")
		held[name] = ordinarySSPRoots(t, ssp, value)
		for i := held[name]; i < want; i++ {
			identity, user := keys.GeneratePrivateKey(), keys.GeneratePrivateKey()
			cfg := ordinaryConfig(t, r.Directory, identity)
			require.NoError(t, faucet.MineBlocks(1))
			leaf, err := wallet.CreateNewTree(cfg, faucet, user, int64(value))
			require.NoError(t, err)
			token, err := wallet.AuthenticateWithServer(t.Context(), cfg)
			require.NoError(t, err)
			_, err = wallet.SendTransferWithKeyTweaks(wallet.ContextWithToken(t.Context(), token), cfg,
				[]wallet.LeafKeyTweak{{Leaf: leaf, SigningPrivKey: user, NewSigningPrivKey: keys.GeneratePrivateKey()}}, ssp, time.Now().Add(time.Hour))
			require.NoError(t, err)
			created[name]++
		}
	}
	return map[string]any{"ssp": blob(ssp.Serialize()), "held": held, "created": created}
}

// Root leaves of `value` the SSP owns or is being sent, shaped like a
// wallet-created tree: no parent, no direct transactions and the zero-sequence
// root input Incognito entry requires.
func ordinarySSPRoots(t *testing.T, ssp keys.Public, value uint64) int {
	t.Helper()
	reader := db.NewPostgresEntClientForIntegrationTest(t, "postgresql://postgres@127.0.0.1:54329/sparkoperator_0?sslmode=disable")
	defer reader.Close()
	root := []predicate.TreeNode{treenode.ValueEQ(value), treenode.Not(treenode.HasParent())}
	owned, err := reader.TreeNode.Query().Where(append(root, treenode.OwnerIdentityPubkeyEQ(ssp), treenode.StatusEQ(schematype.TreeNodeStatusAvailable))...).All(t.Context())
	require.NoError(t, err)
	incoming, err := reader.TransferLeaf.Query().Where(transferleaf.HasTransferWith(transfer.ReceiverIdentityPubkeyEQ(ssp),
		transfer.StatusNotIn(schematype.TransferStatusCompleted, schematype.TransferStatusExpired, schematype.TransferStatusReturned)),
		transferleaf.HasLeafWith(root...)).QueryLeaf().All(t.Context())
	require.NoError(t, err)
	count := 0
	for _, node := range append(owned, incoming...) {
		if len(node.DirectTx) > 0 || len(node.DirectRefundTx) > 0 {
			continue
		}
		root, err := common.TxFromRawTxBytes(node.RawTx)
		if err == nil && len(root.TxIn) == 1 && root.TxIn[0].Sequence == 1<<30 {
			count++
		}
	}
	return count
}
