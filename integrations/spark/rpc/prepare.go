package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"google.golang.org/protobuf/proto"

	"github.com/btcsuite/btcd/wire"
	spark "github.com/lightsparkdev/spark"
	"github.com/lightsparkdev/spark/common"
	txutil "github.com/lightsparkdev/spark/common/bitcoin_transaction"
	"github.com/lightsparkdev/spark/common/keys"
	"github.com/lightsparkdev/spark/common/sighash"
	pb "github.com/lightsparkdev/spark/proto/spark"
)

type unsignedRefund struct {
	Raw       blob                  `json:"raw_tx"`
	Parent    blob                  `json:"prev_tx"`
	Sighash   blob                  `json:"sighash"`
	Operators map[string]commitment `json:"operators"`
}
type backing struct {
	LeafID       string          `json:"leaf_id"`
	Amount       uint64          `json:"amount_sats"`
	Owner        blob            `json:"owner_identity"`
	User         blob            `json:"user_key"`
	Operator     blob            `json:"operator_key"`
	Combined     blob            `json:"combined_key"`
	Node         blob            `json:"node_tx"`
	Direct       blob            `json:"direct_tx"`
	Recoveries   [3]blob         `json:"recoveries"`
	Observations map[string]blob `json:"observations"`
}

type preparation struct {
	Backing  backing          `json:"backing"`
	LeafID   string           `json:"leaf_id"`
	Amount   uint64           `json:"amount_sats"`
	Owner    blob             `json:"owner_identity"`
	User     blob             `json:"user_key"`
	Operator blob             `json:"operator_key"`
	Combined blob             `json:"combined_key"`
	Receiver blob             `json:"receiver_identity"`
	Refunds  []unsignedRefund `json:"refunds"`
}

// Rebuild the same three stepped-down refund variants as the pinned native
// MPC wallet helper. Production code uses common transaction primitives, not
// the upstream testing wallet's private-key-taking sender implementation.
func refundVariant(leaf *pb.TreeNode, receiver keys.Public, variant int) (unsignedRefund, error) {
	parentBytes, oldRefund := leaf.GetNodeTx(), leaf.GetRefundTx()
	if variant == 1 {
		parentBytes = leaf.GetDirectTx()
	}
	parent, err := common.TxFromRawTxBytes(parentBytes)
	if err != nil || len(parent.TxOut) == 0 {
		return unsignedRefund{}, errors.New("native refund parent missing")
	}
	previous, err := common.TxFromRawTxBytes(oldRefund)
	if err != nil || len(previous.TxIn) != 1 {
		return unsignedRefund{}, errors.New("native refund history missing")
	}
	oldSequence := previous.TxIn[0].Sequence
	rounded := txutil.RoundDownToTimelockInterval(oldSequence & 0xffff)
	sequence, _, err := txutil.NextSequence((oldSequence & 0xffff0000) | rounded)
	if err != nil {
		return unsignedRefund{}, errors.New("native leaf requires renewal")
	}
	if variant != 0 {
		sequence += spark.DirectTimelockOffset
	}
	txType := txutil.TxTypeRefundCPFP
	if variant == 1 {
		txType = txutil.TxTypeRefundDirect
	}
	if variant == 2 {
		txType = txutil.TxTypeRefundDirectFromCPFP
	}
	sequence, err = txutil.ValidateSequence(oldSequence&0xffff, txType, sequence)
	if err != nil {
		return unsignedRefund{}, errors.New("native refund sequence rejected")
	}
	script, err := common.P2TRScriptFromPubKey(receiver)
	if err != nil {
		return unsignedRefund{}, err
	}
	refund := wire.NewMsgTx(3)
	refund.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: parent.TxHash(), Index: 0}, Sequence: sequence})
	amount := parent.TxOut[0].Value
	if variant != 0 {
		amount = common.MaybeApplyFee(amount)
	}
	refund.AddTxOut(wire.NewTxOut(amount, script))
	if variant == 0 {
		refund.AddTxOut(common.EphemeralAnchorOutput())
	}
	hash, err := sighash.FromTx(refund, 0, parent.TxOut[0])
	if err != nil {
		return unsignedRefund{}, err
	}
	var raw bytes.Buffer
	if err := refund.Serialize(&raw); err != nil {
		return unsignedRefund{}, err
	}
	return unsignedRefund{Raw: raw.Bytes(), Parent: parentBytes, Sighash: hash.Serialize()}, nil
}

func (c *client) prepare(leafID string, receiverBytes []byte) (preparation, error) {
	receiver, err := keys.ParsePublicKey(receiverBytes)
	if err != nil {
		return preparation{}, errors.New("native receiver key invalid")
	}
	source, leaf, err := c.source(leafID)
	if err != nil {
		return preparation{}, err
	}
	result := preparation{Backing: source, LeafID: leafID, Amount: leaf.GetValue(), Owner: leaf.GetOwnerIdentityPublicKey(), User: leaf.GetOwnerSigningPublicKey(), Operator: leaf.GetSigningKeyshare().GetPublicKey(), Combined: leaf.GetVerifyingPublicKey(), Receiver: receiverBytes}
	for variant := 0; variant < 3; variant++ {
		refund, err := refundVariant(leaf, receiver, variant)
		if err != nil {
			return result, err
		}
		result.Refunds = append(result.Refunds, refund)
	}
	ctx, cancel, err := c.rpcContext(c.config.Coordinator)
	if err != nil {
		return result, err
	}
	defer cancel()
	response, err := pb.NewSparkServiceClient(c.conns[c.config.Coordinator]).GetSigningCommitments(ctx, &pb.GetSigningCommitmentsRequest{NodeIds: []string{leafID}, Count: 3})
	if err != nil {
		return result, err
	}
	if len(response.GetSigningCommitments()) != 3 {
		return result, errors.New("native refund nonce count mismatch")
	}
	for i, requested := range response.GetSigningCommitments() {
		result.Refunds[i].Operators = make(map[string]commitment)
		for id, nonce := range requested.GetSigningNonceCommitments() {
			if _, ok := c.config.Operators[id]; !ok {
				return result, errors.New("unconfigured native signing operator")
			}
			result.Refunds[i].Operators[id] = commitment{Hiding: nonce.GetHiding(), Binding: nonce.GetBinding()}
		}
	}
	return result, nil
}

func (c *client) source(leafID string) (backing, *pb.TreeNode, error) {
	var leaf *pb.TreeNode
	observations := make(map[string]blob)
	for id := range c.config.Operators {
		ctx, cancel, err := c.rpcContext(id)
		if err != nil {
			return backing{}, nil, err
		}
		response, err := pb.NewSparkServiceClient(c.conns[id]).QueryNodes(ctx, &pb.QueryNodesRequest{Source: &pb.QueryNodesRequest_NodeIds{NodeIds: &pb.TreeNodeIds{NodeIds: []string{leafID}}}, Limit: 1})
		cancel()
		if err != nil {
			return backing{}, nil, err
		}
		node, ok := response.GetNodes()[leafID]
		if !ok || len(response.GetNodes()) != 1 || node.GetId() != leafID || node.GetStatus() != "AVAILABLE" || node.GetSigningKeyshare() == nil || !bytes.Equal(node.GetOwnerIdentityPublicKey(), c.config.Owner) {
			return backing{}, nil, errors.New("native leaf unavailable to this identity")
		}
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(node)
		if err != nil {
			return backing{}, nil, err
		}
		digest := sha256.Sum256(raw)
		observations[id] = digest[:]
		if leaf != nil {
			if node.GetValue() != leaf.GetValue() || !bytes.Equal(node.GetOwnerSigningPublicKey(), leaf.GetOwnerSigningPublicKey()) || !bytes.Equal(node.GetVerifyingPublicKey(), leaf.GetVerifyingPublicKey()) || !bytes.Equal(node.GetNodeTx(), leaf.GetNodeTx()) || !bytes.Equal(node.GetDirectTx(), leaf.GetDirectTx()) || !bytes.Equal(node.GetRefundTx(), leaf.GetRefundTx()) || !bytes.Equal(node.GetDirectRefundTx(), leaf.GetDirectRefundTx()) || !bytes.Equal(node.GetDirectFromCpfpRefundTx(), leaf.GetDirectFromCpfpRefundTx()) || !bytes.Equal(node.GetSigningKeyshare().GetPublicKey(), leaf.GetSigningKeyshare().GetPublicKey()) {
				return backing{}, nil, errors.New("native leaf state differs between operators")
			}
		} else {
			leaf = node
		}
	}

	return backing{LeafID: leafID, Amount: leaf.GetValue(), Owner: leaf.GetOwnerIdentityPublicKey(), User: leaf.GetOwnerSigningPublicKey(), Operator: leaf.GetSigningKeyshare().GetPublicKey(), Combined: leaf.GetVerifyingPublicKey(), Node: leaf.GetNodeTx(), Direct: leaf.GetDirectTx(), Recoveries: [3]blob{leaf.GetRefundTx(), leaf.GetDirectRefundTx(), leaf.GetDirectFromCpfpRefundTx()}, Observations: observations}, leaf, nil
}
