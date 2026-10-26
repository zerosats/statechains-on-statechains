// Explicit root2 adapter inside the existing MPC consensus Prepare transaction.
// No method here accepts a caller-supplied expected plan or operator cluster.
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	transferpkg "github.com/lightsparkdev/spark/so/transfer"
	"google.golang.org/protobuf/proto"
)

const zarkNativeDurableMagic = "ZARK-NATIVE-COMMITTED-v1\x00"

// rows were loaded FOR UPDATE after identity authorization by the patched
// verifyMpcAuthorization. They stay locked through VSS verification, transfer
// creation, marker persistence and the local FROST response in this transaction.
func zarkNativeExpectedPlan(ctx context.Context,config *so.Config,submission *transferpkg.MpcSubmission,rows map[uuid.UUID]*ent.TreeNode) ([]byte,error) {
	if len(submission.ZarkNativeRootPacket()) == 0 || len(submission.Leaves()) != 1 || len(submission.LeavesToSend()) != 1 || len(submission.DirectLeavesToSend()) != 0 || len(submission.DirectFromCPFPLeavesToSend()) != 1 {
		return nil,fmt.Errorf("native root job profile differs")
	}
	leaf := submission.Leaves()[0]
	row := rows[leaf.LeafID()]
	if row == nil || len(row.DirectTx) != 0 || len(row.DirectRefundTx) != 0 || row.Value != leaf.AmountSats() || !row.OwnerSigningPubkey.Equals(leaf.OwnerSigningPubKey()) || !row.OwnerIdentityPubkey.Equals(submission.SenderIdentityPublicKey()) {
		return nil,fmt.Errorf("native root authenticated row or owner differs")
	}
	cluster,_,err := zarkNativeCluster(config);if err != nil {return nil,err}
	keyshare,err := row.QuerySigningKeyshare().Only(ctx);if err != nil {return nil,err}
	if !row.OwnerSigningPubkey.Add(keyshare.PublicKey).Equals(row.VerifyingPubkey) {return nil,fmt.Errorf("native root keyshare sum differs")}
	root,err := common.TxFromRawTxBytes(row.RawTx);if err != nil {return nil,err}
	if err := zarkNativeRootLayout(root,row.VerifyingPubkey,row.Value);err != nil {return nil,err}
	old,err := common.TxFromRawTxBytes(row.RawRefundTx);if err != nil {return nil,err}
	oldDirect,err := common.TxFromRawTxBytes(row.DirectFromCpfpRefundTx);if err != nil {return nil,err}
	if len(old.TxIn) != 1 {return nil,fmt.Errorf("native old refund input coverage differs")}
	delay := old.TxIn[0].Sequence & 0xffff
	if delay != 2000 {return nil,fmt.Errorf("native root profile requires the admitted initial refund window")}
	if err := zarkNativeRefundLayout(old,root,row.OwnerSigningPubkey,row.Value,(1<<30)|delay,true);err != nil {return nil,err}
	directAmount := row.Value;if directAmount > 955 {directAmount -= 955}
	if err := zarkNativeRefundLayout(oldDirect,root,row.OwnerSigningPubkey,directAmount,(1<<30)|(delay+50),false);err != nil {return nil,err}
	jobs := []*transferpkg.MpcRefundSigningJob{submission.LeavesToSend()[0],submission.DirectFromCPFPLeavesToSend()[0]}
	for i,job := range jobs {
		if !job.SigningPublicKey().Equals(row.OwnerSigningPubkey) {return nil,fmt.Errorf("native refund USER authority differs")}
		amount := row.Value;if i == 1 {amount = directAmount}
		if err := zarkNativeRefundLayout(job.RefundTx(),root,leaf.ReceiverIdentityPubKey(),amount,(1<<30)|(delay-100+uint32(i)*50),i==0);err != nil {return nil,err}
		if job.RefundTx().HasWitness() {return nil,fmt.Errorf("native refund job must be unsigned")}
	}
	if submission.AuthSignatureScheme() != pbcommon.SignatureScheme_SIGNATURE_SCHEME_ECDSA || leaf.SignatureScheme() != pbcommon.SignatureScheme_SIGNATURE_SCHEME_ECDSA {return nil,fmt.Errorf("native profile requires ordinary Spark ECDSA transport identity")}
	leafMessage := sha256.New();leafMessage.Write([]byte(leaf.LeafID().String()));leafMessage.Write([]byte(submission.TransferID().String()));leafMessage.Write(leaf.SecretCipher())
	if err := common.VerifySignatureWithScheme(submission.SenderIdentityPublicKey(),leaf.SignatureScheme(),leaf.Signature(),leafMessage.Sum(nil));err != nil {return nil,fmt.Errorf("native per-leaf transport signature differs: %w",err)}
	plan := binary.LittleEndian.AppendUint32(nil,1);plan = binary.LittleEndian.AppendUint32(plan,1)
	id := submission.TransferID();plan = append(plan,id[:]...);id = leaf.LeafID();plan = append(plan,id[:]...)
	plan = binary.LittleEndian.AppendUint64(plan,uint64(submission.ExpiryTime().Unix()))
	rootID := root.TxHash();plan = append(plan,rootID[:]...)
	plan = binary.LittleEndian.AppendUint64(plan,row.Value);plan = binary.LittleEndian.AppendUint32(plan,delay)
	plan = append(plan,row.OwnerSigningPubkey.Serialize()...);plan = append(plan,keyshare.PublicKey.Serialize()...)
	plan = append(plan,leaf.MaskCommitment().Serialize()...);plan = append(plan,leaf.ReceiverIdentityPubKey().Serialize()...)
	cipherHash := sha256.Sum256(leaf.SecretCipher());plan = append(plan,cipherHash[:]...);plan = append(plan,cluster[:]...)
	for _,job := range jobs {id := job.RefundTx().TxHash();plan = append(plan,id[:]...)}
	if len(plan) != 352 {return nil,fmt.Errorf("native independently reconstructed plan length")}
	return plan,nil
}

func zarkNativeRootLayout(tx *wire.MsgTx,combined keys.Public,amount uint64) error {
	script,err := common.P2TRScriptFromPubKey(combined);if err != nil {return err}
	if tx.Version != 3 || tx.LockTime != 0 || len(tx.TxIn) != 1 || tx.TxIn[0].Sequence != 1<<30 || len(tx.TxIn[0].SignatureScript) != 0 || len(tx.TxOut) != 2 || tx.TxOut[0].Value != int64(amount) || !bytes.Equal(tx.TxOut[0].PkScript,script) || tx.TxOut[1].Value != 0 || !bytes.Equal(tx.TxOut[1].PkScript,[]byte{81,2,78,115}) {
		return fmt.Errorf("native initial-root transaction layout differs")
	}
	return nil
}
func zarkNativeRefundLayout(tx,parent *wire.MsgTx,receiver keys.Public,amount uint64,sequence uint32,anchor bool) error {
	script,err := common.P2TRScriptFromPubKey(receiver);if err != nil {return err}
	count := 1;if anchor {count = 2}
	if tx.Version != 3 || tx.LockTime != 0 || len(tx.TxIn) != 1 || tx.TxIn[0].PreviousOutPoint.Hash != parent.TxHash() || tx.TxIn[0].PreviousOutPoint.Index != 0 || tx.TxIn[0].Sequence != sequence || len(tx.TxIn[0].SignatureScript) != 0 || len(tx.TxOut) != count || tx.TxOut[0].Value != int64(amount) || !bytes.Equal(tx.TxOut[0].PkScript,script) {return fmt.Errorf("native refund exact transaction layout differs")}
	if anchor && (tx.TxOut[1].Value != 0 || !bytes.Equal(tx.TxOut[1].PkScript,[]byte{81,2,78,115})) {return fmt.Errorf("native CPFP anchor differs")}
	return nil
}

func (h *MpcSendTransferFlowHandler) combineZarkNativeRoot(ctx context.Context,submission *transferpkg.MpcSubmission,rows map[uuid.UUID]*ent.TreeNode) (map[string]validatedKeyTweak,error) {
	plan,err := zarkNativeExpectedPlan(ctx,h.config,submission,rows);if err != nil {return nil,err}
	leaf := submission.Leaves()[0]
	combined,err := decryptZarkNativeV1(h.config,submission.ZarkNativeRootPacket(),plan,leaf.OwnerSigningPubKey());if err != nil {return nil,err}
	defer clear(combined.secret)
	// The two legacy vector slots carry the SAME combined polynomial. With
	// weights 2,-1 that remains P, without disclosing either original vector.
	for _,vector := range leaf.SubUserCommitments() {
		proofs := vector.Proofs();if len(proofs) != len(combined.proofs) {return nil,fmt.Errorf("native combined vector size differs")}
		for i,proof := range proofs {if !bytes.Equal(proof.Serialize(),combined.proofs[i]) {return nil,fmt.Errorf("native combined public vector differs")}}
	}
	tweak := &pb.SendLeafKeyTweak{LeafId:leaf.LeafID().String(),SecretShareTweak:&pb.SecretShare{SecretShare:combined.secret,Proofs:combined.proofs},PubkeySharesTweak:combined.publicShares,SecretCipher:leaf.SecretCipher(),Sig:&pb.SendLeafKeyTweak_Signature{Signature:leaf.Signature()}}
	tweak.ProtoReflect().SetUnknown(combined.marker)
	return h.validateKeyTweakShares(map[string]*pb.SendLeafKeyTweak{leaf.LeafID().String():tweak})
}

func pinZarkNativeTransfer(ctx context.Context,config *so.Config,submission *transferpkg.MpcSubmission,rows map[uuid.UUID]*ent.TreeNode,transfer *ent.Transfer) error {
	if len(submission.ZarkNativeRootPacket()) == 0 {return nil}
	plan,err := zarkNativeExpectedPlan(ctx,config,submission,rows);if err != nil {return err}
	packet,err := decodeZarkNativeV1(config,submission.ZarkNativeRootPacket(),plan,submission.Leaves()[0].OwnerSigningPubKey());if err != nil {return err}
	marker := []byte(zarkNativeDurableMagic);marker = append(marker,packet.commitment[:]...);marker = append(marker,packet.cluster[:]...)
	digest := sha256.Sum256(submission.ZarkNativeRootPacket());marker = append(marker,digest[:]...)
	leaves,err := transfer.QueryTransferLeaves().ForUpdate().All(ctx);if err != nil {return err}
	if len(leaves) != 1 {return fmt.Errorf("native durable marker leaf coverage differs")}
	if len(leaves[0].SenderKeyTweakProof) > 0 && !bytes.Equal(leaves[0].SenderKeyTweakProof,marker) {return fmt.Errorf("native exact packet retry differs")}
	_,err = leaves[0].Update().SetSenderKeyTweakProof(marker).Save(ctx)
	return err
}

// Keep proto import checked at source integration: unknown-field marker is
// retained by the standard validated tweak carrier, not interpreted as scalar.
var _ proto.Message = (*pb.SendLeafKeyTweak)(nil)
