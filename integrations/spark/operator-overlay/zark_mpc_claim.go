// Installed only by the explicit, source-pinned Zark claim-v1 overlay.
package handler

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/keys"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"google.golang.org/protobuf/proto"
)

func decryptClaimEnvelope(config *so.Config, raw []byte) (*pb.ClaimLeafKeyTweaks, error) {
	if bytes.HasPrefix(raw, []byte(zarkClaimMagic)) {
		return decryptZarkClaim(config, raw)
	}
	plaintext, err := eciesgo.Decrypt(eciesgo.NewPrivateKeyFromBytes(config.IdentityPrivateKey.Serialize()), raw)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt claim key tweaks: %w", err)
	}
	defer clear(plaintext)
	result := &pb.ClaimLeafKeyTweaks{}
	if err := proto.Unmarshal(plaintext, result); err != nil {
		return nil, fmt.Errorf("unable to decode claim key tweaks: %w", err)
	}
	return result, nil
}

// A single exact envelope at every operator prevents a receiver from choosing
// different contexts with the same aggregate tweak. Spark's identity signature
// authenticates this entire map before the consensus Prepare mutation boundary.
func zarkClaimPackage(config *so.Config, packages map[string][]byte) ([]byte, error) {
	var selected []byte
	for _, raw := range packages {
		if bytes.HasPrefix(raw, []byte(zarkClaimMagic)) {
			selected = raw
			break
		}
	}
	if selected == nil {
		return nil, nil
	}
	if len(packages) != len(config.SigningOperatorMap) {
		return nil, fmt.Errorf("Zark claim operator package set changed")
	}
	for id := range config.SigningOperatorMap {
		if !bytes.Equal(packages[id], selected) {
			return nil, fmt.Errorf("Zark claim envelope differs across operators")
		}
	}
	return selected, nil
}

// Kept inside the existing row-lock/transaction lifetime. The saved marker is
// checked even when Spark adopts a stored tweak or resumes an applied claim.
// A legacy retry cannot bypass a previously pinned MPC transcript.
func validateZarkClaimContext(config *so.Config, transferID uuid.UUID, owner keys.Public, packages map[string][]byte, leaves []*ent.TransferLeaf, applied bool) (*zarkDecodedClaim, error) {
	raw, err := zarkClaimPackage(config, packages)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		for _, leaf := range leaves {
			if len(leaf.KeyTweak) == 0 {
				continue
			}
			tweak := &pb.ClaimLeafKeyTweak{}
			if err := proto.Unmarshal(leaf.KeyTweak, tweak); err != nil {
				return nil, err
			}
			if len(tweak.ProtoReflect().GetUnknown()) > 0 {
				return nil, fmt.Errorf("stored Zark claim requires exact versioned retry")
			}
		}
		return nil, nil
	}
	decoded, err := decodeZarkClaim(config, raw)
	if err != nil {
		return nil, err
	}
	claim := &decoded.transcript.Claim
	if claim.TransferID != transferID.String() || !bytes.Equal(claim.Receiver, owner.Serialize()) || len(leaves) != 1 {
		return nil, fmt.Errorf("Zark claim transfer or receiver mismatch")
	}
	transferLeaf := leaves[0]
	leaf := transferLeaf.Edges.Leaf
	if leaf == nil || leaf.Edges.SigningKeyshare == nil {
		return nil, fmt.Errorf("Zark claim authenticated leaf missing")
	}
	if leaf.ID.String() != claim.LeafID || leaf.Value != claim.Amount || sha256.Sum256(leaf.RawTx) != claim.BackingTx || sha256.Sum256(leaf.DirectTx) != claim.DirectBackingTx || !bytes.Equal(leaf.VerifyingPubkey.Serialize(), claim.Backing) {
		return nil, fmt.Errorf("Zark claim authenticated backing changed")
	}
	expectedOwner, err := zarkPoint(claim.Incoming)
	if err != nil {
		return nil, err
	}
	expectedOperator, err := zarkPoint(claim.Operator)
	if err != nil {
		return nil, err
	}
	if applied {
		expectedOwner = decoded.public
		tweak, _ := zarkPoint(decoded.proofs[0])
		expectedOperator = expectedOperator.Add(tweak)
	}
	if !leaf.OwnerSigningPubkey.Equals(expectedOwner) || !leaf.Edges.SigningKeyshare.PublicKey.Equals(expectedOperator) {
		return nil, fmt.Errorf("Zark claim pre/post key state changed")
	}
	if len(transferLeaf.KeyTweak) > 0 {
		stored := &pb.ClaimLeafKeyTweak{}
		if err := proto.Unmarshal(transferLeaf.KeyTweak, stored); err != nil {
			return nil, err
		}
		if stored.LeafId != claim.LeafID || !bytes.Equal(stored.ProtoReflect().GetUnknown(), decoded.marker) {
			return nil, fmt.Errorf("Zark claim retry changed its persisted transcript")
		}
	} else if applied {
		return nil, fmt.Errorf("applied Zark claim lost durable transcript marker")
	}
	return decoded, nil
}

func validateZarkClaimPrepare(config *so.Config, transferID uuid.UUID, owner keys.Public, pkg *pb.ClaimPackage, leaves []*ent.TransferLeaf, applied bool) error {
	decoded, err := validateZarkClaimContext(config, transferID, owner, pkg.GetKeyTweakPackage(), leaves, applied)
	if err != nil || decoded == nil {
		return err
	}
	expected := [][]byte{decoded.transcript.Claim.Refunds.CPFP, decoded.transcript.Claim.Refunds.Direct, decoded.transcript.Claim.Refunds.DirectFromCPFP}
	jobs := [][]*pb.UserSignedTxSigningJob{pkg.GetLeavesToClaim(), pkg.GetDirectLeavesToClaim(), pkg.GetDirectFromCpfpLeavesToClaim()}
	for i, variants := range jobs {
		if len(variants) != 1 {
			return fmt.Errorf("Zark claim requires exactly one job for each refund variant")
		}
		job := variants[0]
		if job.GetLeafId() != decoded.transcript.Claim.LeafID || !bytes.Equal(job.GetRawTx(), expected[i]) || !bytes.Equal(job.GetSigningPublicKey(), decoded.public.Serialize()) || len(job.GetAdditionalInputs()) != 0 || len(job.GetSubuserContributions()) != 0 {
			return fmt.Errorf("Zark claim refund body or USER authority changed")
		}
	}
	return nil
}

// Preserve only the immutable transcript digest after applying a tweak. The
// operator scalar is erased from this row; the marker survives lost responses
// and applied-claim retries. Ordinary claims retain their original clear path.
func zarkClaimAppliedMarker(tweak *pb.ClaimLeafKeyTweak) ([]byte, error) {
	unknown := tweak.ProtoReflect().GetUnknown()
	if len(unknown) == 0 {
		return nil, nil
	}
	// A v1 marker is one length-delimited field, three-byte tag plus 32 bytes.
	expectedPrefix := []byte{0x8a, 0xb5, 0x18, 0x20}
	if len(unknown) != 36 || !bytes.Equal(unknown[:4], expectedPrefix) {
		return nil, fmt.Errorf("invalid stored Zark claim marker")
	}
	marker := &pb.ClaimLeafKeyTweak{LeafId: tweak.LeafId}
	marker.ProtoReflect().SetUnknown(append([]byte{}, unknown...))
	return proto.Marshal(marker)
}

func zarkClaimRollbackTweak(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	tweak := &pb.ClaimLeafKeyTweak{}
	if err := proto.Unmarshal(raw, tweak); err != nil {
		return nil, err
	}
	marker, err := zarkClaimAppliedMarker(tweak)
	if err != nil {
		return nil, err
	}
	if marker == nil {
		return nil, nil
	}
	// This is a pre-apply rollback: preserve the complete staged tweak so a
	// retry can only use its exact signed envelope, while upstream restores
	// the old canonical refund transactions and pending receiver status.
	return raw, nil
}

func zarkClaimRejectLegacyOverwrite(raw []byte) error {
	retained, err := zarkClaimRollbackTweak(raw)
	if err != nil {
		return err
	}
	if retained != nil {
		return fmt.Errorf("MPC-bound claim cannot use legacy tweak overwrite")
	}
	return nil
}
