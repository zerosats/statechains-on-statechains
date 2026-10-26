// Independent-share claims use the versioned operator overlay. This bridge
// accepts only public transcripts and already verified USER contributions.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pc "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"google.golang.org/protobuf/proto"
)

type claimRefund struct {
	Raw       blob                  `json:"raw_tx"`
	Operators map[string]commitment `json:"operators"`
	User      commitment            `json:"user"`
	Partial   blob                  `json:"partial"`
}
type claimWire struct {
	TransferID string          `json:"transfer_id"`
	LeafID     string          `json:"leaf_id"`
	Receiver   blob            `json:"receiver_identity"`
	UserKey    blob            `json:"user_key"`
	Packages   map[string]blob `json:"key_tweak_package"`
	Refunds    []claimRefund   `json:"refunds"`
	Signature  blob            `json:"signature"`
}

func (p *claimWire) request(s settings) (*pb.ClaimTransferRequest, error) {
	transferID, err := uuid.Parse(p.TransferID)
	if err != nil || transferID == uuid.Nil || transferID.String() != p.TransferID {
		return nil, errors.New("invalid shared claim transfer")
	}
	leafID, err := uuid.Parse(p.LeafID)
	if err != nil || leafID == uuid.Nil || leafID.String() != p.LeafID {
		return nil, errors.New("invalid shared claim leaf")
	}
	if !bytes.Equal(p.Receiver, s.Owner) || len(p.Refunds) != 3 || len(p.Packages) != len(s.Operators) {
		return nil, errors.New("shared claim receiver or coverage mismatch")
	}
	identity, err := keys.ParsePublicKey(p.Receiver)
	if err != nil {
		return nil, err
	}
	if _, err := keys.ParsePublicKey(p.UserKey); err != nil {
		return nil, err
	}
	packages := make(map[string][]byte)
	var envelope []byte
	for id := range s.Operators {
		value := p.Packages[id]
		if !bytes.HasPrefix(value, []byte("ZARK-MPC-CLAIM-v1\x00")) || len(value) > 1024*1024 {
			return nil, errors.New("shared claim overlay envelope missing")
		}
		if envelope != nil && !bytes.Equal(envelope, value) {
			return nil, errors.New("shared claim operator transcript differs")
		}
		envelope = value
		packages[id] = value
	}
	// The identity signature binds the envelope, including its refund bodies.
	// Reject substitutions locally before asking the operators to validate it.
	var signedEnvelope struct {
		Transcript blob `json:"transcript"`
	}
	if err := json.Unmarshal(envelope[len("ZARK-MPC-CLAIM-v1\x00"):], &signedEnvelope); err != nil {
		return nil, err
	}
	var transcript struct {
		Claim struct {
			Transfer string `json:"transfer_id"`
			Leaf     string `json:"leaf_id"`
			Receiver blob   `json:"receiver_identity"`
			Refunds  struct {
				CPFP     blob `json:"cpfp"`
				Direct   blob `json:"direct"`
				FromCPFP blob `json:"direct_from_cpfp"`
			} `json:"refunds"`
		} `json:"claim"`
		Authority struct {
			Members []struct {
				Public string `json:"public_key"`
			} `json:"members"`
		} `json:"authority"`
	}
	if err := json.Unmarshal(signedEnvelope.Transcript, &transcript); err != nil {
		return nil, err
	}
	if transcript.Claim.Transfer != p.TransferID || transcript.Claim.Leaf != p.LeafID || !bytes.Equal(transcript.Claim.Receiver, p.Receiver) || len(transcript.Authority.Members) != 2 {
		return nil, errors.New("shared claim transcript context mismatch")
	}
	first, err := keys.ParsePublicKeyHex(transcript.Authority.Members[0].Public)
	if err != nil {
		return nil, err
	}
	second, err := keys.ParsePublicKeyHex(transcript.Authority.Members[1].Public)
	if err != nil || !bytes.Equal(first.Add(second).Serialize(), p.UserKey) {
		return nil, errors.New("shared claim USER key mismatch")
	}
	bodies := []blob{transcript.Claim.Refunds.CPFP, transcript.Claim.Refunds.Direct, transcript.Claim.Refunds.FromCPFP}
	signature, err := ecdsa.ParseDERSignature(p.Signature)
	if err != nil || !identity.Verify(signature, common.GetClaimPackageSigningPayload(transferID, packages)) {
		return nil, errors.New("shared claim identity signature mismatch")
	}
	jobs := make([]*pb.UserSignedTxSigningJob, 3)
	for i, refund := range p.Refunds {
		if !bytes.Equal(bodies[i], refund.Raw) {
			return nil, errors.New("shared claim refund transcript mismatch")
		}
		if len(refund.Raw) == 0 || len(refund.Raw) > 64*1024 || len(refund.Partial) != 32 || len(refund.Operators) == 0 {
			return nil, errors.New("shared claim refund shape")
		}
		operators := make(map[string]*pc.SigningCommitment)
		for id, nonce := range refund.Operators {
			if _, ok := s.Operators[id]; !ok {
				return nil, errors.New("unconfigured claim signer")
			}
			for _, point := range []blob{nonce.Hiding, nonce.Binding} {
				if _, err := keys.ParsePublicKey(point); err != nil {
					return nil, err
				}
			}
			operators[id] = nonce.proto()
		}
		for _, point := range []blob{refund.User.Hiding, refund.User.Binding} {
			if _, err := keys.ParsePublicKey(point); err != nil {
				return nil, err
			}
		}
		jobs[i] = &pb.UserSignedTxSigningJob{LeafId: p.LeafID, SigningPublicKey: p.UserKey,
			RawTx: refund.Raw, SigningCommitments: &pb.SigningCommitments{SigningCommitments: operators},
			SigningNonceCommitment: refund.User.proto(), UserSignature: refund.Partial}
	}
	return &pb.ClaimTransferRequest{TransferId: p.TransferID, OwnerIdentityPublicKey: p.Receiver,
		ClaimPackage: &pb.ClaimPackage{LeavesToClaim: jobs[:1], DirectLeavesToClaim: jobs[1:2],
			DirectFromCpfpLeavesToClaim: jobs[2:], KeyTweakPackage: packages, UserSignature: p.Signature,
			HashVariant: pb.HashVariant_HASH_VARIANT_V2}}, nil
}

func (c *client) claimShared(p *claimWire) (blob, error) {
	req, err := p.request(c.config)
	if err != nil {
		return nil, err
	}
	ctx, cancel, err := c.rpcContext(c.config.Coordinator)
	if err != nil {
		return nil, err
	}
	defer cancel()
	response, err := pb.NewSparkServiceClient(c.conns[c.config.Coordinator]).ClaimTransfer(ctx, req)
	if err != nil {
		return nil, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(response)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	// A successful reply is evidence to retain, not final ownership admission.
	// The caller must reconcile all operators and validate delivered recoveries.
	return blob(digest[:]), nil
}
