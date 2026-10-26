// Built against the pinned Spark Go module; no independent dependency graph.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pc "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	transfer "github.com/lightsparkdev/spark/so/transfer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Rust's private-pipe protocol uses JSON byte arrays, not base64 strings.
type blob []byte

func (b *blob) UnmarshalJSON(raw []byte) error {
	if len(raw) == 0 || raw[0] != '[' {
		return errors.New("expected byte array")
	}
	var value []uint8
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*b = value
	return nil
}
func (b blob) MarshalJSON() ([]byte, error) {
	value := make([]uint16, len(b))
	for i, v := range b {
		value[i] = uint16(v)
	}
	return json.Marshal(value)
}

type commitment struct {
	Hiding  blob `json:"hiding"`
	Binding blob `json:"binding"`
}

func (c commitment) proto() *pc.SigningCommitment {
	return &pc.SigningCommitment{Hiding: c.Hiding, Binding: c.Binding}
}

type contextWire struct {
	Scope      json.RawMessage `json:"scope"`
	TransferID string          `json:"transfer_id"`
	LeafID     string          `json:"leaf_id"`
	Amount     uint64          `json:"amount_sats"`
	Receiver   blob            `json:"receiver_identity"`
	Expiry     uint64          `json:"expiry_unix_seconds"`
	Refunds    struct {
		CPFP     blob `json:"cpfp"`
		Direct   blob `json:"direct"`
		FromCPFP blob `json:"direct_from_cpfp"`
	} `json:"refunds"`
}
type contributionWire struct {
	Position uint16          `json:"position"`
	Binding  blob            `json:"binding"`
	Proofs   []blob          `json:"proofs"`
	Shares   map[string]blob `json:"sealed_shares"`
}
type refundWire struct {
	Raw       blob                  `json:"raw_tx"`
	Parent    blob                  `json:"prev_tx"`
	Sighash   blob                  `json:"sighash"`
	Operators map[string]commitment `json:"operators"`
	Users     []commitment          `json:"users"`
	Partials  []blob                `json:"partials"`
}
type packetWire struct {
	Backing *backing    `json:"backing,omitempty"`
	Context contextWire `json:"context"`
	Keys    struct {
		User     json.RawMessage `json:"user"`
		Operator blob            `json:"operator"`
		Combined blob            `json:"combined"`
	} `json:"keys"`
	Mask struct {
		Commitment blob `json:"commitment"`
		Cipher     blob `json:"secret_cipher"`
	} `json:"mask"`
	Contributions          []contributionWire `json:"contributions"`
	Refunds                []refundWire       `json:"refunds"`
	Sender                 blob               `json:"sender_identity"`
	LeafSignature          blob               `json:"leaf_signature"`
	AuthorizationSignature blob               `json:"authorization_signature"`
	RefundDigest           blob               `json:"refund_sighashes_digest"`
	// "schnorr": a 64-byte BIP-340 group signature (Zark blind exit);
	// absent: the strict-DER ECDSA identity signature.
	AuthorizationScheme string `json:"authorization_scheme,omitempty"`
}

func (p *packetWire) request() (*pb.StartTransferMpcRequest, error) {
	req, err := p.build()
	if err != nil {
		return nil, err
	}
	return req, p.verify(req)
}

func (p *packetWire) build() (*pb.StartTransferMpcRequest, error) {
	if len(p.Contributions) != 2 || len(p.Refunds) != 3 {
		return nil, errors.New("native participant/refund count")
	}
	schnorrAuth := p.AuthorizationScheme == "schnorr"
	if !schnorrAuth && p.AuthorizationScheme != "" {
		return nil, errors.New("native authorization scheme")
	}
	var authority struct {
		Members []struct {
			PublicKey string `json:"public_key"`
		} `json:"members"`
	}
	if err := json.Unmarshal(p.Keys.User, &authority); err != nil || len(authority.Members) != 2 {
		return nil, errors.New("native authority shape")
	}
	a, err := keys.ParsePublicKeyHex(authority.Members[0].PublicKey)
	if err != nil {
		return nil, errors.New("native wallet public key")
	}
	b, err := keys.ParsePublicKeyHex(authority.Members[1].PublicKey)
	if err != nil {
		return nil, errors.New("native signer public key")
	}
	owner := a.Add(b).Serialize()
	keyTweaks := make(map[string]*pb.MpcOperatorShares)
	vectors := make([]*pb.SubUserCommitment, 2)
	for j, c := range p.Contributions {
		if c.Position != uint16(j+1) {
			return nil, errors.New("native participant order")
		}
		proofs := make([][]byte, len(c.Proofs))
		for i, proof := range c.Proofs {
			proofs[i] = proof
		}
		vectors[j] = &pb.SubUserCommitment{Proofs: proofs}
		for id, share := range c.Shares {
			if keyTweaks[id] == nil {
				keyTweaks[id] = &pb.MpcOperatorShares{Shares: make([]*pb.MpcSealedShare, 2)}
			}
			keyTweaks[id].Shares[j] = &pb.MpcSealedShare{Ecies: share}
		}
	}
	jobs := make([]*pb.UserSignedTxSigningJob, 3)
	for i, r := range p.Refunds {
		if len(r.Users) != 2 || len(r.Partials) != 2 {
			return nil, errors.New("native refund participant count")
		}
		operators := make(map[string]*pc.SigningCommitment)
		for id, c := range r.Operators {
			operators[id] = c.proto()
		}
		jobs[i] = &pb.UserSignedTxSigningJob{LeafId: p.Context.LeafID, SigningPublicKey: owner, RawTx: r.Raw,
			SigningCommitments: &pb.SigningCommitments{SigningCommitments: operators},
			SubuserContributions: []*pb.SubUserSigningContribution{
				{NonceCommitment: r.Users[0].proto(), PartialSignature: r.Partials[0]},
				{NonceCommitment: r.Users[1].proto(), PartialSignature: r.Partials[1]},
			}}
	}
	ecdsaSignature := func(raw []byte) *pc.Signature {
		return &pc.Signature{Scheme: pc.SignatureScheme_SIGNATURE_SCHEME_ECDSA, Signature: raw}
	}
	authScheme := pc.SignatureScheme_SIGNATURE_SCHEME_ECDSA
	if schnorrAuth {
		authScheme = pc.SignatureScheme_SIGNATURE_SCHEME_SCHNORR
	}
	req := &pb.StartTransferMpcRequest{TransferId: p.Context.TransferID, OwnerIdentityPublicKey: p.Sender,
		MpcTransferPackage: &pb.MpcTransferPackage{Positions: []uint32{1, 2}, KeyTweaks: keyTweaks,
			Leaves:       []*pb.MpcSendLeaf{{LeafId: p.Context.LeafID, SubuserCommitments: vectors, SecretCipher: p.Mask.Cipher, Signature: ecdsaSignature(p.LeafSignature)}},
			LeavesToSend: jobs[:1], DirectLeavesToSend: jobs[1:2], DirectFromCpfpLeavesToSend: jobs[2:],
			Authorization: &pb.TransferAuthorization{TransferId: p.Context.TransferID, RefundSighashesDigest: p.RefundDigest,
				ExpiryTime: timestamppb.New(time.Unix(int64(p.Context.Expiry), 0)), Signature: &pc.Signature{Scheme: authScheme, Signature: p.AuthorizationSignature},
				Leaves: []*pb.LeafAuthorization{{LeafId: p.Context.LeafID, AmountSats: p.Context.Amount, OwnerSigningPublicKey: owner, MaskCommitment: p.Mask.Commitment, ReceiverIdentityPublicKey: p.Context.Receiver}}}}}
	return req, nil
}

func (p *packetWire) verify(req *pb.StartTransferMpcRequest) error {
	schnorrAuth := p.AuthorizationScheme == "schnorr"
	authScheme := req.GetMpcTransferPackage().GetAuthorization().GetSignature().GetScheme()
	// Validate our mapping through Spark's actual parser and signature check,
	// rather than relying only on a second implementation of its wire types.
	parsed, err := transfer.ParseMpcSubmission(req)
	if err != nil {
		return errors.New("native Spark parser rejected packet")
	}
	identity, err := keys.ParsePublicKey(p.Sender)
	if err != nil {
		return errors.New("native sender key")
	}
	if schnorrAuth {
		if common.VerifySignatureWithScheme(identity, authScheme, p.AuthorizationSignature, parsed.AuthorizationPayload()) != nil {
			return errors.New("native authorization signature mismatch")
		}
	} else if sig, err := ecdsa.ParseDERSignature(p.AuthorizationSignature); err != nil || !identity.Verify(sig, parsed.AuthorizationPayload()) {
		return errors.New("native authorization signature mismatch")
	}
	leafPayload := append(append([]byte(p.Context.LeafID), []byte(p.Context.TransferID)...), p.Mask.Cipher...)
	digest := sha256.Sum256(leafPayload)
	leafSig, err := ecdsa.ParseDERSignature(p.LeafSignature)
	if err != nil || !identity.Verify(leafSig, digest[:]) {
		return errors.New("native receiver identity signature mismatch")
	}
	if !bytes.Equal(p.Context.Refunds.CPFP, p.Refunds[0].Sighash) || !bytes.Equal(p.Context.Refunds.Direct, p.Refunds[1].Sighash) || !bytes.Equal(p.Context.Refunds.FromCPFP, p.Refunds[2].Sighash) {
		return errors.New("native refund variant order")
	}
	return nil
}
