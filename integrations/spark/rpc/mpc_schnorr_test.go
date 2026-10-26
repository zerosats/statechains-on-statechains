package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/lightsparkdev/spark/common/keys"
	transfer "github.com/lightsparkdev/spark/so/transfer"
)

func schnorrFixture(t *testing.T) (*packetWire, keys.Private) {
	t.Helper()
	wallet, signer := keys.GeneratePrivateKey(), keys.GeneratePrivateKey()
	owner := wallet.Add(signer)
	point := func() blob { return blob(keys.GeneratePrivateKey().Public().Serialize()) }
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(1000, bytes.Repeat([]byte{0x51}, 1)))
	var raw bytes.Buffer
	if err := tx.Serialize(&raw); err != nil {
		t.Fatal(err)
	}
	p := &packetWire{AuthorizationScheme: "schnorr", Sender: owner.Public().Serialize(), RefundDigest: bytes.Repeat([]byte{9}, 32)}
	p.Context.TransferID = "01234567-89ab-4def-8123-456789abcdef"
	p.Context.LeafID = "11234567-89ab-4def-8123-456789abcdef"
	p.Context.Amount = 64000
	p.Context.Receiver = point()
	p.Context.Expiry = 1900000000
	user, _ := json.Marshal(map[string]any{"members": []map[string]string{{"public_key": wallet.Public().ToHex()}, {"public_key": signer.Public().ToHex()}}})
	p.Keys.User = user
	p.Mask.Commitment = point()
	p.Mask.Cipher = bytes.Repeat([]byte{7}, 129)
	for position := uint16(1); position <= 2; position++ {
		p.Contributions = append(p.Contributions, contributionWire{Position: position, Proofs: []blob{point(), point()},
			Shares: map[string]blob{"0000000000000000000000000000000000000000000000000000000000000001": bytes.Repeat([]byte{4}, 209)}})
	}
	sighashes := []*blob{&p.Context.Refunds.CPFP, &p.Context.Refunds.Direct, &p.Context.Refunds.FromCPFP}
	for i := 0; i < 3; i++ {
		*sighashes[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
		p.Refunds = append(p.Refunds, refundWire{Raw: raw.Bytes(), Sighash: *sighashes[i],
			Operators: map[string]commitment{"0000000000000000000000000000000000000000000000000000000000000001": {Hiding: point(), Binding: point()}},
			Users:     []commitment{{Hiding: point(), Binding: point()}, {Hiding: point(), Binding: point()}},
			Partials:  []blob{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}})
	}
	digest := sha256.Sum256(append(append([]byte(p.Context.LeafID), []byte(p.Context.TransferID)...), p.Mask.Cipher...))
	p.LeafSignature = ecdsa.Sign(owner.ToBTCEC(), digest[:]).Serialize()
	p.AuthorizationSignature = make([]byte, 64)
	return p, owner
}

func signParsedPayload(t *testing.T, p *packetWire, owner keys.Private) {
	t.Helper()
	req, err := p.build()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := transfer.ParseMpcSubmission(req)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(owner.ToBTCEC(), parsed.AuthorizationPayload())
	if err != nil {
		t.Fatal(err)
	}
	p.AuthorizationSignature = sig.Serialize()
}

// The blind group signature is BIP-340 over Spark's own parsed payload; the
// leaf receiver signature stays ECDSA, which ordinary receivers require.
func TestMpcSchnorrAuthorizationThroughSparkParserAndVerifier(t *testing.T) {
	p, owner := schnorrFixture(t)
	signParsedPayload(t, p, owner)
	req, err := p.request()
	if err != nil {
		t.Fatal(err)
	}
	if req.GetMpcTransferPackage().GetAuthorization().GetSignature().GetScheme().String() != "SIGNATURE_SCHEME_SCHNORR" ||
		req.GetMpcTransferPackage().GetLeaves()[0].GetSignature().GetScheme().String() != "SIGNATURE_SCHEME_ECDSA" {
		t.Fatal("authorization or leaf signature scheme mapping")
	}
	// A Schnorr signature labelled ECDSA, an unknown label, and any change to
	// a payload field after signing are all rejected before RPC.
	p.AuthorizationScheme = ""
	if _, err := p.request(); err == nil {
		t.Fatal("schnorr signature accepted as ECDSA")
	}
	p.AuthorizationScheme = "bip340"
	if _, err := p.request(); err == nil {
		t.Fatal("unknown authorization scheme accepted")
	}
	p.AuthorizationScheme = "schnorr"
	for _, edit := range []func(*packetWire){
		func(p *packetWire) { p.Context.Amount++ },
		func(p *packetWire) { p.Context.Expiry++ },
		func(p *packetWire) { p.Context.Receiver = blob(keys.GeneratePrivateKey().Public().Serialize()) },
		func(p *packetWire) { p.Context.LeafID = "21234567-89ab-4def-8123-456789abcdef" },
		func(p *packetWire) { p.RefundDigest = bytes.Repeat([]byte{8}, 32) },
		func(p *packetWire) { p.Contributions[1].Proofs[1] = blob(keys.GeneratePrivateKey().Public().Serialize()) },
	} {
		altered, _ := schnorrFixture(t)
		*altered = *p
		altered.Contributions = []contributionWire{p.Contributions[0], {Position: 2, Proofs: append([]blob{}, p.Contributions[1].Proofs...), Shares: p.Contributions[1].Shares}}
		edit(altered)
		if _, err := altered.request(); err == nil {
			t.Fatal("altered authorized field accepted")
		}
	}
}
