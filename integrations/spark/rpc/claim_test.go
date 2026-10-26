package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestClaimRustPacketMappingAndSubstitution(t *testing.T) {
	path := os.Getenv("ZARK_MPC_CLAIM_PACKET_VECTOR")
	if path == "" {
		t.Skip("requires isolated Rust claim-packet fixture")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p claimWire
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	s := settings{Owner: p.Receiver, Operators: make(map[string]endpoint)}
	for id := range p.Packages {
		s.Operators[id] = endpoint{}
	}
	r, err := p.request(s)
	if err != nil {
		t.Fatal(err)
	}
	jobs := [][]byte{r.ClaimPackage.LeavesToClaim[0].RawTx, r.ClaimPackage.DirectLeavesToClaim[0].RawTx, r.ClaimPackage.DirectFromCpfpLeavesToClaim[0].RawTx}
	for i, raw := range jobs {
		if !bytes.Equal(raw, p.Refunds[i].Raw) {
			t.Fatal("refund mapping changed")
		}
	}
	if !bytes.Equal(r.ClaimPackage.LeavesToClaim[0].UserSignature, p.Refunds[0].Partial) || len(r.ClaimPackage.LeavesToClaim[0].SubuserContributions) != 0 {
		t.Fatal("claim must use collapsed legacy USER share")
	}
	for mutation := 0; mutation < 4; mutation++ {
		var altered claimWire
		if err := json.Unmarshal(raw, &altered); err != nil {
			t.Fatal(err)
		}
		switch mutation {
		case 0:
			altered.Signature[10] ^= 1
		case 1:
			altered.Refunds[1].Raw[0] ^= 1
		case 2:
			for id := range altered.Packages {
				altered.Packages[id][len(altered.Packages[id])-1] ^= 1
				break
			}
		case 3:
			altered.TransferID = "33333333-3333-4333-8333-333333333333"
		}
		if _, err := altered.request(s); err == nil {
			t.Fatalf("accepted mutation %d", mutation)
		}
	}
}
