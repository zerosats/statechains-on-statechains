// Standalone compatibility driver using the unchanged pinned Spark libraries.
// Input contains SYNTHETIC operator keys for decryption; never use live keys.
// Run inside the pinned Spark Go module, passing this file and the fixture.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecies "github.com/ecies/go/v2"
	"github.com/lightsparkdev/spark/common/keys"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"google.golang.org/protobuf/proto"
)

type operatorVector struct {
	Index      uint64 `json:"index"`
	Secret     string `json:"synthetic_operator_secret"`
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
}
type caseVector struct {
	Threshold int                       `json:"threshold"`
	Leaf      string                    `json:"leaf_id"`
	Incoming  string                    `json:"incoming_user_key"`
	Joint     string                    `json:"joint_user_key"`
	Operators map[string]operatorVector `json:"operators"`
}
type fixture struct {
	Schema    string       `json:"schema"`
	Synthetic bool         `json:"synthetic"`
	Live      bool         `json:"live_ingress"`
	Cases     []caseVector `json:"cases"`
}

func decode(text string) ([]byte, error) { return hex.DecodeString(text) }

func validate(value caseVector, id string, plaintext []byte) error {
	var bundle pb.ClaimLeafKeyTweaks
	if err := proto.Unmarshal(plaintext, &bundle); err != nil { return err }
	if len(bundle.GetLeavesToReceive()) != 1 { return errors.New("wrong leaf count") }
	leaf := bundle.GetLeavesToReceive()[0]
	share := leaf.GetSecretShareTweak()
	if leaf.GetLeafId() != value.Leaf || share == nil || len(share.GetSecretShare()) != 32 || len(share.GetProofs()) != value.Threshold {
		return errors.New("wrong native claim shape")
	}
	index := value.Operators[id].Index
	if err := secretsharing.ValidateShare(&secretsharing.VerifiableSecretShare{
		SecretShare: secretsharing.SecretShare{FieldModulus: secp256k1.S256().N, Threshold: value.Threshold,
			Index: new(big.Int).SetUint64(index), Share: new(big.Int).SetBytes(share.GetSecretShare())},
		Proofs: share.GetProofs(),
	}); err != nil { return err }
	incoming, err := keys.ParsePublicKeyHex(value.Incoming)
	if err != nil { return err }
	joint, err := keys.ParsePublicKeyHex(value.Joint)
	if err != nil { return err }
	constant, err := keys.ParsePublicKey(share.GetProofs()[0])
	if err != nil { return err }
	if !incoming.Sub(joint).Equals(constant) { return errors.New("wrong USER rotation") }
	if len(leaf.GetPubkeySharesTweak()) != len(value.Operators) { return errors.New("incomplete public-share map") }
	for operatorID, recipient := range value.Operators {
		expected, err := secretsharing.EvaluatePolynomialCommitment(share.GetProofs(), new(big.Int).SetUint64(recipient.Index), secp256k1.S256().N)
		if err != nil { return err }
		actual, err := keys.ParsePublicKey(leaf.GetPubkeySharesTweak()[operatorID])
		if err != nil { return err }
		if !expected.Equals(actual) { return errors.New("wrong polynomial index/public-share map") }
	}
	return nil
}

func run(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil { return err }
	var input fixture
	if err := json.Unmarshal(raw, &input); err != nil { return err }
	if input.Schema != "zark-spark/standard-claim-fixture/v1" || !input.Synthetic || input.Live || len(input.Cases) != 2 {
		return errors.New("expected isolated synthetic package fixture")
	}
	count := 0
	for _, value := range input.Cases {
		for id, operator := range value.Operators {
			secret, err := decode(operator.Secret)
			if err != nil { return err }
			ciphertext, err := decode(operator.Ciphertext)
			if err != nil { return err }
			expected, err := decode(operator.Plaintext)
			if err != nil { return err }
			private := ecies.NewPrivateKeyFromBytes(secret)
			plaintext, err := ecies.Decrypt(private, ciphertext)
			if err != nil { return err }
			if !bytes.Equal(expected, plaintext) { return errors.New("native ECIES plaintext differs") }
			if err := validate(value, id, plaintext); err != nil { return err }
			// Exercise native rejection, separately from Rust's local checks.
			ciphertext[len(ciphertext)-1] ^= 1
			if _, err := ecies.Decrypt(private, ciphertext); err == nil { return errors.New("mutated ciphertext accepted") }
			var bundle pb.ClaimLeafKeyTweaks
			if err := proto.Unmarshal(plaintext, &bundle); err != nil { return err }
			bundle.LeavesToReceive[0].SecretShareTweak.SecretShare[31] ^= 1
			changed, err := proto.Marshal(&bundle)
			if err != nil { return err }
			if err := validate(value, id, changed); err == nil { return errors.New("mutated share accepted") }
			if err := proto.Unmarshal(plaintext, &bundle); err != nil { return err }
			bundle.LeavesToReceive[0].PubkeySharesTweak[id] = bundle.LeavesToReceive[0].SecretShareTweak.Proofs[0]
			changed, err = proto.Marshal(&bundle)
			if err != nil { return err }
			if err := validate(value, id, changed); err == nil { return errors.New("mutated public-share map accepted") }
			count++
		}
	}
	fmt.Printf("PASS: %d standard claim packages decrypted/decoded by unchanged Spark libraries; VSS and USER rotation verified; ciphertext/share/public-map mutations rejected. No live claim.\n", count)
	return nil
}

func main() {
	if len(os.Args) != 2 { fmt.Fprintln(os.Stderr, "expected synthetic fixture path"); os.Exit(1) }
	if err := run(os.Args[1]); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
