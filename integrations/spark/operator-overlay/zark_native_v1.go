// Source scaffold only: no handler calls this versioned decoder yet. A future
// consensus adapter must reconstruct expectedPlan from locked operator rows,
// authenticate the native sender/package, and pin the exact packet marker in
// the same transaction before applying the returned tweak. Never substitute a
// request-supplied expected plan or unlock a Zark coin after a submission timeout.
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	"github.com/lightsparkdev/spark/common/keys"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	"github.com/lightsparkdev/spark/so"
	"google.golang.org/protobuf/encoding/protowire"
)

const zarkNativeMagic = "ZARK-NATIVE-ROOT-v1\x00"
const zarkNativePayloadMagic = "ZARK-NATIVE-VSS-v1\x00"
const zarkNativeMarkerField protowire.Number = 50002
const zarkNativeMaxPacket = 64 * 1024
const zarkNativeCipherBytes = 97 + len(zarkNativePayloadMagic) + 130

// Only combined polynomial commitments are public. A threshold coalition that
// decrypts the individual server ciphertexts can still reconstruct that server
// polynomial; this primitive does not claim protection against that coalition.
type zarkNativePacket struct {
	plan       []byte
	commitment [32]byte
	cluster    [32]byte
	mask       keys.Public
	proofs     [][]byte
	sealed     map[string][2][]byte
}

type zarkNativeTweak struct {
	secret       []byte
	proofs       [][]byte
	publicShares map[string][]byte
	marker       []byte
}

func zarkNativePoint(raw []byte) (keys.Public, error) {
	key, err := keys.ParsePublicKey(raw)
	if err != nil || len(raw) != 33 || !bytes.Equal(key.Serialize(), raw) {
		return keys.Public{}, fmt.Errorf("invalid native aggregate point")
	}
	return key, nil
}

// Fixed deployment cluster bytes, never a map supplied by a native request.
func zarkNativeCluster(config *so.Config) ([32]byte, []string, error) {
	var zero [32]byte
	if config == nil || config.Threshold != 2 || len(config.SigningOperatorMap) < 2 || len(config.SigningOperatorMap) > 16 {
		return zero, nil, fmt.Errorf("native root profile requires a pinned threshold-two cluster")
	}
	ids := make([]string, 0, len(config.SigningOperatorMap))
	for id := range config.SigningOperatorMap { ids = append(ids, id) }
	sort.Strings(ids)
	encoded := []byte("ZARK/spark/native/cluster/v1")
	encoded = binary.LittleEndian.AppendUint16(encoded, 2)
	encoded = binary.LittleEndian.AppendUint16(encoded, uint16(len(ids)))
	seen := map[string]bool{}
	for _, id := range ids {
		op := config.SigningOperatorMap[id]
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != id || new(big.Int).SetBytes(raw).Sign() == 0 || op == nil || op.Identifier != id || new(big.Int).SetBytes(raw).Cmp(new(big.Int).SetUint64(op.ID+1)) != 0 {
			return zero, nil, fmt.Errorf("native operator identifier changed")
		}
		public := op.IdentityPublicKey.Serialize()
		if _, err := zarkNativePoint(public); err != nil || seen[string(public)] {
			return zero, nil, fmt.Errorf("native operator encryption identity changed")
		}
		seen[string(public)] = true
		encoded = append(encoded, raw...)
		encoded = append(encoded, public...)
	}
	return sha256.Sum256(encoded), ids, nil
}

func decodeZarkNativeV1(config *so.Config, raw, expectedPlan []byte, owner keys.Public) (*zarkNativePacket, error) {
	if len(raw) > zarkNativeMaxPacket || !bytes.HasPrefix(raw, []byte(zarkNativeMagic)) || len(expectedPlan) != 352 {
		return nil, fmt.Errorf("native packet size, version or trusted plan missing")
	}
	cluster, ids, err := zarkNativeCluster(config)
	if err != nil { return nil, err }
	cursor := len(zarkNativeMagic)
	take := func(n int) ([]byte, error) {
		if n < 0 || cursor > len(raw)-n { return nil, fmt.Errorf("truncated native packet") }
		value := raw[cursor:cursor+n]; cursor += n; return value, nil
	}
	plan, err := take(352)
	if err != nil || !bytes.Equal(plan, expectedPlan) || binary.LittleEndian.Uint32(plan[:4]) != 1 || binary.LittleEndian.Uint32(plan[4:8]) != 1 || !bytes.Equal(plan[92:125], owner.Serialize()) || !bytes.Equal(plan[256:288], cluster[:]) {
		return nil, fmt.Errorf("native packet differs from independently authenticated initial-root plan")
	}
	salt, err := take(32)
	if err != nil || bytes.Equal(salt, make([]byte,32)) { return nil, fmt.Errorf("native plan salt missing") }
	h := sha256.New(); h.Write([]byte("ZARK/spark/native/plan/v1")); h.Write(plan); h.Write(salt)
	out := &zarkNativePacket{plan: plan, cluster: cluster, sealed: map[string][2][]byte{}}
	copy(out.commitment[:], h.Sum(nil))
	length, err := take(2)
	if err != nil || binary.LittleEndian.Uint16(length) != 129 { return nil, fmt.Errorf("native mask ciphertext size differs") }
	maskCipher, err := take(129)
	if err != nil || maskCipher[0] != 4 { return nil, fmt.Errorf("invalid native mask ciphertext") }
	if _, err := keys.ParsePublicKey(maskCipher[:65]); err != nil { return nil, fmt.Errorf("invalid native mask ephemeral") }
	cipherHash := sha256.Sum256(maskCipher)
	if !bytes.Equal(plan[224:256],cipherHash[:]) { return nil, fmt.Errorf("native mask ciphertext differs from plan") }
	out.mask, err = zarkNativePoint(plan[158:191])
	if err != nil { return nil, err }
	for i := 0; i < 2; i++ {
		proof, err := take(33)
		if err != nil { return nil, err }
		if _, err := zarkNativePoint(proof); err != nil { return nil, err }
		out.proofs = append(out.proofs, proof)
	}
	expected := owner.Sub(out.mask)
	if !bytes.Equal(expected.Serialize(), out.proofs[0]) { return nil, fmt.Errorf("native combined polynomial constant differs") }
	count, err := take(2)
	if err != nil || binary.LittleEndian.Uint16(count) != uint16(len(ids)) { return nil, fmt.Errorf("native encrypted operator coverage differs") }
	for _, id := range ids {
		rawID, err := take(32)
		if err != nil || hex.EncodeToString(rawID) != id { return nil, fmt.Errorf("native encrypted operator order differs") }
		var pair [2][]byte
		for i := range pair {
			length, err := take(2)
			if err != nil || binary.LittleEndian.Uint16(length) != uint16(zarkNativeCipherBytes) { return nil, fmt.Errorf("native ciphertext size differs") }
			pair[i], err = take(zarkNativeCipherBytes)
			if err != nil || pair[i][0] != 4 { return nil, fmt.Errorf("invalid native ciphertext") }
			if _, err := keys.ParsePublicKey(pair[i][:65]); err != nil { return nil, fmt.Errorf("invalid native ECIES ephemeral") }
		}
		out.sealed[id] = pair
	}
	if cursor != len(raw) { return nil, fmt.Errorf("trailing native packet bytes") }
	return out, nil
}

// This routine performs no mutation. Combined evaluation validation must
// succeed before a caller constructs/persists Spark's single-party tweak shape.
func decryptZarkNativeV1(config *so.Config, raw, expectedPlan []byte, owner keys.Public) (*zarkNativeTweak, error) {
	packet, err := decodeZarkNativeV1(config, raw, expectedPlan, owner)
	if err != nil { return nil, err }
	op := config.SigningOperatorMap[config.Identifier]
	if op == nil || op.ID != config.Index || !op.IdentityPublicKey.Equals(config.IdentityPrivateKey.Public()) { return nil, fmt.Errorf("native local operator identity differs") }
	id, err := hex.DecodeString(config.Identifier)
	if err != nil { return nil, err }
	modulus := secp256k1.S256().N
	combined := new(big.Int)
	defer combined.SetInt64(0)
	pair := packet.sealed[config.Identifier]
	for i, cipher := range pair {
		plaintext, err := eciesgo.Decrypt(eciesgo.NewPrivateKeyFromBytes(config.IdentityPrivateKey.Serialize()), cipher)
		if err != nil { return nil, fmt.Errorf("native VSS decryption failed") }
		defer clear(plaintext)
		prefix := len(zarkNativePayloadMagic)
		if len(plaintext) != prefix+130 || !bytes.Equal(plaintext[:prefix], []byte(zarkNativePayloadMagic)) || !bytes.Equal(plaintext[prefix:prefix+32], packet.commitment[:]) || !bytes.Equal(plaintext[prefix+32:prefix+64], packet.cluster[:]) || !bytes.Equal(plaintext[prefix+64:prefix+96], id) || binary.LittleEndian.Uint16(plaintext[prefix+96:prefix+98]) != uint16(i+1) {
			return nil, fmt.Errorf("native VSS opaque domain differs")
		}
		value := new(big.Int).SetBytes(plaintext[prefix+98:])
		defer value.SetInt64(0)
		if value.Cmp(modulus) >= 0 { return nil, fmt.Errorf("noncanonical native VSS evaluation") }
		if i == 0 { value.Lsh(value,1); combined.Add(combined,value) } else { combined.Sub(combined,value) }
		combined.Mod(combined,modulus)
	}
	if combined.Sign() == 0 { return nil, fmt.Errorf("zero native combined evaluation") }
	if err := secretsharing.ValidateShare(&secretsharing.VerifiableSecretShare{FieldModulus:modulus,Threshold:2,Index:new(big.Int).SetUint64(config.Index+1),Share:combined,Proofs:packet.proofs}); err != nil { return nil, fmt.Errorf("invalid native combined VSS evaluation: %w",err) }
	publicShares := map[string][]byte{}
	for id, op := range config.SigningOperatorMap {
		public, err := secretsharing.EvaluatePolynomialCommitment(packet.proofs,new(big.Int).SetUint64(op.ID+1),modulus)
		if err != nil { return nil, err }
		if _, err := zarkNativePoint(public.Serialize()); err != nil { return nil, err }
		publicShares[id] = public.Serialize()
	}
	marker := protowire.AppendTag(nil,zarkNativeMarkerField,protowire.BytesType)
	digest := sha256.Sum256(raw)
	marker = protowire.AppendBytes(marker,digest[:])
	return &zarkNativeTweak{secret:combined.FillBytes(make([]byte,32)),proofs:packet.proofs,publicShares:publicShares,marker:marker},nil
}
