package handler

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common/keys"
	"github.com/lightsparkdev/spark/so"
	"github.com/stretchr/testify/require"
)

// Explicit cross-language qualification only. Rust creates this isolated
// synthetic fixture under ignored work; no running services or wallet DBs are
// read. Without that fixture, this test makes no encryption-compatibility claim.
func TestZarkNativeV1RustEncryptedCombinedVss(t *testing.T) {
	path := os.Getenv("ZARK_NATIVE_VSS_FIXTURE")
	if path == "" { t.Skip("set ZARK_NATIVE_VSS_FIXTURE to the explicit private Rust fixture.json") }
	rawFixture, err := os.ReadFile(path)
	require.NoError(t,err)
	defer clear(rawFixture)
	var fixture struct {
		Schema string `json:"schema"`
		Version int `json:"version"`
		Synthetic bool `json:"synthetic_native_backing"`
		Packet []byte `json:"packet"`
		Plan []byte `json:"plan"`
		Operators []struct {ID string `json:"id"`; Secret []byte `json:"secret"`} `json:"operators"`
	}
	require.NoError(t,json.Unmarshal(rawFixture,&fixture))
	require.Equal(t,"zark-spark-native-vss-interop",fixture.Schema)
	require.Equal(t,1,fixture.Version)
	require.True(t,fixture.Synthetic)
	require.Len(t,fixture.Plan,352)
	require.Len(t,fixture.Operators,3)
	owner, err := keys.ParsePublicKey(fixture.Plan[92:125]);require.NoError(t,err)
	mask, err := keys.ParsePublicKey(fixture.Plan[158:191]);require.NoError(t,err)
	operators := map[string]*so.SigningOperator{}
	private := make([]keys.Private,len(fixture.Operators))
	for i, op := range fixture.Operators {
		private[i],err = keys.ParsePrivateKey(op.Secret);require.NoError(t,err)
		defer clear(op.Secret)
		operators[op.ID] = &so.SigningOperator{ID:uint64(i),Identifier:op.ID,IdentityPublicKey:private[i].Public()}
	}
	var shares []*big.Int
	var marker []byte
	for i, op := range fixture.Operators {
		config := &so.Config{Index:uint64(i),Identifier:op.ID,IdentityPrivateKey:private[i],SigningOperatorMap:operators,Threshold:2}
		combined,err := decryptZarkNativeV1(config,fixture.Packet,fixture.Plan,owner)
		require.NoError(t,err)
		require.Len(t,combined.secret,32)
		require.Len(t,combined.proofs,2)
		require.Len(t,combined.publicShares,3)
		require.Len(t,combined.marker,36)
		if marker == nil {marker = combined.marker} else {require.Equal(t,marker,combined.marker)}
		shares = append(shares,new(big.Int).SetBytes(combined.secret))
		defer clear(combined.secret)
		for attack := 0; attack < 4; attack++ {
			changed := bytes.Clone(fixture.Packet)
			switch attack {
			case 0: changed[len(zarkNativeMagic)+352] ^= 1 // salt changes opaque C
			case 1: changed[len(zarkNativeMagic)+352+32+2+128] ^= 1 // exact encrypted mask
			case 2:
				base := len(zarkNativeMagic)+352+32+2+129+66+2
				local := base+i*(32+2*(2+zarkNativeCipherBytes))+32+2
				changed[local+zarkNativeCipherBytes-1] ^= 1 // this operator's authenticated ciphertext
			default: changed = append(changed,0) // canonical packet tail
			}
			_,err = decryptZarkNativeV1(config,changed,fixture.Plan,owner)
			require.Error(t,err,"operator %d attack %d",i,attack)
		}
	}
	// Any valid threshold-two subset reconstructs the SAME combined tweak,
	// never either individual's point or scalar in the public operator packet.
	constant := new(big.Int).Lsh(shares[0],1)
	constant.Sub(constant,shares[1]).Mod(constant,secp256k1.S256().N)
	secret,err := keys.ParsePrivateKey(constant.FillBytes(make([]byte,32)))
	require.NoError(t,err)
	require.True(t,secret.Public().Equals(owner.Sub(mask)))
	for _,share := range shares {share.SetInt64(0)}
	constant.SetInt64(0)
}
