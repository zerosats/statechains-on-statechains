// The ordinary recipient can hold its complete key. Its normal claim package
// is nevertheless frozen before delivery so an uncertain RPC retries exactly.
package main

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/keys"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/testing/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Claims every leaf of `tr` to the recipient's fixed leaf key `user`;
// `masks` holds each leaf's decrypted incoming key.
func ordinaryFrozenClaim(t *testing.T, ctx context.Context, directory, transferID string, cfg *wallet.TestWalletConfig, tr *pb.Transfer, masks map[string]keys.Private, user keys.Private) *pb.ClaimTransferRequest {
	t.Helper()
	name := filepath.Join(directory, "ordinary-exit-"+transferID+".claim.pb")
	if raw, err := os.ReadFile(name); err == nil {
		var request pb.ClaimTransferRequest
		require.NoError(t, proto.Unmarshal(raw, &request))
		require.Equal(t, transferID, request.GetTransferId())
		require.Equal(t, cfg.IdentityPublicKey().Serialize(), request.GetOwnerIdentityPublicKey())
		checked, err := proto.MarshalOptions{Deterministic: true}.Marshal(&request)
		require.NoError(t, err)
		require.Equal(t, raw, checked)
		return &request
	} else {
		require.True(t, os.IsNotExist(err))
	}
	// Equivalent to the pinned wallet's normal prepareClaimLeafKeyTweaks.
	// These are exclusively the ordinary recipient's mask/new USER secrets.
	tweaks := make(map[string][]*pb.ClaimLeafKeyTweak)
	leaves := []wallet.LeafKeyTweak{}
	for _, item := range tr.GetLeaves() {
		leaf := item.GetLeaf()
		mask, found := masks[leaf.GetId()]
		require.True(t, found, "ordinary claim mask for %s", leaf.GetId())
		tweak := mask.Sub(user)
		shares, err := secretsharing.SplitSecretWithProofs(new(big.Int).SetBytes(tweak.Serialize()), secp256k1.S256().N, cfg.Threshold, len(cfg.SigningOperators))
		require.NoError(t, err)
		public := make(map[string][]byte)
		private := make(map[string][]byte)
		for id, operator := range cfg.SigningOperators {
			var found *secretsharing.VerifiableSecretShare
			for _, share := range shares {
				if share.Index.Cmp(big.NewInt(int64(operator.ID+1))) == 0 {
					found = share
					break
				}
			}
			require.NotNil(t, found, fmt.Sprintf("ordinary operator share %s", id))
			value := make([]byte, 32)
			found.Share.FillBytes(value)
			private[id] = value
			key, err := keys.ParsePrivateKey(value)
			require.NoError(t, err)
			public[id] = key.Public().Serialize()
		}
		for id, value := range private {
			tweaks[id] = append(tweaks[id], &pb.ClaimLeafKeyTweak{LeafId: leaf.GetId(), SecretShareTweak: &pb.SecretShare{SecretShare: value, Proofs: shares[0].Proofs}, PubkeySharesTweak: public})
		}
		leaves = append(leaves, wallet.LeafKeyTweak{Leaf: leaf, SigningPrivKey: user})
	}
	id, err := uuid.Parse(transferID)
	require.NoError(t, err)
	pack, err := wallet.PrepareClaimPackage(ctx, cfg, id, tweaks, leaves)
	require.NoError(t, err)
	request := &pb.ClaimTransferRequest{TransferId: transferID, OwnerIdentityPublicKey: cfg.IdentityPublicKey().Serialize(), ClaimPackage: pack}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	require.NoError(t, err)
	ordinaryFreeze(t, name, raw)
	return request
}
