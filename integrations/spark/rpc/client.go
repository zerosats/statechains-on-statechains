package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"time"

	pb "github.com/lightsparkdev/spark/proto/spark"
	auth "github.com/lightsparkdev/spark/proto/spark_authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type endpoint struct {
	Address string `json:"address"`
	Domain  string `json:"domain"`
	CA      string `json:"ca_pem"`
}
type settings struct {
	Network     string              `json:"network"`
	Coordinator string              `json:"coordinator"`
	Operators   map[string]endpoint `json:"operators"`
	Owner       blob                `json:"owner_identity"`
}
type client struct {
	config     settings
	conns      map[string]*grpc.ClientConn
	challenges map[string]*auth.ProtectedChallenge
	tokens     map[string]string
}

func newClient(s settings) (*client, error) {
	_, knownNetwork := pb.Network_value[s.Network]
	if len(s.Operators) < 2 || len(s.Operators) > 16 || len(s.Owner) != 33 || !knownNetwork {
		return nil, errors.New("invalid native RPC settings")
	}
	if _, ok := s.Operators[s.Coordinator]; !ok {
		return nil, errors.New("missing native coordinator")
	}
	c := &client{config: s, conns: make(map[string]*grpc.ClientConn), challenges: make(map[string]*auth.ProtectedChallenge), tokens: make(map[string]string)}
	for id, e := range s.Operators {
		if !strings.HasPrefix(e.Address, "https://") || e.Domain == "" {
			c.close()
			return nil, errors.New("native RPC requires pinned TLS")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(e.CA)) {
			c.close()
			return nil, errors.New("invalid native RPC CA")
		}
		conn, err := grpc.NewClient(strings.TrimPrefix(e.Address, "https://"), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: e.Domain, MinVersion: tls.VersionTLS12})), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024)))
		if err != nil {
			c.close()
			return nil, errors.New("native RPC connection failed")
		}
		c.conns[id] = conn
	}
	return c, nil
}
func (c *client) close() {
	for _, conn := range c.conns {
		_ = conn.Close()
	}
}
func (c *client) rpcContext(id string) (context.Context, context.CancelFunc, error) {
	token, ok := c.tokens[id]
	if !ok {
		return nil, nil, errors.New("native RPC session missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token), cancel, nil
}
func (c *client) challenge(id string) (blob, error) {
	conn, ok := c.conns[id]
	if !ok {
		return nil, errors.New("unknown operator")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := auth.NewSparkAuthnServiceClient(conn).GetChallenge(ctx, &auth.GetChallengeRequest{PublicKey: c.config.Owner})
	if err != nil {
		return nil, err
	}
	protected := response.GetProtectedChallenge()
	core := protected.GetChallenge()
	if protected.GetVersion() != 1 || core.GetVersion() != 1 || len(core.GetNonce()) != 32 || !bytes.Equal(core.GetPublicKey(), c.config.Owner) || core.GetTimestamp() < time.Now().Unix()-300 || core.GetTimestamp() > time.Now().Unix()+300 {
		return nil, errors.New("native authentication challenge binding mismatch")
	}
	c.challenges[id] = protected
	encoded, err := proto.Marshal(core)
	return blob(encoded), err
}
func (c *client) authenticate(id string, signature []byte) error {
	challenge, ok := c.challenges[id]
	if !ok {
		return errors.New("native authentication challenge missing")
	}
	delete(c.challenges, id)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := auth.NewSparkAuthnServiceClient(c.conns[id]).VerifyChallenge(ctx, &auth.VerifyChallengeRequest{ProtectedChallenge: challenge, PublicKey: c.config.Owner, Signature: signature})
	if err != nil {
		return err
	}
	if response.GetSessionToken() == "" || response.GetExpirationTimestamp() <= time.Now().Unix() {
		return errors.New("invalid native session response")
	}
	c.tokens[id] = response.GetSessionToken()
	return nil
}

type observation struct {
	Found        bool    `json:"found"`
	Digest       blob    `json:"digest"`
	TransferID   string  `json:"transfer_id"`
	LeafID       string  `json:"leaf_id"`
	Sender       blob    `json:"sender_identity"`
	Receiver     blob    `json:"receiver_identity"`
	Amount       uint64  `json:"amount_sats"`
	VerifyingKey blob    `json:"verifying_key"`
	Completed    bool    `json:"completed"`
	Failure      *string `json:"failure,omitempty"`
}

func (c *client) query(id, transferID string) (observation, error) {
	ctx, cancel, err := c.rpcContext(id)
	if err != nil {
		return observation{}, err
	}
	defer cancel()
	response, err := pb.NewSparkServiceClient(c.conns[id]).QueryTransfersById(ctx, &pb.QueryTransfersByIdRequest{TransferIds: []string{transferID}, Network: pb.Network(pb.Network_value[c.config.Network])})
	if err != nil {
		return observation{}, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(response)
	if err != nil {
		return observation{}, err
	}
	digest := sha256.Sum256(raw)
	result := observation{Digest: blob(digest[:])}
	if len(response.GetTransfers()) == 0 {
		return result, nil
	}
	if len(response.GetTransfers()) != 1 {
		return result, errors.New("native query returned unexpected transfer set")
	}
	transfer := response.GetTransfers()[0]
	if len(transfer.GetLeaves()) != 1 || transfer.GetLeaves()[0].GetLeaf() == nil {
		return result, errors.New("native transfer leaf set mismatch")
	}
	leaf := transfer.GetLeaves()[0].GetLeaf()
	result.Found = true
	result.TransferID = transfer.GetId()
	result.LeafID = leaf.GetId()
	result.Sender = transfer.GetSenderIdentityPublicKey()
	result.Receiver = transfer.GetReceiverIdentityPublicKey()
	result.Amount = transfer.GetTotalValue()
	result.VerifyingKey = leaf.GetVerifyingPublicKey()
	result.Completed = transfer.GetStatus() == pb.TransferStatus_TRANSFER_STATUS_COMPLETED
	if transfer.GetStatus() == pb.TransferStatus_TRANSFER_STATUS_RETURNED || transfer.GetStatus() == pb.TransferStatus_TRANSFER_STATUS_EXPIRED {
		failure := "returned"
		if transfer.GetStatus() == pb.TransferStatus_TRANSFER_STATUS_EXPIRED {
			failure = "expired"
		}
		result.Failure = &failure
	}
	return result, nil
}
func (c *client) submit(p *packetWire) error {
	if !bytes.Equal(p.Sender, c.config.Owner) {
		return errors.New("native sender session mismatch")
	}
	req, err := p.request()
	if err != nil {
		return err
	}
	ctx, cancel, err := c.rpcContext(c.config.Coordinator)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = pb.NewSparkServiceClient(c.conns[c.config.Coordinator]).StartTransferMpc(ctx, req)
	return err
}
