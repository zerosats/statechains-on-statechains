// Private newline-delimited JSON bridge to the pinned Spark protobuf client.
// No private leaf scalar or service-identity key is accepted by this process.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"google.golang.org/grpc/status"
)

type request struct {
	Op         string      `json:"op"`
	Settings   *settings   `json:"settings,omitempty"`
	Operator   string      `json:"operator,omitempty"`
	Signature  blob        `json:"signature,omitempty"`
	TransferID string      `json:"transfer_id,omitempty"`
	LeafID     string      `json:"leaf_id,omitempty"`
	Receiver   blob        `json:"receiver_identity,omitempty"`
	Packet     *packetWire `json:"packet,omitempty"`
	Claim      *claimWire  `json:"claim,omitempty"`
}

func dispatch(c **client, r request) (any, error) {
	if r.Op == "validate" {
		if r.Packet == nil {
			return nil, errors.New("native packet missing")
		}
		_, err := r.Packet.request()
		return nil, err
	}
	if r.Op == "configure" {
		if *c != nil || r.Settings == nil {
			return nil, errors.New("native RPC is already configured")
		}
		configured, err := newClient(*r.Settings)
		if err != nil {
			return nil, err
		}
		*c = configured
		return "zark-spark-rpc-v1", nil
	}
	if *c == nil {
		return nil, errors.New("native RPC is not configured")
	}
	switch r.Op {
	case "challenge":
		return (*c).challenge(r.Operator)
	case "authenticate":
		return nil, (*c).authenticate(r.Operator, r.Signature)
	case "query":
		return (*c).query(r.Operator, r.TransferID)
	case "backing":
		source, _, err := (*c).source(r.LeafID)
		return source, err
	case "prepare":
		return (*c).prepare(r.LeafID, r.Receiver)
	case "claim_shared":
		if r.Claim == nil {
			return nil, errors.New("shared claim missing")
		}
		return (*c).claimShared(r.Claim)
	case "submit":
		if r.Packet == nil {
			return nil, errors.New("native packet missing")
		}
		return nil, (*c).submit(r.Packet)
	default:
		return nil, errors.New("unknown native RPC operation")
	}
}
func run(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 128*1024)
	var c *client
	defer func() {
		if c != nil {
			c.close()
		}
	}()
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		raw := scanner.Bytes()
		var r request
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&r)
		if err == nil {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				err = errors.New("trailing native RPC input")
			}
		}
		var value any
		if err == nil {
			value, err = dispatch(&c, r)
		}
		response := struct {
			OK    bool   `json:"ok"`
			Value any    `json:"value"`
			Error string `json:"error,omitempty"`
		}{OK: err == nil, Value: value}
		if err != nil {
			// Never echo request bodies, session tokens or server error text.
			// The gRPC code distinguishes retryable network/consensus failures.
			response.Error = "native RPC rejected: " + status.Code(err).String()
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func main() {
	if run(os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
