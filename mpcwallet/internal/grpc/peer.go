package grpc

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/hnamzian/yehuda-mpc/internal/mpc"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/mpcwalletpb"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Peer struct {
	addr   string
	client mpcwalletpb.MPCServiceClient
	logger zerolog.Logger
	ctx    context.Context
}

func NewPeer(addr string, logger zerolog.Logger) *Peer {
	return &Peer{addr: addr, logger: logger}
}

func (p *Peer) WithContext(ctx context.Context) *Peer {
	p.ctx = ctx
	return p
}

func (p *Peer) Connect() error {
	conn, err := grpc.Dial(p.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}

	p.client = mpcwalletpb.NewMPCServiceClient(conn)

	go func() {
		for {
			p.logger.Info().Msg("Connecting to peer...")
			_, err := p.client.HealthCheck(p.ctx, &mpcwalletpb.HealthCheckRequest{})
			if err == nil {
				p.logger.Info().Msg("Connected Peer")
				break
			}
			time.Sleep(1 * time.Second)
		}
	}()

	return nil
}

func (p *Peer) GeneratePartialKeyPair(keyID string) error {
	_, err := p.client.GeneratePartialKey(p.ctx, &mpcwalletpb.GeneratePartialKeyRequest{KeyId: keyID})
	return err
}

func (p *Peer) ExchangePartialKey(exchange *mpc.ExchangePartialKeyRequest) (*mpc.ExchangePartialKeyResponse, error) {
	resp, err := p.client.ExchangePartialKey(p.ctx, &mpcwalletpb.ExchangePartialKeyRequest{
		KeyId:      exchange.KeyID,
		Commitment: hex.EncodeToString(exchange.Commitment),
	})
	if err != nil {
		return nil, err
	}
	pubKey, err := hex.DecodeString(resp.PublicKey)
	if err != nil {
		return nil, err
	}
	return &mpc.ExchangePartialKeyResponse{
		KeyID:     resp.KeyId,
		PublicKey: pubKey,
	}, nil
}

func (p *Peer) ProvePartialKeyCommitment(prove *mpc.ProvePartialKeyCommitmentRequest) (*mpc.ProvePartialKeyCommitmentResponse, error) {
	resp, err := p.client.ProvePartialKeyCommitment(p.ctx, &mpcwalletpb.ProvePartialKeyCommitmentRequest{
		KeyId: prove.KeyID,
		Proof: hex.EncodeToString(prove.Proof),
	})
	if err != nil {
		return nil, err
	}
	return &mpc.ProvePartialKeyCommitmentResponse{
		KeyID:    resp.KeyId,
		Verified: resp.Verified,
	}, nil
}

func (p *Peer) ExchangeKey(exchange *mpc.ExchangeKeyRequest) (*mpc.ExchangeKeyResponse, error) {
	exchange_resp, err := p.client.ExchangeKey(p.ctx, &mpcwalletpb.ExchangeKeyRequest{
		KeyId:      exchange.KeyID,
		Commitment: hex.EncodeToString(exchange.Commitment),
	})
	if err != nil {
		return nil, err
	}
	pubKey, err := hex.DecodeString(exchange_resp.PublicKey)
	if err != nil {
		return nil, err
	}
	return &mpc.ExchangeKeyResponse{
		KeyID:     exchange_resp.KeyId,
		PublicKey: pubKey,
	}, nil
}

func (p *Peer) ProveKeyCommitment(prove *mpc.ProveKeyCommitmentRequest) (*mpc.ProveKeyCommitmentResponse, error) {
	resp, err := p.client.ProveKeyCommitment(p.ctx, &mpcwalletpb.ProveKeyCommitmentRequest{
		KeyId: prove.KeyID,
		Proof: hex.EncodeToString(prove.Proof),
	})
	if err != nil {
		return nil, err
	}
	return &mpc.ProveKeyCommitmentResponse{
		KeyID:    resp.KeyId,
		Verified: resp.Verified,
	}, nil
}
