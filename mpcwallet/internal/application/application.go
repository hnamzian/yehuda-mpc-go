package application

import (
	"context"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/hnamzian/yehuda-mpc/internal/mpc"
	"github.com/rs/zerolog"
)

type App interface {
	HealthCheck(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	GeneratePartialKey(context.Context, *GeneratePartialKeyRequest) (*GeneratePartialKeyResponse, error)
	ExchangePartialKey(ctx context.Context, exchange *ExchangePartialKeyRequest) (*ExchangePartialKeyResponse, error)
	ProvePartialKeyCommitment(ctx context.Context, prove *ProvePartialKeyCommitmentRequest) (*ProvePartialKeyCommitmentResponse, error)
	ExchangeKey(context.Context, *ExchangeKeyRequest) (*ExchangeKeyResponse, error)
	ProveKeyCommitment(context.Context, *ProveKeyCommitmentRequest) (*ProveKeyCommitmentResponse, error)
}

type Application struct {
	mpc  *mpc.MPC
	peer mpc.Peer
}

type (
	HealthCheckRequest  struct{}
	HealthCheckResponse struct {
		Status string
	}

	GenerateKeyPairRequest  struct{}
	GenerateKeyPairResponse struct {
		KeyID string
	}

	GeneratePartialKeyRequest struct {
		KeyID string
	}
	GeneratePartialKeyResponse struct{}

	ExchangePartialKeyRequest struct {
		KeyID      string
		Commitment string
	}

	ExchangePartialKeyResponse struct {
		KeyID     string
		PublicKey []byte
	}

	ProvePartialKeyCommitmentRequest struct {
		KeyID string
		Proof string
	}

	ProvePartialKeyCommitmentResponse struct {
		KeyID   string
		Verfied bool
	}

	ExchangeKeyRequest struct {
		KeyID      string
		Commitment string
	}

	ExchangeKeyResponse struct {
		KeyID     string
		PublicKey []byte
	}

	ProveKeyCommitmentRequest struct {
		KeyID string
		Proof string
	}

	ProveKeyCommitmentResponse struct {
		KeyID    string
		Verified bool
	}
)

func NewApplication(name string, walletPath string, peer mpc.Peer, logger zerolog.Logger) Application {
	mpc := mpc.NewMPC(name, "./keys/p1", logger)
	mpc.AddPeer(peer)
	return Application{mpc: mpc, peer: peer}
}

func (a Application) HealthCheck(ctx context.Context, health *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{
		Status: "OK",
	}, nil
}

func (a Application) GenerateKeyPair(ctx context.Context, generate *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	keyID := uuid.New().String()
	err := a.mpc.GenerateKeyPair(keyID)
	if err != nil {
		return nil, err
	}

	return &GenerateKeyPairResponse{
		KeyID: keyID,
	}, nil
}

func (a Application) GeneratePartialKey(ctx context.Context, generate *GeneratePartialKeyRequest) (*GeneratePartialKeyResponse, error) {
	err := a.mpc.GeneratePartialKeyPair(generate.KeyID)
	if err != nil {
		return nil, err
	}
	return &GeneratePartialKeyResponse{}, nil
}

func (a Application) ExchangePartialKey(ctx context.Context, exchange *ExchangePartialKeyRequest) (*ExchangePartialKeyResponse, error) {
	commitment, err := hex.DecodeString(exchange.Commitment)
	if err != nil {
		return nil, err
	}
	a.mpc.ExchangePartialKey(&mpc.ExchangePartialKeyRequest{
		KeyID: 	exchange.KeyID,
		Commitment: commitment,	
	})
	return &ExchangePartialKeyResponse{
		KeyID:     exchange.KeyID,
		PublicKey: a.mpc.PartialPublicKeyBytes(exchange.KeyID),
	}, nil
}

func (a Application) ProvePartialKeyCommitment(ctx context.Context, prove *ProvePartialKeyCommitmentRequest) (*ProvePartialKeyCommitmentResponse, error) {
	proof, err := hex.DecodeString(prove.Proof)
	if err != nil {
		return nil, err
	}
	proof_resp, err := a.mpc.ProvePartialKeyCommitment(&mpc.ProvePartialKeyCommitmentRequest{
		KeyID: prove.KeyID,
		Proof: proof,
	})
	if err != nil {
		return nil, err
	}
	return &ProvePartialKeyCommitmentResponse{
		KeyID:   prove.KeyID,
		Verfied: proof_resp.Verified,
	}, nil
}

func (a Application) ExchangeKey(ctx context.Context, exchange *ExchangeKeyRequest) (*ExchangeKeyResponse, error) {
	commitment, err := hex.DecodeString(exchange.Commitment)
	if err != nil {
		return nil, err
	}
	exchange_resp, err := a.mpc.ExchangeKey(&mpc.ExchangeKeyRequest{
		KeyID:      exchange.KeyID,
		Commitment: commitment,
	})
	if err != nil {
		return nil, err
	}
	return &ExchangeKeyResponse{
		KeyID:     exchange_resp.KeyID,
		PublicKey: exchange_resp.PublicKey,
	}, nil
}

func (a Application) ProveKeyCommitment(ctx context.Context, prove *ProveKeyCommitmentRequest) (*ProveKeyCommitmentResponse, error) {
	proof, err := hex.DecodeString(prove.Proof)
	if err != nil {
		return nil, err
	}
	proof_resp, err := a.mpc.ProveKeyCommitment(&mpc.ProveKeyCommitmentRequest{
		KeyID: prove.KeyID,
		Proof: proof,
	})
	if err != nil {
		return nil, err
	}
	return &ProveKeyCommitmentResponse{
		KeyID:    proof_resp.KeyID,
		Verified: proof_resp.Verified,
	}, nil
}
