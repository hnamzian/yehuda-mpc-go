package grpc

import (
	"context"
	"encoding/hex"

	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/application"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/mpcwalletpb"
	"google.golang.org/grpc"
)

type MpcServer struct {
	app application.App
	mpcwalletpb.UnimplementedMPCServiceServer
}

func RegisterWalletServer(registrar grpc.ServiceRegistrar, app application.App) *MpcServer {
	mpcwalletpb.RegisterMPCServiceServer(registrar, &MpcServer{app: app})
	return &MpcServer{}
}

func (s MpcServer) HealthCheck(ctx context.Context, request *mpcwalletpb.HealthCheckRequest) (*mpcwalletpb.HealthCheckResponse, error) {
	resp, err := s.app.HealthCheck(ctx, &application.HealthCheckRequest{})
	return &mpcwalletpb.HealthCheckResponse{
		Status: resp.Status,
	}, err
}

func (s MpcServer) GetWallet(ctx context.Context, get *mpcwalletpb.GetWalletRequest) (*mpcwalletpb.GetWalletResponse, error) {
	resp, err := s.app.GetWallet(ctx, &application.GetWalletRequest{
		KeyID: get.KeyId,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.GetWalletResponse{
		KeyId:         resp.KeyID,
		PartialPubKey: hex.EncodeToString(resp.PartialPublicKey),
		PublicKey:     hex.EncodeToString(resp.PublicKey),
	}, nil
}

func (s MpcServer) GenerateKeyPair(ctx context.Context, request *mpcwalletpb.GenerateKeyPairRequest) (*mpcwalletpb.GenerateKeyPairResponse, error) {
	resp, err := s.app.GenerateKeyPair(ctx, &application.GenerateKeyPairRequest{})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.GenerateKeyPairResponse{
		KeyId: resp.KeyID,
	}, nil
}

func (s MpcServer) GeneratePartialKey(ctx context.Context, request *mpcwalletpb.GeneratePartialKeyRequest) (*mpcwalletpb.GeneratePartialKeyResponse, error) {
	_, err := s.app.GeneratePartialKey(ctx, &application.GeneratePartialKeyRequest{KeyID: request.KeyId})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.GeneratePartialKeyResponse{}, nil
}

func (s MpcServer) ExchangePartialKey(ctx context.Context, request *mpcwalletpb.ExchangePartialKeyRequest) (*mpcwalletpb.ExchangePartialKeyResponse, error) {
	resp, err := s.app.ExchangePartialKey(ctx, &application.ExchangePartialKeyRequest{
		KeyID:      request.KeyId,
		Commitment: request.Commitment,
	})
	if err != nil {
		return nil, err
	}
	pub_key := hex.EncodeToString(resp.PublicKey)
	return &mpcwalletpb.ExchangePartialKeyResponse{
		KeyId:     resp.KeyID,
		PublicKey: pub_key,
	}, nil
}

func (s MpcServer) ProvePartialKeyCommitment(ctx context.Context, request *mpcwalletpb.ProvePartialKeyCommitmentRequest) (*mpcwalletpb.ProvePartialKeyCommitmentResponse, error) {
	resp, err := s.app.ProvePartialKeyCommitment(ctx, &application.ProvePartialKeyCommitmentRequest{
		KeyID: request.KeyId,
		Proof: request.Proof,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.ProvePartialKeyCommitmentResponse{
		KeyId:    resp.KeyID,
		Verified: resp.Verfied,
	}, nil
}

func (s MpcServer) ExchangeKey(ctx context.Context, exchange *mpcwalletpb.ExchangeKeyRequest) (*mpcwalletpb.ExchangeKeyResponse, error) {
	resp, err := s.app.ExchangeKey(ctx, &application.ExchangeKeyRequest{
		KeyID:      exchange.KeyId,
		Commitment: exchange.Commitment,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.ExchangeKeyResponse{
		KeyId:     resp.KeyID,
		PublicKey: hex.EncodeToString(resp.PublicKey),
	}, nil
}

func (s MpcServer) ProveKeyCommitment(ctx context.Context, prove *mpcwalletpb.ProveKeyCommitmentRequest) (*mpcwalletpb.ProveKeyCommitmentResponse, error) {
	resp, err := s.app.ProveKeyCommitment(ctx, &application.ProveKeyCommitmentRequest{
		KeyID: prove.KeyId,
		Proof: prove.Proof,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.ProveKeyCommitmentResponse{
		KeyId:    resp.KeyID,
		Verified: resp.Verified,
	}, nil
}
