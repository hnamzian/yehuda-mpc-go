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

func (s MpcServer) Sign(ctx context.Context, request *mpcwalletpb.SignRequest) (*mpcwalletpb.SignResponse, error) {
	resp, err := s.app.Sign(ctx, &application.SignRequest{
		KeyID:   request.KeyId,
		Message: request.Message,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.SignResponse{
		KeyId: request.KeyId,
		SigR:  hex.EncodeToString(resp.SignatureR),
		SigS:  hex.EncodeToString(resp.SignatureS),
	}, nil
}

func (s MpcServer) SignASN1(ctx context.Context, request *mpcwalletpb.SignASN1Request) (*mpcwalletpb.SignASN1Response, error) {
	resp, err := s.app.SignASN1(ctx, &application.SignASN1Request{
		KeyID:   request.KeyId,
		Message: request.Message,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.SignASN1Response{
		KeyId: request.KeyId,
		Signature:  hex.EncodeToString(resp.Signature),
	}, nil
}

func (s MpcServer) Verify(ctx context.Context, request *mpcwalletpb.VerifyRequest) (*mpcwalletpb.VerifyResponse, error) {
	sig_r, err := hex.DecodeString(request.SigR)
	if err != nil {
		return nil, err
	}
	sig_s, err := hex.DecodeString(request.SigS)
	if err != nil {
		return nil, err
	}
	resp, err := s.app.Verify(ctx, &application.VerifyRequest{
		KeyID:      request.KeyId,
		Message:    request.Message,
		SignatureR: sig_r,
		SignatureS: sig_s,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.VerifyResponse{
		KeyId:    request.KeyId,
		Verified: resp.Verified,
	}, nil
}

func (s MpcServer) VerifyASN1(ctx context.Context, request *mpcwalletpb.VerifyASN1Request) (*mpcwalletpb.VerifyASN1Response, error) {
	sig, err := hex.DecodeString(request.Signature)
	if err != nil {
		return nil, err
	}
	resp, err := s.app.VerifyASN1(ctx, &application.VerifyASN1Request{
		KeyID:      request.KeyId,
		Message:    request.Message,
		Signature: sig,
	})
	if err != nil {
		return nil, err
	}
	return &mpcwalletpb.VerifyASN1Response{
		KeyId:    request.KeyId,
		Verified: resp.Verified,
	}, nil
}

func (s MpcServer) GenerateSignatureR(ctx context.Context, request *mpcwalletpb.GenerateSignatureRRequest) (*mpcwalletpb.GenerateSignatureRResponse, error) {
	partialR_bytes, err := hex.DecodeString(request.Partial_R)
	if err != nil {
		return nil, err
	}
	resp, err := s.app.GenerateSignatureR(ctx, &application.GenerateSignatureRRequest{
		SigID:    request.SigId,
		KeyID:    request.KeyId,
		PartialR: partialR_bytes,
	})
	return &mpcwalletpb.GenerateSignatureRResponse{
		SigId: resp.SigID,
		KeyId: resp.KeyID,
		R:     hex.EncodeToString(resp.R),
	}, nil
}

func (s MpcServer) GeneratePartialSignatureS(ctx context.Context, request *mpcwalletpb.GeneratePartialSignatureSRequest) (*mpcwalletpb.GeneratePartialSignatureSResponse, error) {
	PeerEncPrivKeyBytes, err := hex.DecodeString(request.EncryptedPrivKey)
	if err != nil {
		return nil, err
	}
	PaillierPkBytes, err := hex.DecodeString(request.PaillierPk)
	if err != nil {
		return nil, err
	}
	digestBytes, err := hex.DecodeString(request.Digest)
	if err != nil {
		return nil, err
	}
	resp, err := s.app.GeneratePartialSignatureS(ctx, &application.GeneratePartialSignatureSRequest{
		SigID:                request.SigId,
		KeyID:                request.KeyId,
		PeerEncryptedPrivKey: PeerEncPrivKeyBytes,
		PeerPaillierKey:      PaillierPkBytes,
		Digest:               digestBytes,
	})
	return &mpcwalletpb.GeneratePartialSignatureSResponse{
		SigId: resp.SigID,
		KeyId: resp.KeyID,
		S:     hex.EncodeToString(resp.S),
	}, nil
}
