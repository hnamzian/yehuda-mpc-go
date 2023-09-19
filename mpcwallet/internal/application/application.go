package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/hnamzian/yehuda-mpc/internal/mpc"
	"github.com/rs/zerolog"
)

type App interface {
	HealthCheck(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
	GetWallet(context.Context, *GetWalletRequest) (*GetWalletResponse, error)
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	GeneratePartialKey(context.Context, *GeneratePartialKeyRequest) (*GeneratePartialKeyResponse, error)
	ExchangePartialKey(ctx context.Context, exchange *ExchangePartialKeyRequest) (*ExchangePartialKeyResponse, error)
	ProvePartialKeyCommitment(ctx context.Context, prove *ProvePartialKeyCommitmentRequest) (*ProvePartialKeyCommitmentResponse, error)
	ExchangeKey(context.Context, *ExchangeKeyRequest) (*ExchangeKeyResponse, error)
	ProveKeyCommitment(context.Context, *ProveKeyCommitmentRequest) (*ProveKeyCommitmentResponse, error)
	Sign(context.Context, *SignRequest) (*SignResponse, error)
	SignASN1(context.Context, *SignASN1Request) (*SignASN1Response, error)
	Verify(context.Context, *VerifyRequest) (*VerifyResponse, error)
	VerifyASN1(context.Context, *VerifyASN1Request) (*VerifyASN1Response, error)
	GenerateSignatureR(ctx context.Context, generate *GenerateSignatureRRequest) (*GenerateSignatureRResponse, error)
	GeneratePartialSignatureS(ctx context.Context, generate *GeneratePartialSignatureSRequest) (*GeneratePartialSignatureSResponse, error)
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

	GetWalletRequest struct {
		KeyID string
	}
	GetWalletResponse struct {
		KeyID            string
		PartialPublicKey []byte
		PublicKey        []byte
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

	SignRequest struct {
		KeyID   string
		Message string
	}

	SignResponse struct {
		SigID      string
		KeyID      string
		SignatureR []byte
		SignatureS []byte
	}

	SignASN1Request struct {
		KeyID   string
		Message string
	}

	SignASN1Response struct {
		SigID     string
		KeyID     string
		Signature []byte
	}

	VerifyRequest struct {
		KeyID      string
		Message    string
		SignatureR []byte
		SignatureS []byte
	}

	VerifyResponse struct {
		KeyID    string
		Verified bool
	}

	VerifyASN1Request struct {
		KeyID     string
		Message   string
		Signature []byte
	}

	VerifyASN1Response struct {
		KeyID    string
		Verified bool
	}

	GenerateSignatureRRequest struct {
		SigID    string
		KeyID    string
		PartialR []byte
	}

	GenerateSignatureRResponse struct {
		SigID string
		KeyID string
		R     []byte
	}

	GeneratePartialSignatureSRequest struct {
		SigID                string
		KeyID                string
		PeerEncryptedPrivKey []byte
		PeerPaillierKey      []byte
		Digest               []byte
	}

	GeneratePartialSignatureSResponse struct {
		SigID string
		KeyID string
		S     []byte
	}
)

func NewApplication(name string, walletPath string, peer mpc.Peer, logger zerolog.Logger) Application {
	mpc := mpc.NewMPC(name, "./keys/p1", logger)
	mpc.AddPeer(peer)
	mpc.InitSignator()
	return Application{mpc: mpc, peer: peer}
}

func (a Application) HealthCheck(ctx context.Context, health *HealthCheckRequest) (*HealthCheckResponse, error) {
	return &HealthCheckResponse{
		Status: "OK",
	}, nil
}

func (a Application) GetWallet(ctx context.Context, get *GetWalletRequest) (*GetWalletResponse, error) {
	partialPubKey := a.mpc.PartialPublicKeyBytes(get.KeyID)
	publicKey := a.mpc.PublicKeyBytes(get.KeyID)
	return &GetWalletResponse{
		KeyID:            get.KeyID,
		PartialPublicKey: partialPubKey,
		PublicKey:        publicKey,
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
		KeyID:      exchange.KeyID,
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

func (a Application) Sign(ctx context.Context, sign *SignRequest) (*SignResponse, error) {
	h := sha256.Sum256([]byte(sign.Message))
	sigR, sigS, err := a.mpc.Sign(h[:], sign.KeyID)
	if err != nil {
		return nil, err
	}
	return &SignResponse{
		KeyID:      sign.KeyID,
		SignatureR: sigR,
		SignatureS: sigS,
	}, nil
}

func (a Application) SignASN1(ctx context.Context, sign *SignASN1Request) (*SignASN1Response, error) {
	h := sha256.Sum256([]byte(sign.Message))
	sig, err := a.mpc.SignASN1(h[:], sign.KeyID)
	if err != nil {
		return nil, err
	}
	return &SignASN1Response{
		KeyID:     sign.KeyID,
		Signature: sig,
	}, nil
}

func (a Application) Verify(ctx context.Context, verify *VerifyRequest) (*VerifyResponse, error) {
	h := sha256.Sum256([]byte(verify.Message))
	verified := a.mpc.Verify(h[:], verify.SignatureR, verify.SignatureS, verify.KeyID)
	return &VerifyResponse{
		KeyID:    verify.KeyID,
		Verified: verified,
	}, nil
}

func (a Application) VerifyASN1(ctx context.Context, verify *VerifyASN1Request) (*VerifyASN1Response, error) {
	h := sha256.Sum256([]byte(verify.Message))
	verified := a.mpc.VerifyASN1(h[:], verify.Signature, verify.KeyID)
	return &VerifyASN1Response{
		KeyID:    verify.KeyID,
		Verified: verified,
	}, nil
}

func (a Application) GenerateSignatureR(ctx context.Context, generate *GenerateSignatureRRequest) (*GenerateSignatureRResponse, error) {
	resp, err := a.mpc.GenerateSigantureR(&mpc.GenerateSigRRequest{
		SigID: generate.SigID,
		KeyID: generate.KeyID,
		R:     generate.PartialR,
	})
	if err != nil {
		return nil, err
	}

	return &GenerateSignatureRResponse{
		SigID: resp.SigID,
		KeyID: resp.KeyID,
		R:     resp.R,
	}, nil
}

func (a Application) GeneratePartialSignatureS(ctx context.Context, generate *GeneratePartialSignatureSRequest) (*GeneratePartialSignatureSResponse, error) {
	resp, err := a.mpc.GeneratePartialSignatureS(&mpc.GeneratePartialSignatureSRequest{
		SigID:  generate.SigID,
		KeyID:  generate.KeyID,
		D:      generate.PeerEncryptedPrivKey,
		PK:     generate.PeerPaillierKey,
		Digest: generate.Digest,
	})
	if err != nil {
		return nil, err
	}

	return &GeneratePartialSignatureSResponse{
		SigID: resp.SigID,
		KeyID: resp.KeyID,
		S:     resp.S,
	}, nil
}
