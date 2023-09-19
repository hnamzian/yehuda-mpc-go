package mpc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/paillier"
	homomorphic "github.com/hnamzian/yehuda-mpc/internal/paillier"
	"github.com/rs/zerolog"
)

type MPC struct {
	name                     string
	wallets                  Wallets
	peer                     Peer
	peerPartialKeyCommitment map[string][]byte
	peerKeyCommitment        map[string][]byte
	paillierPk               *homomorphic.PaillierKey
	signator                 Signator
	logger                   zerolog.Logger
}

func NewMPC(name string, paillier_path string, logger zerolog.Logger) *MPC {
	pk, err := homomorphic.CreatePaillierKeypair(paillier_path)
	if err != nil {
		panic(err)
	}
	return &MPC{
		name:                     name,
		peerPartialKeyCommitment: make(map[string][]byte),
		peerKeyCommitment:        make(map[string][]byte),
		paillierPk:               pk,
		wallets:                  make(Wallets),
		logger:                   logger,
	}
}

func (mpc *MPC) AddPeer(peer Peer) {
	mpc.peer = peer
}

func (mpc *MPC) GenerateKeyPair(id string) error {
	err := mpc.GeneratePartialKeyPair(id)
	if err != nil {
		return err
	}
	// err = mpc.peer.Connect()
	// if err != nil {
	// 	return err
	// }
	err = mpc.peer.GeneratePartialKeyPair(id)
	if err != nil {
		return err
	}

	mpc.logger.Debug().Msg("peer.ExchangePartialKey")
	hash := sha256.New()
	resp, err := mpc.peer.ExchangePartialKey(&ExchangePartialKeyRequest{
		KeyID:      id,
		Commitment: hash.Sum(mpc.wallets.GetWallet(id).PartialPublicKeyBytes()),
	})
	if err != nil {
		return err
	}
	mpc.logger.Debug().Msg("peer.ExchangePartialKey OK")

	peerPubKey := PublicKeyFromBytes(resp.PublicKey)
	mpc.wallets.GetWallet(id).ComputeWalletPublicKey(peerPubKey)
	mpc.logger.Debug().Str("PublicKey", hex.EncodeToString(mpc.wallets.GetWallet(id).PublicKeyBytes())).Msg("Public Key Updated")

	mpc.logger.Debug().Msg("peer.ProvePartialKeyCommitment")
	proof_resp, err := mpc.peer.ProvePartialKeyCommitment(&ProvePartialKeyCommitmentRequest{
		KeyID: id,
		Proof: PublicKeyToBytes(mpc.wallets.GetWallet(id).PartialPublicKey()),
	})
	if err != nil {
		return err
	}
	if !proof_resp.Verified {
		return fmt.Errorf("Peer partial public key not verified")
	}
	mpc.logger.Debug().Msg("peer.ProvePartialKeyCommitment OK")

	mpc.logger.Debug().Msg("peer.ExchangeKey")
	_, err = mpc.peer.ExchangeKey(&ExchangeKeyRequest{
		KeyID:      id,
		Commitment: hash.Sum(mpc.wallets.GetWallet(id).PublicKeyBytes()),
	})
	if err != nil {
		return err
	}
	mpc.logger.Debug().Msg("peer.ExchangeKey OK")

	mpc.logger.Debug().Msg("peer.ProveKeyCommitment")
	key_resp, err := mpc.peer.ProveKeyCommitment(&ProveKeyCommitmentRequest{
		KeyID: id,
		Proof: PublicKeyToBytes(mpc.wallets.GetWallet(id).PublicKey()),
	})
	if err != nil {
		return err
	}
	if !key_resp.Verified {
		return fmt.Errorf("Peer public key not verified")
	}
	mpc.logger.Debug().Msg("peer.ProveKeyCommitment OK")

	return nil
}

func (mpc *MPC) GeneratePartialKeyPair(id string) (err error) {
	mpc.logger.Debug().Msg("mpc.GeneratePartialKeyPair")
	defer func() {
		if err != nil {
			mpc.logger.Error().Err(err).Msg("mpc.GeneratePartialKeyPair FAILED")
		}
		mpc.logger.Debug().Msg("mpc.GeneratePartialKeyPair OK")
	}()

	err = mpc.wallets.NewWallet(id)
	if err != nil {
		return
	}

	// mpc.logger.Debug().Str("PartialPublicKey", hex.EncodeToString(mpc.wallets.GetWallet(id).PartialPublicKeyBytes())).Msg("Partial key pair generated")
	return
}

func (mpc *MPC) ExchangePartialKey(exchange *ExchangePartialKeyRequest) (resp *ExchangePartialKeyResponse, err error) {
	mpc.logger.Debug().Msg("mpc.ExchangePartialKey")
	defer func() {
		if err != nil {
			mpc.logger.Error().Err(err).Msg("mpc.ExchangePartialKey FAILED")
		}
		mpc.logger.Debug().Msg("mpc.ExchangePartialKey OK")
	}()

	mpc.peerPartialKeyCommitment[exchange.KeyID] = exchange.Commitment
	return &ExchangePartialKeyResponse{
		KeyID:     exchange.KeyID,
		PublicKey: mpc.wallets.GetWallet(exchange.KeyID).PartialPublicKeyBytes(),
	}, nil
}

func (mpc *MPC) ProvePartialKeyCommitment(proof *ProvePartialKeyCommitmentRequest) (resp *ProvePartialKeyCommitmentResponse, err error) {
	mpc.logger.Debug().Msg("mpc.ProvePartialKeyCommitment")
	defer func() {
		if err != nil {
			mpc.logger.Error().Err(err).Msg("mpc.ProvePartialKeyCommitment FAILED")
		}
		mpc.logger.Debug().Msg("mpc.ProvePartialKeyCommitment OK")
	}()

	hash := sha256.New()
	if bytes.Equal(hash.Sum(proof.Proof), mpc.peerPartialKeyCommitment[proof.KeyID]) {
		err := mpc.wallets.GetWallet(proof.KeyID).ComputeWalletPublicKey(PublicKeyFromBytes(proof.Proof))
		mpc.logger.Debug().Str("PublicKey", hex.EncodeToString(mpc.wallets.GetWallet(proof.KeyID).PublicKeyBytes())).Msg("Public Key Updated")
		if err != nil {
			return nil, err
		}
		return &ProvePartialKeyCommitmentResponse{
			KeyID:    proof.KeyID,
			Verified: true,
		}, nil
	}
	return &ProvePartialKeyCommitmentResponse{
		KeyID:    proof.KeyID,
		Verified: false,
	}, nil
}

func (mpc *MPC) ExchangeKey(exchange *ExchangeKeyRequest) (resp *ExchangeKeyResponse, err error) {
	mpc.logger.Debug().Msg("mpc.ExchangeKey")
	defer func() {
		if err != nil {
			mpc.logger.Error().Err(err).Msg("mpc.ExchangeKey FAILED")
		}
		mpc.logger.Debug().Msg("mpc.ExchangeKey OK")
	}()

	mpc.peerKeyCommitment[exchange.KeyID] = exchange.Commitment
	return &ExchangeKeyResponse{
		KeyID:     exchange.KeyID,
		PublicKey: mpc.wallets.GetWallet(exchange.KeyID).PublicKeyBytes(),
	}, nil
}

func (mpc *MPC) ProveKeyCommitment(proof *ProveKeyCommitmentRequest) (resp *ProveKeyCommitmentResponse, err error) {
	mpc.logger.Debug().Msg("mpc.ProveKeyCommitment")
	defer func() {
		if err != nil {
			mpc.logger.Error().Err(err).Msg("mpc.ProveKeyCommitment FAILED")
		}
		mpc.logger.Debug().Msg("mpc.ProveKeyCommitment OK")
	}()

	hash := sha256.New()
	if bytes.Equal(hash.Sum(proof.Proof), mpc.peerKeyCommitment[proof.KeyID]) {
		return &ProveKeyCommitmentResponse{
			KeyID:    proof.KeyID,
			Verified: true,
		}, nil
	}
	return &ProveKeyCommitmentResponse{
		KeyID:    proof.KeyID,
		Verified: false,
	}, nil
}

func (mpc *MPC) PartialPrivateKey(id string) *ecdsa.PrivateKey {
	return mpc.wallets.GetWallet(id).PartialPrivateKey()
}

func (mpc *MPC) PartialPrivateKeyBytes(id string) []byte {
	return mpc.wallets.GetWallet(id).PartialPrivateKeyBytes()
}

func (mpc *MPC) PartialPublicKey(id string) *ecdsa.PublicKey {
	return mpc.wallets.GetWallet(id).PartialPublicKey()
}

func (mpc *MPC) PartialPublicKeyBytes(id string) []byte {
	return mpc.wallets.GetWallet(id).PartialPublicKeyBytes()
}

func (mpc *MPC) PartyPaillerPublicKey() *paillier.PublicKey {
	return mpc.paillierPk.Pk
}

func (mpc *MPC) ComputePublicKey(id string, p2Key *ecdsa.PublicKey) {
	mpc.wallets.GetWallet(id).ComputeWalletPublicKey(p2Key)
}

func (mpc *MPC) ComputePrivateKey(id string, p2Key *ecdsa.PrivateKey) {
	mpc.wallets.GetWallet(id).ComputePrivateKey(p2Key)
}

func (mpc *MPC) PrivateKey(id string) *ecdsa.PrivateKey {
	return mpc.wallets.GetWallet(id).PrivateKey()
}

func (mpc *MPC) PublicKey(id string) *ecdsa.PublicKey {
	return mpc.wallets.GetWallet(id).PublicKey()
}

func (mpc *MPC) PublicKeyBytes(id string) []byte {
	return mpc.wallets.GetWallet(id).PublicKeyBytes()
}

func (mpc *MPC) VerifyPublicKey(id string) bool {
	return mpc.wallets.GetWallet(id).VerifyPublicKey()
}

func (mpc *MPC) EncryptPrivKey(id string) (paillier.Ciphertext, error) {
	keybytes := mpc.wallets.GetWallet(id).PartialPrivateKey().D
	encrypted_d, _, err := mpc.paillierPk.Pk.Encrypt(keybytes)
	return encrypted_d, err
}

func (mpc *MPC) InitSignator() {
	mpc.signator = NewSignator(mpc.peer, mpc.paillierPk, &mpc.wallets)
}

func (mpc *MPC) Sign(digest []byte, keyID string) ([]byte, []byte, error) {
	return mpc.signator.Sign(digest, keyID)
}

func (mpc *MPC) SignASN1(digest []byte, keyID string) ([]byte, error) {
	return mpc.signator.SignASN1(digest, keyID)
}

func (mpc *MPC) Verify(digest []byte, sig_R, sig_S []byte, keyID string) bool {
	return mpc.signator.Verify(digest, sig_R, sig_S, keyID)
}

func (mpc *MPC) VerifyASN1(digest []byte, sig []byte, keyID string) bool {
	return mpc.signator.VerifyASN1(digest, sig, keyID)
}

func (mpc *MPC) GenerateSigantureR(request *GenerateSigRRequest) (*GenerateSigRResponse, error) {
	r, err := mpc.signator.generateSigantureR(request.SigID, request.KeyID, UnmarshalR(request.R))
	if err != nil {
		return nil, err
	}
	return &GenerateSigRResponse{
		SigID: request.SigID,
		KeyID: request.KeyID,
		R:     r.Bytes(),
	}, nil
}

func (mpc *MPC) GeneratePartialSignatureS(request *GeneratePartialSignatureSRequest) (*GeneratePartialSignatureSResponse, error) {
	pk := &paillier.PublicKey{}
	pk.UnmarshalJSON(request.PK)

	var S *big.Int
	S, err := mpc.signator.generateSignaturePartialS(
		request.SigID,
		request.KeyID,
		request.D,
		pk,
		request.Digest,
	)
	if err != nil {
		return nil, err
	}

	return &GeneratePartialSignatureSResponse{
		SigID: request.SigID,
		KeyID: request.KeyID,
		S:     S.Bytes(),
	}, nil
}
