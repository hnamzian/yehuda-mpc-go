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
	sig                      *Signature
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

	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Exchanging Partial Key Commitment")
	hash := sha256.New()
	resp, err := mpc.peer.ExchangePartialKey(&ExchangePartialKeyRequest{
		KeyID:      id,
		Commitment: hash.Sum(mpc.wallets.GetWallet(id).PartialPublicKeyBytes()),
	})
	if err != nil {
		return err
	}
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Partial Key Commitment Exchanged")

	peerPubKey := PublicKeyFromBytes(resp.PublicKey)
	mpc.wallets.GetWallet(id).ComputeWalletPublicKey(peerPubKey)
	mpc.logger.Debug().Str("MPC", mpc.name).Str("PublicKey", hex.EncodeToString(mpc.wallets.GetWallet(id).PublicKeyBytes())).Msg("Public Key Updated")

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
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Partial Key Commitment Verified")

	fmt.Printf("hash1: %s", hex.EncodeToString(hash.Sum(mpc.wallets.GetWallet(id).PublicKeyBytes())))
	_, err = mpc.peer.ExchangeKey(&ExchangeKeyRequest{
		KeyID:      id,
		Commitment: hash.Sum(mpc.wallets.GetWallet(id).PublicKeyBytes()),
	})
	if err != nil {
		return err
	}
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Public Key Exchanged")

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
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Public Key Commitment Verified")

	return nil
}

func (mpc *MPC) GeneratePartialKeyPair(id string) error {
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Generating partial key pair")

	err := mpc.wallets.NewWallet(id)
	if err != nil {
		return err
	}

	mpc.logger.Debug().Str("MPC", mpc.name).Str("PartialPublicKey", hex.EncodeToString(mpc.wallets.GetWallet(id).PartialPublicKeyBytes())).Msg("Partial key pair generated")
	return nil
}

func (mpc *MPC) ExchangePartialKey(exchange *ExchangePartialKeyRequest) (*ExchangePartialKeyResponse, error) {
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Exchanging Partial Key Commitment")
	defer mpc.logger.Debug().Str("MPC", mpc.name).Msg("Partial Key Commitment Exchanged")

	mpc.peerPartialKeyCommitment[exchange.KeyID] = exchange.Commitment
	return &ExchangePartialKeyResponse{
		KeyID:     exchange.KeyID,
		PublicKey: mpc.wallets.GetWallet(exchange.KeyID).PartialPublicKeyBytes(),
	}, nil
}

func (mpc *MPC) ProvePartialKeyCommitment(proof *ProvePartialKeyCommitmentRequest) (*ProvePartialKeyCommitmentResponse, error) {
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Verifying Partial Key Commitment")
	defer mpc.logger.Debug().Str("MPC", mpc.name).Msg("Partial Key Commitment Verified")

	hash := sha256.New()
	if bytes.Equal(hash.Sum(proof.Proof), mpc.peerPartialKeyCommitment[proof.KeyID]) {
		err := mpc.wallets.GetWallet(proof.KeyID).ComputeWalletPublicKey(PublicKeyFromBytes(proof.Proof))
		mpc.logger.Debug().Str("MPC", mpc.name).Str("PublicKey", hex.EncodeToString(mpc.wallets.GetWallet(proof.KeyID).PublicKeyBytes())).Msg("Public Key Updated")
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

func (mpc *MPC) ExchangeKey(exchange *ExchangeKeyRequest) (*ExchangeKeyResponse, error) {
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Exchanging Public Key Commitment")
	defer mpc.logger.Debug().Str("MPC", mpc.name).Msg("Public Key Commitment Exchanged")

	mpc.peerKeyCommitment[exchange.KeyID] = exchange.Commitment
	return &ExchangeKeyResponse{
		KeyID:     exchange.KeyID,
		PublicKey: mpc.wallets.GetWallet(exchange.KeyID).PublicKeyBytes(),
	}, nil
}

func (mpc *MPC) ProveKeyCommitment(proof *ProveKeyCommitmentRequest) (*ProveKeyCommitmentResponse, error) {
	mpc.logger.Debug().Str("MPC", mpc.name).Msg("Verifying Public Key Commitment")
	defer mpc.logger.Debug().Str("MPC", mpc.name).Msg("Public Key Commitment verified")
	
	
	hash := sha256.New()
	fmt.Printf("hash2: %s", hex.EncodeToString(hash.Sum(proof.Proof)))
	
	if bytes.Equal(hash.Sum(proof.Proof), mpc.peerKeyCommitment[proof.KeyID]) {
		fmt.Printf("00000000000000000000000")
		
		return &ProveKeyCommitmentResponse{
			KeyID:    proof.KeyID,
			Verified: true,
		}, nil
	}
	fmt.Printf("11111111111111111111111")
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

func (mpc *MPC) InitSignature() {
	mpc.sig = InitSignature()
}

func (mpc *MPC) GetSignature() *Signature {
	return mpc.sig
}

func (mpc *MPC) ComputeSigpartialS(id string, d2_encrypted paillier.Ciphertext, pk2 *paillier.PublicKey, digest []byte) (paillier.Ciphertext, error) {
	w := mpc.wallets.GetWallet(id)
	return mpc.sig.computeSigPartialS(w.PartialPrivateKey(), d2_encrypted, pk2, digest)
}

func (mpc *MPC) ComputeSignature(s2_encrypted paillier.Ciphertext) (*big.Int, *big.Int, error) {
	return mpc.sig.computeSignature(mpc.paillierPk.Sk, s2_encrypted)
}

// func (mpc *MPC) ComputeK(k2 *big.Int) {
// 	p.sig.ComputeK(k2)
// }

func (mpc *MPC) ComputeR(R2 *R) {
	mpc.sig.ComputeR(R2)
}
