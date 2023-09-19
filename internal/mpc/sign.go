package mpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/google/uuid"
	homomorphic "github.com/hnamzian/yehuda-mpc/internal/paillier"
	"github.com/hnamzian/yehuda-mpc/internal/random"
)

type ECDSASignautre struct {
	R, S *big.Int
}

type SignatureR ecdsa.PublicKey

func (R *SignatureR) Marshal() []byte {
	return elliptic.Marshal(elliptic.P256(), R.X, R.Y)
}
func UnmarshalR(data []byte) *SignatureR {
	x, y := elliptic.Unmarshal(elliptic.P256(), data)
	return &SignatureR{Curve: elliptic.P256(), X: x, Y: y}
}

type Signature struct {
	keyID string
	_R    *SignatureR
	_r    *big.Int
	my_k  *big.Int
	my_R  *SignatureR
	my_r  *big.Int
}
type Signatures map[string]*Signature

type Signator struct {
	peer       Peer
	wallets    *Wallets
	signatures Signatures
	paillierPk *homomorphic.PaillierKey
}

func NewSignator(peer Peer, paillierPK *homomorphic.PaillierKey, wallets *Wallets) Signator {
	return Signator{
		peer:       peer,
		signatures: make(Signatures),
		wallets:    wallets,
		paillierPk: paillierPK,
	}
}

func (s *Signator) Sign(digest []byte, keyID string) ([]byte, []byte, error) {
	sigID := uuid.New().String()
	if err := s.GenerateR(sigID, keyID); err != nil {
		return nil, nil, err
	}

	// compute partial S by Peer
	d := s.wallets.GetWallet(keyID).partialKey.D
	var d_encbigint *big.Int
	d_encbigint, _, err := s.paillierPk.Pk.Encrypt(d)
	if err != nil {
		return nil, nil, err
	}
	pk_bytes, err := s.paillierPk.Pk.MarshalJSON()
	if err != nil {
		return nil, nil, err
	}
	resp, err := s.peer.GeneratePartialSignatureS(&GeneratePartialSignatureSRequest{
		SigID:  sigID,
		KeyID:  keyID,
		D:      d_encbigint.Bytes(),
		PK:     pk_bytes,
		Digest: digest,
	})

	// compute signature S
	partial_s := new(big.Int).SetBytes(resp.S)
	sig_R, sig_S, err := s.computeSignature(sigID, keyID, partial_s)
	if err != nil {
		return nil, nil, err
	}

	verified := ecdsa.Verify(s.wallets.GetWallet(keyID).publicKey, digest, sig_R, sig_S)
	fmt.Printf("verified: %v\n", verified)

	return sig_R.Bytes(), sig_S.Bytes(), err
}

func (s *Signator) SignASN1(digest []byte, keyID string) ([]byte, error) {
	sig_r, sig_s, err := s.Sign(digest, keyID)
	if err != nil {
		return nil, err
	}
	sig := ECDSASignautre{
		R: new(big.Int).SetBytes(sig_r),
		S: new(big.Int).SetBytes(sig_s),
	}
	return asn1.Marshal(sig)
}

func (s *Signator) Verify(digest []byte, sig_R, sig_S []byte, keyID string) bool {
	verified := ecdsa.Verify(s.wallets.GetWallet(keyID).publicKey, digest, new(big.Int).SetBytes(sig_R), new(big.Int).SetBytes(sig_S))
	return verified
}

func (s *Signator) VerifyASN1(digest []byte, signature []byte, keyID string) bool {
	verified := ecdsa.VerifyASN1(s.wallets.GetWallet(keyID).publicKey, digest, signature)
	return verified
}

func (s *Signator) GenerateR(sigID, keyID string) error {
	// generate random k1 and
	// generate partial R; R1 = k1*G
	if err := s.generatePartialR(sigID, keyID); err != nil {
		return err
	}

	// send R1 to Party2 to generate R = k2*R1
	resp, err := s.peer.GenerateSigantureR(&GenerateSigRRequest{
		SigID: sigID,
		KeyID: keyID,
		R:     s.signatures[sigID].my_R.Marshal(),
	})
	if err != nil {
		return err
	}
	s.signatures[sigID]._r = new(big.Int).SetBytes(resp.R)

	return nil
}

func (s *Signator) generatePartialR(sigID, keyID string) error {
	my_k, err := random.GetRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	Rx, Ry := elliptic.P256().ScalarBaseMult(my_k.Bytes())

	my_R := &SignatureR{Curve: elliptic.P256(), X: Rx, Y: Ry}

	sig := &Signature{
		keyID: keyID,
		my_k:  my_k,
		my_R:  my_R,
	}

	s.signatures[sigID] = sig

	return nil
}

func (s *Signator) generateSigantureR(sigID, keyID string, R1 *SignatureR) (*big.Int, error) {
	my_k, err := random.GetRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	Rx, Ry := elliptic.P256().ScalarMult(R1.X, R1.Y, my_k.Bytes())
	R := &SignatureR{Curve: elliptic.P256(), X: Rx, Y: Ry}
	r := R.X.Mod(R.X, elliptic.P256().Params().N)

	s.signatures[sigID] = &Signature{
		keyID: keyID,
		my_k:  my_k,
		_R:    R,
		_r:    r,
	}
	return s.signatures[sigID]._r, nil
}

func (s *Signator) generateSignaturePartialS(sigID, keyID string, peer_d_encbytes []byte, pk *paillier.PublicKey, digest []byte) (paillier.Ciphertext, error) {
	// compute my encrypted private key by Party2 Paillier Public Key
	// convert []byte to *big.Int
	peer_d_encrypted := new(big.Int).SetBytes(peer_d_encbytes)

	// Calculate Encrypted Private Key Enc(d) = Enc(d1) + Enc(d2)
	my_d_encrypted, _, err := pk.Encrypt(s.wallets.GetWallet(keyID).partialKey.D)
	if err != nil {
		return nil, err
	}
	d_encrypted, err := pk.Add(peer_d_encrypted, my_d_encrypted)
	if err != nil {
		return nil, err
	}

	// Calculate Enc(r.d) = Enc(r) * Enc(d)
	rd_encrypted, err := pk.Mul(s.signatures[sigID]._r, d_encrypted)
	if err != nil {
		return nil, err
	}

	// Encrypt hash of the message Enc(h) with pk1
	digest_bign := new(big.Int).SetBytes(digest[:])
	digest_encrypted, _, err := pk.Encrypt(digest_bign)
	if err != nil {
		return nil, err
	}

	// Calculate Enc(h+r.d) = Enc(h) * Enc(r.d)
	hrd_encrypted, err := pk.Add(digest_encrypted, rd_encrypted)
	if err != nil {
		return nil, err
	}

	// Calculate k2^-1
	k1_inv := s.signatures[sigID].my_k.ModInverse(s.signatures[sigID].my_k, elliptic.P256().Params().N)

	// 21. Calculate Enc(k2^-1 * (h+r.d)) = Enc(k2^-1) * Enc(h+r.d)
	s1_encrypted, err := pk.Mul(k1_inv, hrd_encrypted)
	if err != nil {
		return nil, err
	}

	return s1_encrypted, nil
}

func (s *Signator) computeSignature(sigID, keyID string, s2_encrypted paillier.Ciphertext) (*big.Int, *big.Int, error) {
	// 22. Decrypt Encrypted partial signature s2
	s2, err := s.paillierPk.Sk.Decrypt(s2_encrypted)
	if err != nil {
		return nil, nil, err
	}

	// Calculate k1^-1
	k1_inv := s.signatures[sigID].my_k.ModInverse(s.signatures[sigID].my_k, elliptic.P256().Params().N)

	// Calculate s = k1^-1 * s2
	sig_s := new(big.Int).Mul(k1_inv, s2)
	sig_s = sig_s.Mod(sig_s, elliptic.P256().Params().N)

	return s.signatures[sigID]._r, sig_s, nil
}
