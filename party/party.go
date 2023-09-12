package party

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/hnamzian/yehuda-mpc/crypto"
	homomorphic "github.com/hnamzian/yehuda-mpc/paillier"
)

type Party struct {
	ec         *crypto.EcdsaKey
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	paillierPk *homomorphic.PaillierKey
	sig        *Signature
}

func NewParty() *Party {
	pk, err := homomorphic.CreatePaillierKeypair()
	if err != nil {
		panic(err)
	}

	return &Party{
		ec:         crypto.NewEcdsaKey(elliptic.P256()),
		paillierPk: pk,
	}
}

func (p *Party) GenerateKeyPair() error {
	return p.ec.GenerateKeyPair()
}

func (p *Party) PartyPrivateKey() *ecdsa.PrivateKey {
	return p.ec.PrivateKey()
}

func (p *Party) PartyPublicKey() *ecdsa.PublicKey {
	return p.ec.PublicKey()
}

func (p *Party) PartyPaillerPublicKey() *paillier.PublicKey {
	return p.paillierPk.Pk
}

func (p *Party) ComputePublicKey(p2Key *ecdsa.PublicKey) {
	Qx, Qy := elliptic.P256().Add(p.ec.PublicKey().X, p.ec.PublicKey().Y, p2Key.X, p2Key.Y)
	p.publicKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: Qx, Y: Qy}
}

func (p *Party) ComputePrivateKey(p2Key *ecdsa.PrivateKey) {
	D := new(big.Int).Add(p.ec.PrivateKey().D, p2Key.D)
	p.privateKey = &ecdsa.PrivateKey{D: D, PublicKey: *p.publicKey}
}

func (p *Party) PrivateKey() *ecdsa.PrivateKey {
	return p.privateKey
}

func (p *Party) PublicKey() *ecdsa.PublicKey {
	return p.publicKey
}

func (p *Party) VerifyPublicKeyIsOnCurve() bool {
	return p.publicKey.IsOnCurve(p.publicKey.X, p.publicKey.Y)
}

func (p *Party) EncryptPrivKey() (paillier.Ciphertext, error) {
	encrypted_d, _, err := p.paillierPk.Pk.Encrypt(p.ec.PrivateKey().D)
	return encrypted_d, err
}

func (p *Party) InitSignature() {
	p.sig = InitSignature()
}

func (p *Party) GetSignature() *Signature {
	return p.sig
}

func (p *Party) ComputeSigpartialS(d2_encrypted paillier.Ciphertext, pk2 *paillier.PublicKey, digest []byte) (paillier.Ciphertext, error) {
	return p.sig.computeSigPartialS(p.ec.PrivateKey(), d2_encrypted, pk2, digest)
}

func (p *Party) ComputeSignature(s2_encrypted paillier.Ciphertext) (*big.Int, *big.Int, error) {
	return p.sig.computeSignature(p.paillierPk.Sk, s2_encrypted)
}


// func (p *Party) ComputeK(k2 *big.Int) {
// 	p.sig.ComputeK(k2)
// }

func (p *Party) ComputeR(R2 *R) {
	p.sig.ComputeR(R2)
}
