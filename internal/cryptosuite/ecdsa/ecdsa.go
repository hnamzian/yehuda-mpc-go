package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/hnamzian/yehuda-mpc/internal/cryptosuite"
)

type Ecdsa struct {
	cryptosuite.Cryptosuite
	curve elliptic.Curve
}

func NewEcdsa(curve elliptic.Curve) Ecdsa {
	return Ecdsa{
		curve: curve,
	}
}

func (e Ecdsa) GenerateKeyPair() (cryptosuite.Key, error) {
	d, err := ecdsa.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return EcdsaKey{privKey: d}, nil
}
