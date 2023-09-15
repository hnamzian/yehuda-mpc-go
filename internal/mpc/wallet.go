package mpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type Wallet struct {
	partialKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

func (w *Wallet) PartialPublicKey() *ecdsa.PublicKey {
	return &w.partialKey.PublicKey
}
func (w *Wallet) PartialPublicKeyBytes() []byte {
	return elliptic.Marshal(w.partialKey.Curve, w.partialKey.X, w.partialKey.Y)
}
func (w *Wallet) PartialPrivateKey() *ecdsa.PrivateKey {
	return w.partialKey
}
func (w *Wallet) PartialPrivateKeyBytes() []byte {
	return w.partialKey.D.Bytes()
}
func (w *Wallet) ComputeWalletPublicKey(pubKey *ecdsa.PublicKey) error {
	Qx, Qy := elliptic.P256().Add(w.partialKey.X, w.partialKey.Y, pubKey.X, pubKey.Y)
	w.publicKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: Qx, Y: Qy}
	return nil
}
func (w *Wallet) ComputePrivateKey(privKey *ecdsa.PrivateKey) {
	D := new(big.Int).Add(w.PartialPrivateKey().D, privKey.D)
	w.privateKey = &ecdsa.PrivateKey{D: D, PublicKey: *w.publicKey}
}
func (w *Wallet) PrivateKey() *ecdsa.PrivateKey {
	return w.privateKey
}
func (w *Wallet) PublicKey() *ecdsa.PublicKey {
	return w.publicKey
}
func (w *Wallet) PublicKeyBytes() []byte {
	pubkey := w.PublicKey()
	return elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y)
}
func (w *Wallet) VerifyPublicKey() bool {
	return w.publicKey.IsOnCurve(w.publicKey.X, w.publicKey.Y)
}

type Wallets map[string]*Wallet

func (ws Wallets) NewWallet(id string) (error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ws[id] = &Wallet{
		partialKey: key,
	}
	return nil
}

func (w Wallets) GetWallet(name string) *Wallet {
	return w[name]
}
