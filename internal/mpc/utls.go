package mpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
)

func PublicKeyFromBytes(b []byte) *ecdsa.PublicKey {
	pub_x, pub_y := elliptic.Unmarshal(elliptic.P256(), b)
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: pub_x, Y: pub_y}
}

func PublicKeyToBytes(pubKey *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
}