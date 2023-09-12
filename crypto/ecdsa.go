package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

type EcdsaKey struct {
	privKey *ecdsa.PrivateKey
	curve elliptic.Curve
}

func NewEcdsaKey(curve elliptic.Curve) *EcdsaKey {
	return &EcdsaKey{
		curve: curve,
	}
}

func (k *EcdsaKey) GenerateKeyPair() (error) {
	// generate random number as private key
	d, err := ecdsa.GenerateKey(k.curve, rand.Reader)
	if err != nil {
		return err
	}
	k.privKey = d

	// // compute public key from private key; Q = Mod(d * G, N)
	// d.D = d.D.Mod(d.D, k.curve.Params().N)
	// k.pubKey = &d.PublicKey

	return nil
}

func (k *EcdsaKey) PrivateKey() *ecdsa.PrivateKey {
	return k.privKey
}

func (k *EcdsaKey) PublicKey() *ecdsa.PublicKey {
	return &k.privKey.PublicKey
}

// func EcdsaSign(msg []byte, d *ecdsa.PrivateKey, Q *ecdsa.PublicKey) {
// 	k, err := getRandomNumber(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		panic(err)
// 	}
// 	Rx, Ry := elliptic.P256().ScalarBaseMult(k.Bytes())
// 	R := ecdsa.PublicKey{Curve: elliptic.P256(), X: Rx, Y: Ry}
// 	r := R.X.Mod(R.X, elliptic.P256().Params().N)

// 	rd := big.NewInt(1).Mul(r, d.D)

// 	e := sha256.Sum256(msg)
// 	ebn := new(big.Int).SetBytes(e[:])

// 	kInverse := k.ModInverse(k, elliptic.P256().Params().N)

// 	erd := big.NewInt(1).Add(ebn, rd)

// 	s := big.NewInt(1).Mul(kInverse, erd)
// 	s = big.NewInt(1).Mod(s, elliptic.P256().Params().N)
// 	fmt.Printf("s: %x\n", s)
// 	fmt.Printf("r: %x\n", r)

// 	// convert [32]byte to []byte
// 	var eb []byte
// 	for _, b := range e {
// 		eb = append(eb, b)
// 	}

// 	v := ecdsa.Verify(Q, eb, r, s)
// 	fmt.Printf("v: %v\n", v)
// }