package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/hnamzian/yehuda-mpc/internal/cryptosuite"
)

type EcdsaKey struct {
	cryptosuite.Key
	privKey *ecdsa.PrivateKey
}

func (ec EcdsaKey) Sign(digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, ec.privKey, digest)
}

func (ec EcdsaKey) Verify(digest []byte, sig []byte) bool {
	return ecdsa.VerifyASN1(&ec.privKey.PublicKey, digest, sig)
}

func (ec EcdsaKey) PrivateKey() []byte {
	return ec.privKey.D.Bytes()
}

func (ec EcdsaKey) PublicKey() []byte {
	return elliptic.Marshal(ec.privKey.Curve, ec.privKey.X, ec.privKey.Y)
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
