package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/hnamzian/yehuda-mpc/internal/logger"
	"github.com/hnamzian/yehuda-mpc/internal/mpc"
)

var msg = []byte("Hello, world!")

// func UnsafeMPCSign(msg []byte, p1, p2 *mpc.MPC, kid1, kid2 string) {
// 	p1.InitSignature()
// 	k1 := p1.GetSignature().GetMyk()
// 	R1 := p1.GetSignature().GetMyR()

// 	p2.InitSignature()
// 	k2 := p2.GetSignature().GetMyk()
// 	R2 := p2.GetSignature().GetMyR()

// 	p1.ComputeR(R2)
// 	// R := p1.GetSignature().GetR()

// 	p2.ComputeR(R1)
// 	// R = p2.GetSignature().GetR()

// 	r := p1.GetSignature().Getr()
// 	// r := R2.X.Mod(&R.X, elliptic.P256().Params().N)

// 	rd := big.NewInt(1).Mul(r, p1.PrivateKey(kid1).D)

// 	e := sha256.Sum256(msg)
// 	ebn := new(big.Int).SetBytes(e[:])

// 	k2Inverse := k2.ModInverse(k2, elliptic.P256().Params().N)
// 	k1Inverse := k1.ModInverse(k1, elliptic.P256().Params().N)
// 	// kInverse := new(big.Int).Mul(k1Inverse, k2Inverse)

// 	erd := big.NewInt(1).Add(ebn, rd)
// 	k2erd := big.NewInt(1).Mul(k2Inverse, erd)
// 	s := big.NewInt(1).Mul(k1Inverse, k2erd)
// 	s = s.Mod(s, elliptic.P256().Params().N)

// 	fmt.Printf("s: %x\n", s)
// 	fmt.Printf("r: %x\n", r)

// 	var eb []byte
// 	for _, b := range e {
// 		eb = append(eb, b)
// 	}

// 	v := ecdsa.Verify(p1.PublicKey(kid1), eb, r, s)
// 	fmt.Printf("v: %v\n", v)
// }

type ECDSASignautre struct {
	R, S *big.Int
}

func main() {
	logger := logger.NewLogger(logger.LoggerConfig{
		Level: "debug",
	})

	logger.Info().Msg("1a. Party1 initialized")
	p1 := mpc.NewMPC("Party1", "./keys/p1", logger)
	logger.Info().Msg("1b. Party1 initialized")
	p2 := mpc.NewMPC("Party2", "./keys/p2", logger)

	p1.AddPeer(p2)
	p2.AddPeer(p1)

	p1.InitSignator()
	p2.InitSignator()

	// 2a. generate keypair for P1 (d1, Q1)
	kid1 := uuid.New().String()
	err := p1.GenerateKeyPair(kid1)
	if err != nil {
		panic(err)
	}
	logger.Info().Msg("2a. Generate Party1 Keypair")
	logger.Info().Str("Partial Private Key", hex.EncodeToString(p1.PartialPrivateKeyBytes(kid1))).Msg("Party1 Partial Private Key")
	logger.Info().Str("Partial Private Key", hex.EncodeToString(p1.PartialPublicKeyBytes(kid1))).Msg("Party1 Partial Public Key")
	logger.Info().Str("Partial Private Key", hex.EncodeToString(p1.PublicKeyBytes(kid1))).Msg("Party1 Public Key")
	logger.Info().Str("Partial Private Key", hex.EncodeToString(p2.PartialPrivateKeyBytes(kid1))).Msg("Party2 Partial Private Key")
	logger.Info().Str("Partial Private Key", hex.EncodeToString(p2.PartialPublicKeyBytes(kid1))).Msg("Party2 partial Public Key")
	logger.Info().Str("Partial Private Key", hex.EncodeToString(p1.PublicKeyBytes(kid1))).Msg("Party2 Public Key")

	h := sha256.Sum256(msg)
	sig_r, sig_s, err := p1.Sign(h[:], kid1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("r: %x\n", sig_r)
	fmt.Printf("s: %x\n", sig_s)
	verified := ecdsa.Verify(p1.PublicKey(kid1), h[:], new(big.Int).SetBytes(sig_r), new(big.Int).SetBytes(sig_s))
	fmt.Printf("verified: %v\n", verified)

	sig := ECDSASignautre{
		R: new(big.Int).SetBytes(sig_r),
		S: new(big.Int).SetBytes(sig_s),
	}
	signature, err := asn1.Marshal(sig)
	fmt.Printf("signature: %x\n", signature)

	verified = ecdsa.VerifyASN1(p1.PublicKey(kid1), h[:], signature)
	fmt.Printf("verified: %v\n", verified)

	// p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// sig, err := p.Sign(rand.Reader, msg, nil)
	// fmt.Printf("sig: %x\n", sig)
}
