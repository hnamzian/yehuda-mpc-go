package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/coinbase/kryptology/pkg/paillier"
)

var one = new(big.Int).SetInt64(1)
var msg = []byte("Hello, world!")

func GeneratePrivateKey() (*ecdsa.PrivateKey, ecdsa.PublicKey) {
	d, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	d.D = d.D.Mod(d.D, elliptic.P256().Params().N)
	Q := d.PublicKey

	return d, Q
}

func CreatePaillierKeypair() (*paillier.PublicKey, *paillier.SecretKey, error) {
	// pk, sk, err := paillier.NewKeys()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("pk: %x\n", pk)
	// fmt.Printf("sk: %x\n", sk)

	// pkb, err := pk.MarshalJSON()
	// if err != nil {
	// 	panic(err)
	// }
	// os.WriteFile("pk.json", pkb, 0644)

	// skb, err := sk.MarshalJSON()
	// if err != nil {
	// 	panic(err)
	// }
	// os.WriteFile("sk.json", skb, 0644)

	pkjson, err := os.ReadFile("pk.json")
	if err != nil {
		panic(err)
	}
	pk := new(paillier.PublicKey)
	err = pk.UnmarshalJSON(pkjson)
	if err != nil {
		panic(err)
	}
	fmt.Printf("pk: %x\n", pk)

	skjson, err := os.ReadFile("sk.json")
	if err != nil {
		panic(err)
	}
	sk := new(paillier.SecretKey)
	err = sk.UnmarshalJSON(skjson)
	if err != nil {
		panic(err)
	}
	fmt.Printf("sk: %x\n", sk)

	// c1, _, err := pk.Encrypt(big.NewInt(1))
	// c2, _, err := pk.Encrypt(big.NewInt(1))
	// c3, err := pk.Add(c1, c2)
	// d, err := sk.Decrypt(c3)
	// fmt.Printf("c1: %x\n", d)

	return pk, sk, err
}

func EcdsaSign(msg []byte, d *ecdsa.PrivateKey, Q *ecdsa.PublicKey) {
	k, err := getRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	Rx, Ry := elliptic.P256().ScalarBaseMult(k.Bytes())
	R := ecdsa.PublicKey{Curve: elliptic.P256(), X: Rx, Y: Ry}
	r := R.X.Mod(R.X, elliptic.P256().Params().N)

	rd := big.NewInt(1).Mul(r, d.D)

	e := sha256.Sum256(msg)
	ebn := new(big.Int).SetBytes(e[:])

	kInverse := k.ModInverse(k, elliptic.P256().Params().N)

	erd := big.NewInt(1).Add(ebn, rd)

	s := big.NewInt(1).Mul(kInverse, erd)
	s = big.NewInt(1).Mod(s, elliptic.P256().Params().N)
	fmt.Printf("s: %x\n", s)
	fmt.Printf("r: %x\n", r)

	// convert [32]byte to []byte
	var eb []byte
	for _, b := range e {
		eb = append(eb, b)
	}

	v := ecdsa.Verify(Q, eb, r, s)
	fmt.Printf("v: %v\n", v)
}
func UnsafeMPCSign(msg []byte, d1, d2, d *ecdsa.PrivateKey, Q1, Q2, Q *ecdsa.PublicKey) {
	k1, err := getRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	k2, err := getRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	R2x, R2y := elliptic.P256().ScalarBaseMult(k2.Bytes())
	R2 := ecdsa.PublicKey{Curve: elliptic.P256(), X: R2x, Y: R2y}
	// r2 := R2.X.Mod(R1.X, elliptic.P256().Params().N)

	Rx, Ry := elliptic.P256().ScalarMult(R2.X, R2.Y, k1.Bytes())
	R := ecdsa.PublicKey{Curve: elliptic.P256(), X: Rx, Y: Ry}
	r := R2.X.Mod(R.X, elliptic.P256().Params().N)

	rd := big.NewInt(1).Mul(r, big.NewInt(0).Add(d1.D, d2.D))

	e := sha256.Sum256(msg)
	ebn := new(big.Int).SetBytes(e[:])

	k2Inverse := k2.ModInverse(k2, elliptic.P256().Params().N)
	k1Inverse := k1.ModInverse(k1, elliptic.P256().Params().N)
	// kInverse := new(big.Int).Mul(k1Inverse, k2Inverse)

	erd := big.NewInt(1).Add(ebn, rd)
	k2erd := big.NewInt(1).Mul(k2Inverse, erd)
	s := big.NewInt(1).Mul(k1Inverse, k2erd)
	s = s.Mod(s, elliptic.P256().Params().N)

	fmt.Printf("s: %x\n", s)
	fmt.Printf("r: %x\n", r)

	var eb []byte
	for _, b := range e {
		eb = append(eb, b)
	}

	v := ecdsa.Verify(Q, eb, r, s)
	fmt.Printf("v: %v\n", v)
}

func main() {
	// 1. generate keypair for P1 (d1, Q1)
	d1, Q1 := GeneratePrivateKey()
	fmt.Println("1. Generate Party1 Keypair")
	fmt.Printf("d1: %x\n", d1.D)
	fmt.Printf("Q1: %x\n", Q1)

	// 2. generate keypair for P2 (d2, Q2)
	d2, Q2 := GeneratePrivateKey()
	fmt.Println("\n2. Generate Party2 Keypair")
	fmt.Printf("d2: %x\n", d2.D)
	fmt.Printf("Q2: %x\n", Q2)

	// 3. Calculate the keypair (d, Q) = (d1+d2, Q1+Q2)
	D := new(big.Int).Add(d1.D, d2.D)
	d := &ecdsa.PrivateKey{D: D, PublicKey: Q1}
	Qx, Qy := elliptic.P256().Add(Q1.X, Q1.Y, Q2.X, Q2.Y)
	Q := ecdsa.PublicKey{Curve: elliptic.P256(), X: Qx, Y: Qy}
	fmt.Println("\n3. Calculate the keypair (d, Q) = (d1+d2, Q1+Q2)")
	fmt.Printf("d: %x\n", d.D)
	fmt.Printf("Q: %x\n", Q)

	// 4. Verify that Q = d*G
	if !Q.Curve.IsOnCurve(Q.X, Q.Y) {
		panic("invalid public key")
	}
	fmt.Println("\n4. Verify that Q = d*G: OK")

	// 5. Sign a message with d and Verify the signature with Q
	sig_r, sig_s, err := ecdsa.Sign(rand.Reader, d, msg)
	if err != nil {
		panic(err)
	}
	v := ecdsa.Verify(&Q, msg, sig_r, sig_s)
	fmt.Printf("\n5. Sign a message with d and Verify the signature with Q: %v\n", v)

	// 6. Generate a random number k1 for Party1
	k1, err := getRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n6. Generate a random number k1 for Party1: %x\n", k1)

	// 7. Calculate R = k1*G and r = R.x
	R1x, R1y := elliptic.P256().ScalarBaseMult(k1.Bytes())
	R1 := ecdsa.PublicKey{Curve: elliptic.P256(), X: R1x, Y: R1y}
	r1 := R1.X.Mod(R1.X, elliptic.P256().Params().N)
	fmt.Printf("\n7. Calculate R = k1*G and r = R.x: %x\n", r1)

	// 8. Generate a random number k2 for Party2
	k2, err := getRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n8. Generate a random number k2 for Party2: %x\n", k2)

	// 9. Calculate R = k2*G and r = R.x
	R2x, R2y := elliptic.P256().ScalarBaseMult(k2.Bytes())
	R2 := ecdsa.PublicKey{Curve: elliptic.P256(), X: R2x, Y: R2y}
	r2 := R2.X.Mod(R2.X, elliptic.P256().Params().N)
	fmt.Printf("\n9. Calculate R2 = k2*G and r2 = R2.x: %x\n", r2)

	// 10. Assume k=k1.k2
	k := new(big.Int).Mul(k1, k2)
	fmt.Printf("\n10. Assume k=k1.k2: %x\n", k)

	// 11. Calculate R=k1.R2 or R=k2.R1
	Rx, Ry := elliptic.P256().ScalarMult(R2.X, R2.Y, k1.Bytes())
	R := ecdsa.PublicKey{Curve: elliptic.P256(), X: Rx, Y: Ry}
	r := R.X.Mod(R.X, elliptic.P256().Params().N)
	fmt.Printf("\n11a. Calculate R=k1.R2 or R=k2.R1: %x\n", r)

	Rx, Ry = elliptic.P256().ScalarMult(R1.X, R1.Y, k2.Bytes())
	R = ecdsa.PublicKey{Curve: elliptic.P256(), X: Rx, Y: Ry}
	r = R.X.Mod(R.X, elliptic.P256().Params().N)
	fmt.Printf("\n11b. Calculate R=k2.R1 or R=k1.R2: %x\n", r)

	// 12. Generate Paillier Keypair for Party1
	pk1, sk1, err := CreatePaillierKeypair()
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n12. Generate Paillier Keypair for Party1\n")

	// 13. Encrypt d1 with pk1
	enc_d1, _, err := pk1.Encrypt(d1.D)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n13. Encrypt d1 with pk1 Enc(r.d1): %v\n", enc_d1)

	// 14. Calculate Enc(d2)
	enc_d2, _, err := pk1.Encrypt(d2.D)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n14. Calculate Enc(d2): %v\n", enc_d2)

	// 15. Calculate Enc(d) = Enc(d1) + Enc(d2)
	enc_d, err := pk1.Add(enc_d1, enc_d2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n15. Calculate Enc(d) = Enc(d1) + Enc(d2): %v\n", enc_d)

	// 16. Calculate Enc(r.d) = Enc(r) * Enc(d)
	enc_rd, err := pk1.Mul(r, enc_d)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n16. Calculate Enc(r.d) = Enc(r) * Enc(d): %v\n", enc_rd)

	// 17. Calculate hash of the message
	h := sha256.Sum256(msg)
	fmt.Printf("\n17. Calculate SHA256 Hash of the message: %x\n", h)

	// 18. Encrypt hash of the message Enc(h) with pk1
	hbn := new(big.Int).SetBytes(h[:])
	enc_h, _, err := pk1.Encrypt(hbn)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n18. Encrypt hash of the message Enc(h) with pk1: %v\n", enc_h)

	// 19. Calculate Enc(h+r.d) = Enc(h) * Enc(r.d)
	enc_hrd, err := pk1.Add(enc_h, enc_rd)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n19. Calculate Enc(h+r.d) = Enc(h) * Enc(r.d): %v\n", enc_hrd)

	// 20. Calculate k2^-1
	k2Inverse := k2.ModInverse(k2, elliptic.P256().Params().N)
	fmt.Printf("\n20. Calculate k2^-1: %x\n", k2Inverse)

	// 21. Calculate Enc(k2^-1 * (h+r.d)) = Enc(k2^-1) * Enc(h+r.d)
	enc_s2, err := pk1.Mul(k2Inverse, enc_hrd)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n21. Calculate Enc(k2^-1 * (h+r.d)) = Enc(k2^-1) * Enc(h+r.d): %v\n", enc_s2)

	// 22. Decrypt Encrypted partial signature s2
	s2, err := sk1.Decrypt(enc_s2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n22. Decrypt Encrypted partial signature s2: %x\n", s2)

	// 23. Calculate k1^-1
	k1Inv := k1.ModInverse(k1, elliptic.P256().Params().N)
	fmt.Printf("\n23. Calculate k1^-1: %x\n", k1Inv)

	// 24. Calculate s = k1^-1 * s2
	s := new(big.Int).Mul(k1Inv, s2)
	s = s.Mod(s, elliptic.P256().Params().N)
	fmt.Printf("\n24. Calculate s = k1^-1 * s2: %x\n", s)

	// 25. Verify the signature
	var eb []byte
	for _, b := range h {
		eb = append(eb, b)
	}
	v = ecdsa.Verify(&Q, eb, r, s)
	fmt.Printf("\n25. Verify the signature: %v\n", v)

}

func getRandomNumber(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	// Note that for P-521 this will actually be 63 bits more than the order, as
	// division rounds down, but the extra bit is inconsequential.
	b := make([]byte, params.N.BitLen()/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func writeBigIntToFile(filename string, num *big.Int) error {
	// Convert the big integer to a byte slice
	data := num.Bytes()

	// Write the byte slice to the file
	return ioutil.WriteFile(filename, data, 0644)
}

func readBigIntFromFile(filename string) (*big.Int, error) {
	// Read the byte slice from the file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Convert the byte slice back to a big integer
	loadedBigInt := new(big.Int).SetBytes(data)
	return loadedBigInt, nil
}
