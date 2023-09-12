package party

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/hnamzian/yehuda-mpc/random"
)

type R struct {
	X big.Int
	Y big.Int
}

type Signature struct {
	_R   *R
	_r   *big.Int
	my_k *big.Int
	my_R *R
	my_r *big.Int
}

func InitSignature() *Signature {
	my_k, my_r, my_R := generate_kr()
	return &Signature{
		my_k: my_k,
		my_r: my_r,
		my_R: my_R,
	}
}

func generate_kr() (*big.Int, *big.Int, *R) {
	// Generate a random number k1 for Party1
	k, err := random.GetRandomNumber(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// 7. Calculate R = k*G and r = R.x
	Rx, Ry := elliptic.P256().ScalarBaseMult(k.Bytes())
	Rp := ecdsa.PublicKey{Curve: elliptic.P256(), X: Rx, Y: Ry}
	r := Rp.X.Mod(Rp.X, elliptic.P256().Params().N)

	return k, r, &R{X: *Rp.X, Y: *Rp.Y}
}

func (s *Signature) GetMyk() *big.Int {
	return s.my_k
}
func (s *Signature) GetMyr() *big.Int {
	return s.my_r
}
func (s *Signature) GetMyR() *R {
	return s.my_R
}
func (s *Signature) GetR() *R {
	return s._R
}
func (s *Signature) Getr() *big.Int {
	return s._r
}
func (s *Signature) ComputeR(R2 *R) {
	Rx, Ry := elliptic.P256().ScalarMult(&R2.X, &R2.Y, s.my_k.Bytes())
	s._R = &R{X: *Rx, Y: *Ry}
	s._r = s._R.X.Mod(&s._R.X, elliptic.P256().Params().N)
}

func (s *Signature) computeSigPartialS(d1 *ecdsa.PrivateKey, d2_encrypted paillier.Ciphertext, pk2 *paillier.PublicKey, digest []byte) (paillier.Ciphertext, error) {
	// compute my encrypted private key by Party2 Paillier Public Key
	d1_encrypted, _, err := pk2.Encrypt(d1.D)
	if err != nil {
		return nil, err
	}

	// Calculate Encrypted Private Key Enc(d) = Enc(d1) + Enc(d2)
	d_encrypted, err := pk2.Add(d1_encrypted, d2_encrypted)
	if err != nil {
		return nil, err
	}

	// Calculate Enc(r.d) = Enc(r) * Enc(d)
	rd_encrypted, err := pk2.Mul(s._r, d_encrypted)
	if err != nil {
		return nil, err
	}

	// Encrypt hash of the message Enc(h) with pk1
	digest_bign := new(big.Int).SetBytes(digest[:])
	digest_encrypted, _, err := pk2.Encrypt(digest_bign)
	if err != nil {
		return nil, err
	}

	// Calculate Enc(h+r.d) = Enc(h) * Enc(r.d)
	hrd_encrypted, err := pk2.Add(digest_encrypted, rd_encrypted)
	if err != nil {
		return nil, err
	}

	// Calculate k2^-1
	k1_inv := s.my_k.ModInverse(s.my_k, elliptic.P256().Params().N)

	// 21. Calculate Enc(k2^-1 * (h+r.d)) = Enc(k2^-1) * Enc(h+r.d)
	s1_encrypted, err := pk2.Mul(k1_inv, hrd_encrypted)
	if err != nil {
		return nil, err
	}

	return s1_encrypted, nil
}

func (s *Signature) computeSignature(sk *paillier.SecretKey, s2_encrypted paillier.Ciphertext) (*big.Int, *big.Int, error) {
	// 22. Decrypt Encrypted partial signature s2
	s2, err := sk.Decrypt(s2_encrypted)
	if err != nil {
		return nil, nil, err
	}

	// Calculate k1^-1
	k1_inv := s.my_k.ModInverse(s.my_k, elliptic.P256().Params().N)

	// Calculate s = k1^-1 * s2
	sig_s := new(big.Int).Mul(k1_inv, s2)
	sig_s = sig_s.Mod(sig_s, elliptic.P256().Params().N)

	return s._r, sig_s, nil
}


