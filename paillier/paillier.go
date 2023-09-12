package homomorphic

import (
	"os"

	"github.com/coinbase/kryptology/pkg/paillier"
)

type PaillierKey struct {
	Pk *paillier.PublicKey
	Sk *paillier.SecretKey
}

func CreatePaillierKeypair() (*PaillierKey, error) {
	pkjson, err := os.ReadFile("pk.json")
	if err != nil {
		panic(err)
	}
	pk := new(paillier.PublicKey)
	err = pk.UnmarshalJSON(pkjson)
	if err != nil {
		panic(err)
	}

	skjson, err := os.ReadFile("sk.json")
	if err != nil {
		panic(err)
	}
	sk := new(paillier.SecretKey)
	err = sk.UnmarshalJSON(skjson)
	if err != nil {
		panic(err)
	}

	return &PaillierKey{
		Pk: pk,
		Sk: sk,
	}, err
}
