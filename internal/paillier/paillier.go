package homomorphic

import (
	"fmt"
	"os"

	"github.com/coinbase/kryptology/pkg/paillier"
)

type PaillierKey struct {
	Pk *paillier.PublicKey `json:"pk"`
	Sk *paillier.SecretKey `json:"sk"`
}

func GeneratePaillierKey() (*paillier.PublicKey, *paillier.SecretKey, error) {
	return paillier.NewKeys()
}

func CreatePaillierKeypair(path string) (*PaillierKey, error) {
	pkjson, err := os.ReadFile(fmt.Sprintf("%s/pk.json", path))
	if err != nil {
		panic(err)
	}
	pk := new(paillier.PublicKey)
	err = pk.UnmarshalJSON(pkjson)
	if err != nil {
		panic(err)
	}

	skjson, err := os.ReadFile(fmt.Sprintf("%s/sk.json", path))
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
