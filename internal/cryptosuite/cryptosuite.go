package cryptosuite

type Cryptosuite interface {
	GenerateKeyPair() (Key, error)
}