package cryptosuite

type Key interface {
	PublicKey() []byte
	PrivateKey() []byte
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) bool
}