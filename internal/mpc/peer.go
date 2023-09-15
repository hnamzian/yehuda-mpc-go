package mpc

type Peer interface {
	// Connect() error
	GeneratePartialKeyPair(string) error
	ExchangePartialKey(*ExchangePartialKeyRequest) (*ExchangePartialKeyResponse, error)
	ProvePartialKeyCommitment(*ProvePartialKeyCommitmentRequest) (*ProvePartialKeyCommitmentResponse, error)
	ExchangeKey(*ExchangeKeyRequest) (*ExchangeKeyResponse, error)
	ProveKeyCommitment(*ProveKeyCommitmentRequest) (*ProveKeyCommitmentResponse, error)
}

type (
	ExchangePartialKeyRequest struct {
		KeyID      string
		Commitment []byte
	}

	ExchangePartialKeyResponse struct {
		KeyID     string
		PublicKey []byte
	}

	ProvePartialKeyCommitmentRequest struct {
		KeyID string
		Proof []byte
	}

	ProvePartialKeyCommitmentResponse struct {
		KeyID    string
		Verified bool
	}

	ExchangeKeyRequest struct {
		KeyID      string
		Commitment []byte
	}

	ExchangeKeyResponse struct {
		KeyID     string
		PublicKey []byte
	}

	ProveKeyCommitmentRequest struct {
		KeyID string
		Proof []byte
	}

	ProveKeyCommitmentResponse struct {
		KeyID    string
		Verified bool
	}
)

