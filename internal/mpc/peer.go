package mpc

type Peer interface {
	// Connect() error
	GeneratePartialKeyPair(string) error
	ExchangePartialKey(*ExchangePartialKeyRequest) (*ExchangePartialKeyResponse, error)
	ProvePartialKeyCommitment(*ProvePartialKeyCommitmentRequest) (*ProvePartialKeyCommitmentResponse, error)
	ExchangeKey(*ExchangeKeyRequest) (*ExchangeKeyResponse, error)
	ProveKeyCommitment(*ProveKeyCommitmentRequest) (*ProveKeyCommitmentResponse, error)
	GenerateSigantureR(*GenerateSigRRequest) (*GenerateSigRResponse, error)
	GeneratePartialSignatureS(*GeneratePartialSignatureSRequest) (*GeneratePartialSignatureSResponse, error)
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

	GenerateSigRRequest struct {
		SigID string
		KeyID string
		R     []byte
	}

	GenerateSigRResponse struct {
		SigID string
		KeyID string
		R     []byte
	}

	GeneratePartialSignatureSRequest struct {
		SigID  string
		KeyID  string
		D      []byte
		PK     []byte
		Digest []byte
	}

	GeneratePartialSignatureSResponse struct {
		SigID string
		KeyID string
		S     []byte
	}
)
