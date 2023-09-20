package logger

import (
	"context"

	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/application"
	"github.com/rs/zerolog"
)

type Application struct {
	app    application.App
	logger zerolog.Logger
}

func NewApplication(app application.App, logger zerolog.Logger) Application {
	return Application{app: app, logger: logger}
}

func (a Application) GetWallet(ctx context.Context, get *application.GetWalletRequest) (get_resp *application.GetWalletResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.GetWallet")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.GetWallet")
		} else {
			a.logger.Info().Msg("<-- MPCService.GetWallet")
		}
	}()
	return a.app.GetWallet(ctx, get)
}

func (a Application) HealthCheck(ctx context.Context, health *application.HealthCheckRequest) (health_rsp *application.HealthCheckResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.HealthCheck")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.HealthCheck")
		} else {
			a.logger.Info().Msg("<-- MPCService.HealthCheck")
		}
	}()
	return a.app.HealthCheck(ctx, health)
}

func (a Application) GenerateKeyPair(ctx context.Context, generate *application.GenerateKeyPairRequest) (key *application.GenerateKeyPairResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.GenerateKeyPair")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.GenerateKeyPair")
		} else {
			a.logger.Info().Msg("<-- MPCService.GenerateKeyPair")
		}
	}()
	return a.app.GenerateKeyPair(ctx, generate)
}

func (a Application) GeneratePartialKey(ctx context.Context, generate *application.GeneratePartialKeyRequest) (key *application.GeneratePartialKeyResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.GeneratePartialKey")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.GeneratePartialKey")
		} else {
			a.logger.Info().Msg("<-- MPCService.GeneratePartialKey")
		}
	}()
	return a.app.GeneratePartialKey(ctx, generate)
}

func (a Application) ExchangePartialKey(ctx context.Context, exchange *application.ExchangePartialKeyRequest) (exchange_resp *application.ExchangePartialKeyResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.ExchangePartialKey")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.ExchangePartialKey")
		} else {
			a.logger.Info().Msg("<-- MPCService.ExchangePartialKey")
		}
	}()
	return a.app.ExchangePartialKey(ctx, exchange)
}

func (a Application) ProvePartialKeyCommitment(ctx context.Context, prove *application.ProvePartialKeyCommitmentRequest) (proof_resp *application.ProvePartialKeyCommitmentResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.ProvePartialKeyCommitment")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.ProvePartialKeyCommitment")
		} else {
			a.logger.Info().Msg("<-- MPCService.ProvePartialKeyCommitment")
		}
	}()
	return a.app.ProvePartialKeyCommitment(ctx, prove)
}

func (a Application) ExchangeKey(ctx context.Context, exchange *application.ExchangeKeyRequest) (exchange_resp *application.ExchangeKeyResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.ExchangeKey")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.ExchangeKey")
		} else {
			a.logger.Info().Msg("<-- MPCService.ExchangeKey")
		}
	}()
	return a.app.ExchangeKey(ctx, exchange)
}

func (a Application) ProveKeyCommitment(ctx context.Context, prove *application.ProveKeyCommitmentRequest) (proof_resp *application.ProveKeyCommitmentResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.ProveKeyCommitment")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.ProveKeyCommitment")
		} else {
			a.logger.Info().Msg("<-- MPCService.ProveKeyCommitment")
		}
	}()
	return a.app.ProveKeyCommitment(ctx, prove)
}

func (a Application) Sign(ctx context.Context, sign *application.SignRequest) (resp *application.SignResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.Sign")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.Sign")
		} else {
			a.logger.Info().Msg("<-- MPCService.Sign")
		}
	}()
	return a.app.Sign(ctx, sign)
}

func (a Application) SignASN1(ctx context.Context, sign *application.SignASN1Request) (resp *application.SignASN1Response, err error) {
	a.logger.Info().Msgf("--> MPCService.SignASN1")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.SignASN1")
		} else {
			a.logger.Info().Msg("<-- MPCService.SignASN1")
		}
	}()
	return a.app.SignASN1(ctx, sign)
}

func (a Application) Verify(ctx context.Context, verify *application.VerifyRequest) (resp *application.VerifyResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.Verify")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.Verify")
		} else {
			a.logger.Info().Msg("<-- MPCService.Verify")
		}
	}()
	return a.app.Verify(ctx, verify)
}

func (a Application) VerifyASN1(ctx context.Context, verify *application.VerifyASN1Request) (resp *application.VerifyASN1Response, err error) {
	a.logger.Info().Msgf("--> MPCService.VerifyASN1")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.VerifyASN1")
		} else {
			a.logger.Info().Msg("<-- MPCService.VerifyASN1")
		}
	}()
	return a.app.VerifyASN1(ctx, verify)
}

func (a Application) GenerateSignatureR(ctx context.Context, generate *application.GenerateSignatureRRequest) (resp *application.GenerateSignatureRResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.GenerateSignatureR")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.GenerateSignatureR")
		} else {
			a.logger.Info().Msg("<-- MPCService.GenerateSignatureR")
		}
	}()
	return a.app.GenerateSignatureR(ctx, generate)
}

func (a Application) GeneratePartialSignatureS(ctx context.Context, generate *application.GeneratePartialSignatureSRequest) (resp *application.GeneratePartialSignatureSResponse, err error) {
	a.logger.Info().Msgf("--> MPCService.GeneratePartialSignatureS")
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.GeneratePartialSignatureS")
		} else {
			a.logger.Info().Msg("<-- MPCService.GeneratePartialSignatureS")
		}
	}()
	return a.app.GeneratePartialSignatureS(ctx, generate)
}
