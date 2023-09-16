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
	a.logger.Info().Msgf("--> MPCService.GetWallet: %v", get)
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
	a.logger.Info().Msgf("--> MPCService.HealthCheck: %v", health)
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
	a.logger.Info().Msgf("--> MPCService.GenerateKeyPair: %v", generate)
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
	a.logger.Info().Msgf("--> MPCService.GeneratePartialKey: %v", generate)
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
	a.logger.Info().Msgf("--> MPCService.ExchangePartialKey: %v", exchange)
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
	a.logger.Info().Msgf("--> MPCService.ProvePartialKeyCommitment: %v", prove)
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
	a.logger.Info().Msgf("--> MPCService.ExchangeKey: %v", exchange)
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
	a.logger.Info().Msgf("--> MPCService.ProveKeyCommitment: %v", prove)
	defer func() {
		if err != nil {
			a.logger.Error().Err(err).Msg("<-- MPCService.ProveKeyCommitment")
		} else {
			a.logger.Info().Msg("<-- MPCService.ProveKeyCommitment")
		}
	}()
	return a.app.ProveKeyCommitment(ctx, prove)
}
