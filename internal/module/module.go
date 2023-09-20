package module

import (
	"context"

	"github.com/go-chi/chi/v5"
	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

type Core interface {
	Config() *config.AppConfig
	RPC() *grpc.Server
	Mux() *chi.Mux
	Logger() zerolog.Logger
}

type Module interface {
	Startup(context.Context, Core) error
}
