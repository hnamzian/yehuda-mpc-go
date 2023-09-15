package module

import (
	"context"

	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

type Core interface {
	Config() *config.AppConfig
	RPC() *grpc.Server
	Logger() zerolog.Logger
}

type Module interface {
	Startup(context.Context, Core) error
}
