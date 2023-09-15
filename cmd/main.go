package main

import (
	"context"
	"fmt"
	"net"

	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/hnamzian/yehuda-mpc/internal/logger"
	"github.com/hnamzian/yehuda-mpc/mpcwallet"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type App struct {
	config *config.AppConfig
	rpc    *grpc.Server
	logger zerolog.Logger
}

func main() {
	cfg, err := config.InitConfig()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Config: %v\n", cfg)

	app := App{
		config: cfg,
	}

	opts := []grpc.ServerOption{}
	s := grpc.NewServer(opts...)
	reflection.Register(s)
	app.rpc = s

	app.logger = logger.NewLogger(logger.LoggerConfig{
		Level: logger.DEBUG,
	})

	mpcwallet.Module{}.Startup(context.Background(), app)

	ln, err := net.Listen("tcp", app.Config().Grpc.Address())
	if err != nil {
		panic(err)
	}
	fmt.Println("Starting server...")
	if err = s.Serve(ln); err != nil {
		panic(err)
	}

}

func (a App) Config() *config.AppConfig {
	return a.config
}

func (a App) RPC() *grpc.Server {
	return a.rpc
}

func (a App) Logger() zerolog.Logger {
	return a.logger
}
