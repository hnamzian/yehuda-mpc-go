package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/hnamzian/yehuda-mpc/internal/logger"
	"github.com/hnamzian/yehuda-mpc/mpcwallet"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type App struct {
	config *config.AppConfig
	rpc    *grpc.Server
	mux    *chi.Mux
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

	app.mux = chi.NewMux()

	app.logger = logger.NewLogger(logger.LoggerConfig{
		Level: logger.DEBUG,
	})

	mpcwallet.Module{}.Startup(context.Background(), app)

	group, _ := errgroup.WithContext(context.Background())

	group.Go(app.runGrpcServer)
	group.Go(app.runHttpServer)

	group.Wait()

	// go func() {
	// 	server := http.Server{
	// 		Addr:    app.Config().Http.Address(),
	// 		Handler: app.Mux(),
	// 	}
	// 	if err := server.ListenAndServe(); err != nil {
	// 		panic(err)
	// 	}
	// }()
}

func (a App) Config() *config.AppConfig {
	return a.config
}

func (a App) RPC() *grpc.Server {
	return a.rpc
}

func (a App) Mux() *chi.Mux {
	return a.mux
}

func (a App) Logger() zerolog.Logger {
	return a.logger
}

func (app App) runGrpcServer() error {
	ln, err := net.Listen("tcp", app.Config().Grpc.Address())
	if err != nil {
		return err
	}
	fmt.Println("Starting server...")
	if err = app.rpc.Serve(ln); err != nil {
		return err
	}
	return nil
}

func (app App) runHttpServer() error {
	server := http.Server{
		Addr:    app.Config().Http.Address(),
		Handler: app.Mux(),
	}
	if err := server.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
