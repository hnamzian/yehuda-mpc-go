package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

type App struct {
	config *config.AppConfig
	rpc    *grpc.Server
	mux    *chi.Mux
	logger zerolog.Logger
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

func (app App) runGrpcServer(ctx context.Context) error {
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

func (app App) runHttpServer(ctx context.Context) error {
	server := http.Server{
		Addr:    app.Config().Http.Address(),
		Handler: app.Mux(),
	}
	if err := server.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
