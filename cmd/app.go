package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
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

func (app App) waitForRpc(ctx context.Context) error {
	ln, err := net.Listen("tcp", app.Config().Grpc.Address())
	if err != nil {
		return err
	}

	group, gCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		fmt.Println("Starting server...")
		if err = app.rpc.Serve(ln); err != nil {
			return err
		}
		return nil
	})

	group.Go(func() error {
		<-gCtx.Done()
		app.logger.Info().Msg("shutting down rpc server...")

		timer := time.NewTimer(5 * time.Second)
		stopped := make(chan struct{}, 1)
		go func() {
			app.rpc.GracefulStop()
			close(stopped)
		}()
		select {
		case <-timer.C:
			app.rpc.Stop()
			return fmt.Errorf("failed to gracefully stop the rpc server: %w", ctx.Err())
		case <-stopped:
			app.logger.Info().Msg("rpc server stopped")
			return nil
		}
	})

	return group.Wait()
}

func (app App) waitForHttp(ctx context.Context) error {
	server := http.Server{
		Addr:    app.Config().Http.Address(),
		Handler: app.Mux(),
	}

	group, gCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("failed to start http server: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		<-gCtx.Done()
		app.logger.Info().Msg("shutting down http server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to gracefully shutdown http server: %w", err)
		}
		return nil
	})

	return group.Wait()
}
