package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/hnamzian/yehuda-mpc/internal/module"
	"github.com/hnamzian/yehuda-mpc/internal/waiter"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

type App struct {
	config  *config.AppConfig
	rpc     *grpc.Server
	mux     *chi.Mux
	modules []module.Module
	logger  zerolog.Logger
	waiter  *waiter.Waiter
}

func (app App) StartModules() error {
	for _, m := range app.modules {
		if err := m.Startup(app.waiter.Context(), app); err != nil {
			return err
		}
	}
	return nil
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
	listener, err := net.Listen("tcp", app.config.Grpc.Address())
	if err != nil {
		return err
	}

	group, gCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		fmt.Println("rpc server started")
		defer fmt.Println("rpc server shutdown")
		if err := app.RPC().Serve(listener); err != nil && err != grpc.ErrServerStopped {
			return err
		}
		return nil
	})
	group.Go(func() error {
		<-gCtx.Done()
		fmt.Println("rpc server to be shutdown")
		stopped := make(chan struct{})
		go func() {
			app.RPC().GracefulStop()
			close(stopped)
		}()
		timeout := time.NewTimer(5*time.Second)
		select {
		case <-timeout.C:
			// Force it to stop
			app.RPC().Stop()
			return fmt.Errorf("rpc server failed to stop gracefully")
		case <-stopped:
			return nil
		}
	})

	return group.Wait()
}

func (app App) waitForHttp(ctx context.Context) error {
	webServer := &http.Server{
		Addr:    app.config.Web.Address(),
		Handler: app.mux,
	}
	fmt.Printf("Web server listening on %s\n", app.config.Web.Address())

	group, gCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		fmt.Println("web server started")
		defer fmt.Println("web server shutdown")
		if err := webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})
	group.Go(func() error {
		<-gCtx.Done()
		fmt.Println("web server to be shutdown")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := webServer.Shutdown(ctx); err != nil {
			return err
		}
		return nil
	})

	return group.Wait()
}
