package main

import (
	"context"
	"fmt"

	"github.com/go-chi/chi/v5"
	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/hnamzian/yehuda-mpc/internal/logger"
	"github.com/hnamzian/yehuda-mpc/internal/waiter"
	"github.com/hnamzian/yehuda-mpc/mpcwallet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

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

	w := waiter.NewWaiter()
	w.Add(app.waitForRpc)
	w.Add(app.waitForHttp)
	w.Wait()
}
