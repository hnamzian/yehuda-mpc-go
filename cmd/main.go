package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hnamzian/yehuda-mpc/internal/config"
	"github.com/hnamzian/yehuda-mpc/internal/logger"
	"github.com/hnamzian/yehuda-mpc/internal/module"
	"github.com/hnamzian/yehuda-mpc/internal/waiter"
	"github.com/hnamzian/yehuda-mpc/internal/web"
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
	app.mux.Mount("/", http.FileServer(http.FS(web.WebUI)))
	
	app.logger = logger.NewLogger(logger.LoggerConfig{
		Level: logger.DEBUG,
	})
	
	app.waiter = waiter.NewWaiter()

	app.modules = []module.Module{
		mpcwallet.Module{},
	}
	if err = app.StartModules(); err != nil {
		panic(err)
	}

	app.waiter.Add(app.waitForRpc)
	app.waiter.Add(app.waitForHttp)
	app.waiter.Wait()
}
