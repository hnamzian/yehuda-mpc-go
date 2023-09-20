package mpcwallet

import (
	"context"

	"github.com/hnamzian/yehuda-mpc/internal/module"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/application"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/grpc"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/logger"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/rest"
)

type Module struct{}

func (m Module) Startup(ctx context.Context, core module.Core) error {
	peer := grpc.NewPeer(core.Config().Peers[0].Addr, core.Logger()).WithContext(ctx)
	err := peer.Connect()
	if err != nil {
		return err
	}

	var app application.App
	app = application.NewApplication(core.Config().ID, core.Config().Wallet.Path, peer, core.Logger())
	app = logger.NewApplication(app, core.Logger())

	grpc.RegisterWalletServer(core.RPC(), app)

	if err = rest.RegisterGateway(ctx, core.Mux(), core.Config().Grpc.Address()); err != nil {
		return err
	}
	if err = rest.RegisterSwagger(core.Mux()); err != nil {
		return err
	}

	return nil
}
