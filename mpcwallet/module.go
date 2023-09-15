package mpcwallet

import (
	"context"

	"github.com/hnamzian/yehuda-mpc/internal/module"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/application"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/grpc"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/internal/logger"
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

	return nil
}
