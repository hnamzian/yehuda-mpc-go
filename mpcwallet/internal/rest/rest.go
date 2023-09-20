package rest

import (
	"context"

	"github.com/go-chi/chi/v5"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hnamzian/yehuda-mpc/mpcwallet/mpcwalletpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func RegisterGateway(ctx context.Context, mux *chi.Mux, addr string) error {
	const apiRoot = "/api/key"
	gateway := runtime.NewServeMux()
	err := mpcwalletpb.RegisterMPCServiceHandlerFromEndpoint(ctx, gateway, addr, []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	})
	if err != nil {
		return err
	}

	mux.Mount(apiRoot, gateway)

	return nil
}
