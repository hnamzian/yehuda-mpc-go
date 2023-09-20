package config

import (
	"fmt"
	"os"

	"github.com/hnamzian/yehuda-mpc/internal/grpc"
	"github.com/hnamzian/yehuda-mpc/internal/peers"
	"github.com/hnamzian/yehuda-mpc/internal/wallet"
	"github.com/hnamzian/yehuda-mpc/internal/web"
	"github.com/spf13/viper"
)

type AppConfig struct {
	ID       string              `mapstructure:"id"`
	LogLevel string              `mapstructure:"logLevel"`
	Grpc     grpc.GrpcConfig     `mapstructure:"grpc"`
	Web      web.WebConfig       `mapstructure:"web"`
	Peers    []peers.Peer        `mapstructure:"peers"`
	Wallet   wallet.WalletConfig `mapstructure:"wallet"`
}

func InitConfig() (*AppConfig, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		return nil, fmt.Errorf("CONFIG_PATH is not set")
	}
	viper.SetConfigFile(configPath)

	viper.SetDefault("logLevel", "debug")

	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %s", err)
	}

	var config AppConfig
	err = viper.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %s", err)
	}

	return &config, nil
}
