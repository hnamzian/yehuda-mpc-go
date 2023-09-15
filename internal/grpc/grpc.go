package grpc

import "fmt"

type GrpcConfig struct {
	Host string `mapstructure:"host"`
	Port string `mapstructure:"port"`
}

func (c *GrpcConfig) Address() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}
