package http

import "fmt"

type HttpConfig struct {
	Host string
	Port string
}

func (c HttpConfig) Address() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}
