package sign

import (
	"github.com/coredns/coredns/plugin"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("sign", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	zones, err := parse(c)
	if err != nil {
		return plugin.Error("sign", err)
	}

	return nil
}

func parse(c *caddy.Controller) error {
	return nil
}
