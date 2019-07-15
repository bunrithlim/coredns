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
	_, err := parse(c)
	if err != nil {
		return plugin.Error("sign", err)
	}

	// Don't call AddPlugin, *sign* is not a plugin.
	return nil
}

func parse(c *caddy.Controller) (*Sign, error) {
	for c.Next() {

		// c.NextBlock() ...
	}

	return nil, nil
}
