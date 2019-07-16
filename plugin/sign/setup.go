package sign

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
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
	sign := &Sign{}
	config := dnsserver.GetConfig(c)

	for c.Next() {
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		dbfile := c.Val()
		if !filepath.IsAbs(dbfile) && config.Root != "" {
			dbfile = filepath.Join(config.Root, dbfile)
		}

		origins := make([]string, len(c.ServerBlockKeys))
		copy(origins, c.ServerBlockKeys)
		args := c.RemainingArgs()
		if len(args) > 0 {
			origins = args
		}

		signers := make([]Signer, len(origins))
		for i := range origins {
			signers[i] = Signer{
				dbfile:     dbfile,
				origin:     plugin.Host(origins[i]).Normalize(),
				jitter:     time.Duration(-5 * rand.Float32() * float32(time.Hour) * 24),
				directory:  "/var/lib/coredns",
				signedfile: fmt.Sprintf("db.%ssigned", origins[i]),
			}
		}

		for c.NextBlock() {
			switch c.Val() {
			case "key":
				pairs, err := keyParse(c)
				if err != nil {
					return sign, err
				}
				for i := range signers {
					for _, p := range pairs {
						p.Public.Header().Name = signers[i].origin
					}
					signers[i].keys = append(signers[i].keys, pairs...)
				}
			case "directory":
				dir := c.RemainingArgs()
				if len(dir) == 0 || len(dir) > 1 {
					return sign, fmt.Errorf("can only be one argument after %q", "directory")
				}
				for i := range signers {
					signers[i].directory = dir[0]
					signers[i].signedfile = fmt.Sprintf("db.%ssigned", signers[i].origin)
				}
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
		sign.signers = append(sign.signers, signers...)
	}

	return sign, nil
}
