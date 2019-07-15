package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mholt/caddy"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

// Pair holds DNSSEC key information, botht the public and private components are stored here.
type Pair struct {
	Public  *dns.DNSKEY
	Tag     uint16
	Private crypto.Signer
}

// keyParse reads the public and private key from disk.
func keyParse(c *caddy.Controller) ([]Pair, error) {
	if !c.NextArg() {
		return nil, c.ArgErr()
	}
	pairs := []Pair{}

	println("ffdfd")
	switch c.Val() {
	case "file":
		ks := c.RemainingArgs()
		if len(ks) == 0 {
			return nil, c.ArgErr()
		}
		pair, err := readKeyPair(ks[0]+".key", ks[0]+".private")
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair)
	case "directory":
		return nil, fmt.Errorf("directory: not implemented")
	}

	return pairs, nil
}

func readKeyPair(public, private string) (Pair, error) {
	rk, err := os.Open(public)
	if err != nil {
		return Pair{}, err
	}
	b, err := ioutil.ReadAll(rk)
	if err != nil {
		return Pair{}, err
	}
	dnskey, err := dns.NewRR(string(b))
	if err != nil {
		return Pair{}, err
	}
	if _, ok := dnskey.(*dns.DNSKEY); !ok {
		return Pair{}, fmt.Errorf("RR in %q is not a DNSKEY: %d", public, dnskey.Header().Rrtype)
	}
	ksk := dnskey.(*dns.DNSKEY).Flags&(1<<8) == (1<<8) && dnskey.(*dns.DNSKEY).Flags&1 == 1
	if !ksk {
		return Pair{}, fmt.Errorf("DNSKEY in %q, DNSKEY is not a CSK/KSK", public)
	}

	rp, err := os.Open(private)
	if err != nil {
		return Pair{}, err
	}
	privkey, err := dnskey.(*dns.DNSKEY).ReadPrivateKey(rp, private)
	if err != nil {
		return Pair{}, err
	}
	switch signer := privkey.(type) {
	case *ecdsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), Tag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	case *ed25519.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), Tag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	case *rsa.PrivateKey:
		return Pair{Public: dnskey.(*dns.DNSKEY), Tag: dnskey.(*dns.DNSKEY).KeyTag(), Private: signer}, nil
	default:
		return Pair{}, fmt.Errorf("unsupported algorithm %s", signer)
	}
}
