package sign

import "github.com/coredns/coredns/plugin"

type Sign struct {
	signers []Signer

	Next plugin.Handler
}
