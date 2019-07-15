package sign

import "github.com/coredns/coredns/plugin"

type sign struct {
	signers []signer

	Next plugin.Handler
}
