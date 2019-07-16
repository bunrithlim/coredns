package sign

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestSign(t *testing.T) {
	input := `sign db.miek.nl miek.nl {
		key file Kmiek.nl.+013+59725
		directory .
		}`
	c := caddy.NewTestController("dns", input)
	sign, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(sign.signers) != 1 {
		t.Fatalf("Expected 1 signer got %d", len(sign.signers))
	}
	if err := sign.signers[0].Sign(); err != nil {
		t.Error(err)
	}
}
