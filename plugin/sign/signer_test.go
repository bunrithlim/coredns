package sign

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestSign(t *testing.T) {
	/*
		s := &Signer{
			dbfile:     "db.miek.nl",
			signedfile: "db.miek.nl.signed",
			directory:  ".",
		}
		pair, err := readKeyPair("Kmiek.nl.+013+59725.key", "Kmiek.nl.+013+59725.private", "miek.nl.")
		if err != nil {
			t.Fatal(err)
		}

		s.keys = []Pair{pair}
		if err := s.Sign("miek.nl."); err != nil {
			t.Error(err)
		}
	*/

	input := `sign db.miek.nl miek.nl {
		key file Kmiek.nl.+013+59725
		directory .
		}`
	c := caddy.NewTestController("dns", input)
	sign, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.signers[0].Sign("miek.nl."); err != nil {
		t.Error(err)
	}
}
