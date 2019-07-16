package sign

import (
	"os"
	"path/filepath"
	"time"
)

// Sign holders signers that sign the various zones files.
type Sign struct {
	signers []Signer
}

// Resign scans all signers and signs are resigns zones if needed.
// TODO(miek): this needs to check the jitter and when they actually want to to be resigned.
func (s *Sign) Resign() {
	for _, signer := range s.signers {
		signedfile := filepath.Join(signer.directory, signer.signedfile)
		rd, err := os.Open(signedfile)
		resign := false
		if err != nil && os.IsNotExist(err) {
			resign = true
		}

		now := time.Now()
		if !resign {
			resign = Resign(rd, now)
		}

		if !resign {
			continue
		}

		signer.Sign(now)
	}
}
