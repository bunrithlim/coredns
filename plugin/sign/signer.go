package sign

import (
	"math/rand"
	"os"
	"time"

	"github.com/coredns/coredns/plugin/file/tree"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("sign")

// Signer holds the data need to sign a zone file.
type Signer struct {
	keys   []Pair
	origin string

	expiration uint32
	inception  uint32
	ttl        uint32

	directory  string
	dbfile     string
	signedfile string

	jitter time.Duration
}

// New returns a new signer.
func New() Signer {
	s := Signer{
		jitter: time.Duration(-5 * rand.Float32() * float32(time.Hour) * 24),
	}

	return s
}

// Sign signs a zone file according to the parameters in s.
func (s Signer) Sign(origin string) error {
	now := time.Now()

	rd, err := os.Open(s.dbfile)
	if err != nil {
		return err
	}

	z, err := Parse(rd, origin, s.dbfile)
	if err != nil {
		return err
	}

	s.inception, s.expiration = lifetime(time.Now().UTC())
	s.origin = origin

	s.ttl = z.Apex.SOA.Header().Ttl
	z.Apex.SOA.Serial = uint32(time.Now().Unix())
	names := names(origin, z)

	nsec := NSEC(origin, next(origin, names, 0), s.ttl, []uint16{dns.TypeSOA, dns.TypeNS}) // need to dish out correct types
	z.Insert(nsec)

	for _, pair := range s.keys {
		z.Insert(pair.Public.ToDS(dns.SHA1))
		z.Insert(pair.Public.ToDS(dns.SHA256))
		z.Insert(pair.Public.ToCDNSKEY())
	}
	for _, pair := range s.keys {
		rrsig, err := pair.signRRs([]dns.RR{z.Apex.SOA}, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return err
		}
		z.Insert(rrsig)
		rrsig, err = pair.signRRs(z.Apex.NS, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return err
		}
		z.Insert(rrsig)
		rrsig, err = pair.signRRs([]dns.RR{nsec}, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return err
		}
		z.Insert(rrsig)
	}

	// We are walking the tree in the same direction, so names[] can be used here to indicated the next element.
	i := 1
	z.Tree.Do(func(e *tree.Elem) bool {
		nsec := NSEC(e.Name(), next(origin, names, i), s.ttl, []uint16{dns.TypeSOA, dns.TypeNS}) // e.Types() or something
		z.Insert(nsec)
		// nsec ownername should be OK.

		for _, rrs := range e.M() {
			if rrs[0].Header().Rrtype == dns.TypeRRSIG {
				continue
			}
			for _, pair := range s.keys {
				rrsig, err := pair.signRRs(rrs, s.origin, s.ttl, s.inception, s.expiration)
				if err != nil {
					return true
				}
				e.Insert(rrsig)
			}
		}
		i++
		return false
	})

	s.write(z) // error handling, once booleans are gone

	log.Infof("Signed %q with %d key(s) in %s, saved in %q", origin, len(s.keys), time.Since(now), s.signedfile)

	return nil
}

func lifetime(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(-3 * time.Hour).Unix())      // -(2+1) hours, be sure to catch daylight saving time and such
	expir := uint32(now.Add(21 * 24 * time.Hour).Unix()) // sign for 21 days
	return incep, expir
}
