package sign

import (
	"io"
	"time"

	"github.com/miekg/dns"
)

// Resign will scan rd and check the signature on the SOA record. If that record
// has only 2 weeks left this function will return true. If the SOA isn't found in the first
// 100 records it will return false.
func Resign(rd io.Reader, now time.Time) bool {
	zp := dns.NewZoneParser(rd, ".", "resign")
	zp.SetIncludeAllowed(true)

	i := 0
	expir := now.Add(14 * 24 * time.Hour) // if expired within 2 weeks, resign
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := zp.Err(); err != nil {
			return true
		}

		switch x := rr.(type) {
		case *dns.RRSIG:
			if x.TypeCovered == dns.TypeSOA {
				return x.ValidityPeriod(expir)
			}
		}
		i++
		if i > 100 {
			return false
		}
	}
	return false
}
