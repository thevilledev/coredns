//go:build gofuzz

package dnssec

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"

	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/pkg/fuzz"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// Fuzz fuzzes dnssec.
func Fuzz(data []byte) int {
	name := "example."

	// Backend file plugin to generate normal responses to be signed by dnssec.
	zone, _ := file.Parse(strings.NewReader(fuzzExample), name, "stdin", 0)
	backend := file.File{Next: test.ErrorHandler(), Zones: file.Zones{Z: map[string]*file.Zone{name: zone}, Names: []string{name}}}

	// Generate an Ed25519 key for signing to exercise signature paths.
	pub, priv, _ := ed25519.GenerateKey(nil)
	dk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
	key := &DNSKEY{K: dk, D: dk.ToDS(dns.SHA256), s: priv, tag: dk.KeyTag()}

	// Compose dnssec in front of file backend.
	c := cache.New(1024)
	d := New([]string{name}, []*DNSKEY{key}, false, backend, c)

	return fuzz.Do(d, data)
}

const fuzzExample = `
$TTL    30M
$ORIGIN example.
@       IN      SOA     ns1.example. admin.example. (
                             2025010101 ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             4H )       ; Negative Cache TTL
                IN      NS      ns1.example.
                IN      NS      ns2.example.

                IN      MX      1  mail1.example.
                IN      MX      5  mail2.example.

		IN      A       10.0.0.1
		IN      AAAA    fd00::1

a               IN      A       10.0.0.2
                IN      AAAA    fd00::2
www             IN      CNAME   a
archive         IN      CNAME   a

srv		IN	SRV     10 10 8080 a.example.
mx		IN	MX      10 a.example.`
