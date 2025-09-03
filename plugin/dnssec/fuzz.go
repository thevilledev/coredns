//go:build gofuzz

package dnssec

import (
	"context"
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

	// Derive simple key variations from fuzzer input (fast, no RSA/ECDSA).
	// b0 controls split-keys vs single-key; b1 toggles odd flag combos.
	var b0, b1 byte
	if len(data) > 0 {
		b0 = data[0]
	}
	if len(data) > 1 {
		b1 = data[1]
	}

	keys := []*DNSKEY{}
	makeKey := func(flags uint16) *DNSKEY {
		pub, priv, _ := ed25519.GenerateKey(nil)
		dk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: flags, Protocol: 3, Algorithm: dns.ED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
		return &DNSKEY{K: dk, D: dk.ToDS(dns.SHA256), s: priv, tag: dk.KeyTag()}
	}

	// Flags per RFC4034 2.1.1: 256 (ZSK), 257 (KSK). We also sometimes use odd values to test code paths.
	split := (b0 & 0x01) == 0x01
	if split {
		// Create both a KSK and a ZSK
		kskFlags := uint16(257)
		zskFlags := uint16(256)
		if (b1 & 0x01) == 0x01 {
			// Introduce an odd flag pattern sometimes
			kskFlags = 0
			zskFlags = 513
		}
		keys = append(keys, makeKey(kskFlags))
		keys = append(keys, makeKey(zskFlags))
	} else {
		flags := uint16(257)
		if (b1 & 0x02) == 0x02 {
			flags = 256
		}
		keys = append(keys, makeKey(flags))
	}

	// Compose dnssec in front of file backend.
	c := cache.New(1024)
	d := New([]string{name}, keys, split, backend, c)

	// Drive additional deterministic queries to cover key dnssec paths.
	ctx := context.TODO()
	w := &test.ResponseWriter{}

	// 1) Signed answer path: www.example. A with DO
	m1 := new(dns.Msg)
	m1.SetQuestion("www."+name, dns.TypeA)
	o1 := new(dns.OPT)
	o1.Hdr.Name = "."
	o1.Hdr.Rrtype = dns.TypeOPT
	o1.SetDo()
	o1.SetUDPSize(4096)
	m1.Extra = []dns.RR{o1}
	_, _ = d.ServeDNS(ctx, w, m1)

	// 2) Cache hit: same query again should use signature cache
	_, _ = d.ServeDNS(ctx, w, m1)

	// 3) NXDOMAIN/NoData path: nonexistent name with DO
	m2 := new(dns.Msg)
	m2.SetQuestion("nope."+name, dns.TypeA)
	o2 := new(dns.OPT)
	o2.Hdr.Name = "."
	o2.Hdr.Rrtype = dns.TypeOPT
	o2.SetDo()
	o2.SetUDPSize(4096)
	m2.Extra = []dns.RR{o2}
	_, _ = d.ServeDNS(ctx, w, m2)

	// 4) DNSKEY interception with DO (triggers getDNSKEY signing)
	m3 := new(dns.Msg)
	m3.SetQuestion(name, dns.TypeDNSKEY)
	o3 := new(dns.OPT)
	o3.Hdr.Name = "."
	o3.Hdr.Rrtype = dns.TypeOPT
	o3.SetDo()
	o3.SetUDPSize(4096)
	m3.Extra = []dns.RR{o3}
	_, _ = d.ServeDNS(ctx, w, m3)

	// 5) Delegation/referral path: query below delegated child with DO
	m4 := new(dns.Msg)
	m4.SetQuestion("x.child."+name, dns.TypeA)
	o4 := new(dns.OPT)
	o4.Hdr.Name = "."
	o4.Hdr.Rrtype = dns.TypeOPT
	o4.SetDo()
	o4.SetUDPSize(4096)
	m4.Extra = []dns.RR{o4}
	_, _ = d.ServeDNS(ctx, w, m4)

	// 6) No-DO path: pass-through without signing
	m5 := new(dns.Msg)
	m5.SetQuestion("www."+name, dns.TypeA)
	_, _ = d.ServeDNS(ctx, w, m5)

	// Finally, run the generic harness call to mix in random paths.
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

; delegation for child.example.
child           IN      NS      ns1.child.example.
ns1.child       IN      A       10.0.0.53

srv		IN	SRV     10 10 8080 a.example.
mx		IN	MX      10 a.example.`
