//go:build gofuzz

package template

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/fuzz"
	"github.com/coredns/coredns/plugin/test"
)

var handlers []Handler

func init() {
	confs := []string{
		// Basic A answer
		`template ANY A example.com {
			match ".*"
			rcode NOERROR
			answer "{{ .Name }} 60 IN A 192.0.2.1"
		}`,
		// With additional and authority sections
		`template IN MX example.com {
			match ".*"
			rcode NOERROR
			answer "{{ .Name }} 60 IN MX 10 mail.example.com."
			additional "mail.example.com. 60 IN A 198.51.100.7"
			authority  "example.com. 60 IN NS ns0.example.com."
		}`,
		// NXDOMAIN with EDE and SOA in authority
		`template IN ANY invalid. {
			match ".*"
			rcode NXDOMAIN
			authority "invalid. 60 IN SOA ns.invalid. hostmaster.invalid. (1 60 60 60 60)"
			ederror 21 "Blocked"
		}`,
		// CNAME answer to exercise upstream.Lookup path (error tolerated)
		`template IN A cname.example. {
			match ".*"
			rcode NOERROR
			answer "{{ .Name }} 60 IN CNAME target.example."
		}`,
		// Regex with capture groups
		`template IN A ip.example. {
			match "^ip-(?P<a>[0-9]+)-(?P<b>[0-9]+)-(?P<c>[0-9]+)-(?P<d>[0-9]+)[.]ip[.]example[.]$"
			rcode NOERROR
			answer "{{ .Name }} 60 IN A {{ .Group.a }}.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
		}`,
		// Regex with parseInt function over hex components
		`template IN A iphex.example. {
			match "^ip0a(?P<b>[a-f0-9]{2})(?P<c>[a-f0-9]{2})(?P<d>[a-f0-9]{2})[.]iphex[.]example[.]$"
			rcode NOERROR
			answer "{{ .Name }} 3600 IN A 10.{{ parseInt .Group.b 16 8 }}.{{ parseInt .Group.c 16 8 }}.{{ parseInt .Group.d 16 8 }}"
		}`,
		// Fallthrough behavior (no match against queried name triggers fallthrough path)
		`template IN ANY fall.example. {
			match "^doesnotmatch[.]fall[.]example[.]$"
			rcode NOERROR
			answer "fall.example. 60 IN TXT \"x\""
			fallthrough
		}`,
		// Metadata usage in template (Meta returns empty string without metadata plugin, but executes)
		`template IN TXT meta.example. {
			match ".*"
			rcode NOERROR
			answer "_meta.meta.example. 60 IN TXT \"m={{ .Meta \"trace/id\" }}\""
		}`,
		// NOERROR/NODATA with SOA in authority
		`template IN AAAA nodata.example. {
			match ".*"
			rcode NOERROR
			authority "nodata.example. 60 IN SOA ns.nodata. hostmaster.nodata. (1 60 60 60 60)"
		}`,
		// Reference a missing capture group to exercise runtime template error handling
		`template IN A badgroup.example. {
			match "^no-captures[.]badgroup[.]example[.]$"
			rcode NOERROR
			answer "{{ .Name }} 60 IN A {{ .Group.missing }}"
		}`,
		// Large TXT (multiple strings) to exercise length handling
		`template IN TXT bigtxt.example. {
			match ".*"
			rcode NOERROR
			answer "bigtxt.example. 60 IN TXT \"aaaaaaaaaaaaaaaaaaaaaaaa\" \"bbbbbbbbbbbbbbbbbbbbbbbb\" \"cccccccccccccccccccccccc\""
		}`,
		// AAAA straight answer
		`template IN AAAA v6.example. {
			match ".*"
			rcode NOERROR
			answer "{{ .Name }} 60 IN AAAA 2001:db8::1"
		}`,
	}
	for _, cfg := range confs {
		c := caddy.NewTestController("dns", cfg)
		h, err := templateParse(c)
		if err == nil {
			h.Next = test.ErrorHandler()
			handlers = append(handlers, h)
		}
	}
	// Fallback minimal handler if all parsing failed
	if len(handlers) == 0 {
		c := caddy.NewTestController("dns", `template ANY A example.com {
			match ".*"
			rcode NOERROR
			answer "{{ .Name }} 60 IN A 192.0.2.1"
		}`)
		if h, err := templateParse(c); err == nil {
			h.Next = test.ErrorHandler()
			handlers = append(handlers, h)
		}
	}
}

// Fuzz fuzzes template.
func Fuzz(data []byte) int {
	if len(handlers) == 0 {
		return 0
	}
	idx := 0
	if len(data) > 0 {
		idx = int(data[0]) % len(handlers)
	}
	h := handlers[idx]
	return fuzz.Do(h, data)
}
