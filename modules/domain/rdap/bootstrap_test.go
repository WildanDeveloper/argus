package rdap

import (
	"strings"
	"testing"
)

// These fixtures are copied from what data.iana.org actually serves. An earlier
// hand-written fixture used a flat shape, which hid a parser bug that would have
// made every real lookup fail; the parser is therefore pinned to the published
// document shape rather than to a convenient one.
const realDNSBootstrap = `{
  "description": "RDAP bootstrap file for Domain Name System registrations",
  "publication": "2026-06-01T20:00:00Z",
  "services": [
    [ ["kg"], ["http://rdap.cctld.kg/"] ],
    [ ["mg"], ["http://rdap.nic.mg/"] ],
    [ ["com","net"], ["https://rdap.verisign.com/com/v1/", "http://rdap.verisign.com/com/v1/"] ],
    [ ["de"], ["https://rdap.denic.de/"] ]
  ],
  "version": "1.0"
}`

const realIPv4Bootstrap = `{
  "description": "RDAP bootstrap file for IPv4 address allocations",
  "publication": "2026-06-01T20:00:00Z",
  "services": [
    [ ["41.0.0.0/8","102.0.0.0/8"], ["https://rdap.afrinic.net/rdap/"] ],
    [ ["1.0.0.0/8","14.0.0.0/8","203.0.0.0/8"], ["https://rdap.apnic.net/"] ]
  ],
  "version": "1.0"
}`

const realASNBootstrap = `{
  "description": "RDAP bootstrap file for Autonomous System Number allocations",
  "publication": "2026-06-01T20:00:01Z",
  "services": [
    [
      ["36864-37887", "327680-328703", "328704-329727", "329728-330751"],
      ["https://rdap.afrinic.net/rdap/", "http://rdap.afrinic.net/rdap/"]
    ],
    [ ["15169"], ["https://rdap.arin.net/registry/autnum/"] ]
  ],
  "version": "1.0"
}`

func TestParseRealNestedShape(t *testing.T) {
	b, err := parseBootstrap([]byte(realDNSBootstrap), "domain")
	if err != nil {
		t.Fatal(err)
	}
	// The nested shape means a flat parse finds nothing at all.
	if b.Size() != 5 {
		t.Errorf("parsed %d keys, want 5 (com, net, kg, mg, de)", b.Size())
	}
	urls := b.EndpointsForDomain("com")
	if len(urls) != 1 || urls[0] != "https://rdap.verisign.com/com/v1/" {
		t.Errorf("com endpoints = %v", urls)
	}
	// One entry can serve several TLDs.
	if got := b.EndpointsForDomain("net"); len(got) != 1 {
		t.Errorf("net endpoints = %v", got)
	}
}

func TestHTTPSIsPreferredOverPlaintext(t *testing.T) {
	// Registries publish both. Argus must not fall back to cleartext for
	// registration data just because http happened to be listed first.
	b, err := parseBootstrap([]byte(realDNSBootstrap), "domain")
	if err != nil {
		t.Fatal(err)
	}
	urls := b.EndpointsForDomain("com")
	if len(urls) != 1 {
		t.Fatalf("com endpoints = %v; the http duplicate should have been dropped", urls)
	}
	if !strings.HasPrefix(urls[0], "https://") {
		t.Errorf("first endpoint = %q, want the https one", urls[0])
	}
}

func TestDomainKeyIsTheTLD(t *testing.T) {
	// Registries are delegated per top-level domain, so the bootstrap key is the TLD
	// and not the name being looked up.
	cases := map[string]string{
		"example.com":          "com",
		"www.example.co.uk":    "uk",
		"a.b.c.example.net":    "net",
		"xn--mnchen-3ya.de":    "de",
		"example.com.":         "com",
		"deep.sub.example.org": "org",
	}
	for in, want := range cases {
		got, ok := tldOf(in)
		if !ok {
			t.Errorf("tldOf(%q) found no TLD", in)
			continue
		}
		if got != want {
			t.Errorf("tldOf(%q) = %q, want %q", in, got, want)
		}
	}

	// A single label has no delegation point and therefore no registry.
	for _, in := range []string{"localhost", "com", ""} {
		if _, ok := tldOf(in); ok {
			t.Errorf("tldOf(%q) should find no TLD", in)
		}
	}
}

func TestAddressResolvesToMostSpecificPrefix(t *testing.T) {
	// RIRs publish both broad and specific allocations. Querying the broad one
	// returns an error or, worse, an unrelated record, so the longest match wins.
	b, err := parseBootstrap([]byte(`{
	  "services": [
	    [ ["10.0.0.0/8"],   ["https://broad.example/"] ],
	    [ ["10.1.0.0/16"],  ["https://specific.example/"] ],
	    [ ["10.1.2.0/24"],  ["https://most.example/"] ]
	  ]
	}`), "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	urls, key := b.EndpointsForAddr("10.1.2.3")
	if len(urls) != 1 || urls[0] != "https://most.example/" {
		t.Errorf("endpoints = %v (key %s), want the /24 that most specifically covers the address", urls, key)
	}
	if key != "10.1.2.0/24" {
		t.Errorf("matched key = %q, want 10.1.2.0/24", key)
	}
	// An address only covered by the broad block uses the broad one.
	if urls, _ := b.EndpointsForAddr("10.9.9.9"); len(urls) != 1 || urls[0] != "https://broad.example/" {
		t.Errorf("fallback endpoints = %v", urls)
	}
	// An address in no allocation at all returns nothing.
	if urls, _ := b.EndpointsForAddr("192.0.2.1"); len(urls) != 0 {
		t.Errorf("unallocated address returned %v", urls)
	}
}

func TestAddressFamiliesDoNotCross(t *testing.T) {
	// A v4 registry must not answer for a v6 address even when a prefix would
	// textually appear to match.
	b, err := parseBootstrap([]byte(`{"services": [ [ ["0.0.0.0/0"], ["https://v4.example/"] ] ]}`), "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if urls, _ := b.EndpointsForAddr("2001:db8::1"); len(urls) != 0 {
		t.Errorf("a v4 registry answered for a v6 address: %v", urls)
	}
}

func TestIPKeyStripsPrefix(t *testing.T) {
	// A CIDR target has no RDAP object of its own; the address inside it does.
	if got, ok := ipKeyOf("203.0.113.0/24"); !ok || got != "203.0.113.0" {
		t.Errorf("ipKeyOf = %q ok=%v", got, ok)
	}
	if got, ok := ipKeyOf("2001:db8::/32"); !ok || got != "2001:db8::" {
		t.Errorf("ipKeyOf v6 = %q ok=%v", got, ok)
	}
	if _, ok := ipKeyOf("not-an-ip"); ok {
		t.Error("ipKeyOf accepted a non-address")
	}
}

func TestASNResolvesThroughRanges(t *testing.T) {
	// The registry publishes allocations as intervals, so containment rather than
	// equality is the test. An exact-match lookup would fail for every ASN that is
	// merely inside an allocation.
	b, err := parseBootstrap([]byte(realASNBootstrap), "asn")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"36864":  "https://rdap.afrinic.net/rdap/",         // range start
		"37000":  "https://rdap.afrinic.net/rdap/",         // range interior
		"37887":  "https://rdap.afrinic.net/rdap/",         // range end
		"330751": "https://rdap.afrinic.net/rdap/",         // second range end
		"15169":  "https://rdap.arin.net/registry/autnum/", // single number
	}
	for asn, want := range cases {
		urls, _ := b.EndpointsForASN(asn)
		if len(urls) != 1 || urls[0] != want {
			t.Errorf("AS%s endpoints = %v, want %s", asn, urls, want)
		}
	}
	// Just outside every allocation.
	for _, asn := range []string{"36863", "37888", "64500"} {
		if urls, _ := b.EndpointsForASN(asn); len(urls) != 0 {
			t.Errorf("AS%s is outside every allocation but resolved to %v", asn, urls)
		}
	}
	// The AS prefix must be tolerated.
	if urls, _ := b.EndpointsForASN("AS36864"); len(urls) != 1 {
		t.Errorf("AS-prefixed lookup failed: %v", urls)
	}
}

func TestEndpointURLShapes(t *testing.T) {
	cases := []struct{ base, class, key, want string }{
		{"https://rdap.verisign.com/com/v1/", "domain", "example.com", "https://rdap.verisign.com/com/v1/domain/example.com"},
		{"https://rdap.example/", "ip", "203.0.113.1", "https://rdap.example/ip/203.0.113.1"},
		{"https://rdap.example/registry/autnum/", "asn", "15169", "https://rdap.example/registry/autnum/autnum/15169"},
	}
	for _, c := range cases {
		if got := endpointURL(c.base, c.class, c.key); got != c.want {
			t.Errorf("endpointURL(%q,%q,%q) = %q, want %q", c.base, c.class, c.key, got, c.want)
		}
	}
}

func TestParseRejectsUnusableDocuments(t *testing.T) {
	// An empty or malformed registry must be an error rather than a silently
	// empty map, which would look exactly like "this TLD has no RDAP service".
	for name, doc := range map[string]string{
		"empty services": `{"services": []}`,
		"not json":       `not json at all`,
		"no key or url":  `{"services": [ [[], []] ]}`,
	} {
		if _, err := parseBootstrap([]byte(doc), "domain"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseRealIPv4Shape(t *testing.T) {
	b, err := parseBootstrap([]byte(realIPv4Bootstrap), "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if b.Size() != 5 {
		t.Errorf("parsed %d prefixes, want 5", b.Size())
	}
	if urls, key := b.EndpointsForAddr("203.0.113.7"); len(urls) != 1 || key != "203.0.0.0/8" {
		t.Errorf("203.0.113.7 resolved to %v (key %s)", urls, key)
	}
}

func TestVCardParsing(t *testing.T) {
	raw := []any{
		"vcard",
		[]any{
			[]any{"version", map[string]any{}, "text", "4.0"},
			[]any{"fn", map[string]any{}, "text", "Example Registrar Inc."},
			[]any{"org", map[string]any{}, "text", "Example; Registrar"},
			[]any{"email", map[string]any{}, "text", "first@example.test"},
			[]any{"email", map[string]any{}, "text", "second@example.test"},
			[]any{"tel", map[string]any{"type": []any{"voice"}}, "uri", "tel:+1.5555550100"},
			[]any{"adr", map[string]any{}, "text", "", "", "", []any{"1 Main St"}, []any{"Town"}, nil, nil, []any{"Country"}},
		},
	}
	c := parseVCardArray(raw)
	if c.version != "4.0" {
		t.Errorf("version = %q", c.version)
	}
	if c.name() != "Example Registrar Inc." {
		t.Errorf("name = %q; fn should win over org", c.name())
	}
	emails := c.emails()
	if len(emails) != 2 || emails[0] != "first@example.test" {
		t.Errorf("emails = %v; multi-valued properties must all be kept", emails)
	}
	phones := c.phones()
	if len(phones) != 1 || phones[0] != "+1.5555550100" {
		t.Errorf("phones = %v; the tel: prefix should be stripped", phones)
	}
}

func TestVCardSkipsRedactionPlaceholders(t *testing.T) {
	// A placeholder is not an address. Treating one as a real contact would put
	// "REDACTED FOR PRIVACY" into the graph as an email entity.
	raw := []any{"vcard", []any{
		[]any{"fn", map[string]any{}, "text", "REDACTED FOR PRIVACY"},
		[]any{"email", map[string]any{}, "text", "REDACTED FOR PRIVACY"},
		[]any{"email", map[string]any{}, "text", "real@example.test"},
	}}
	c := parseVCardArray(raw)
	emails := c.emails()
	if len(emails) != 1 || emails[0] != "real@example.test" {
		t.Errorf("emails = %v, want only the real address", emails)
	}
	if !isRedactedPlaceholder("REDACTED FOR PRIVACY") {
		t.Error("placeholder not recognized")
	}
	if isRedactedPlaceholder("Example Registrar") {
		t.Error("a real name was treated as a placeholder")
	}
}

func TestVCardToleratesMalformedInput(t *testing.T) {
	// A malformed card must not panic and must yield an empty, usable result.
	for _, raw := range []any{nil, "vcard", []any{"vcard"}, []any{"vcard", []any{}}, []any{"vcard", "notalist"}} {
		c := parseVCardArray(raw)
		if len(c.emails()) != 0 {
			t.Errorf("malformed input %v produced emails %v", raw, c.emails())
		}
	}
}
