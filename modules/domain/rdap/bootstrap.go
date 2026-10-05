package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Bootstrap URLs, per object class.
//
// These paths are not interchangeable and one of them does not exist: there is no
// ip.json. IPv4 and IPv6 are published as separate registries, so an IP lookup has
// to consult both and keep the answer that actually covers the address.
var bootstrapURLs = map[string][]string{
	"domain": {"https://data.iana.org/rdap/dns.json"},
	"ipv4":   {"https://data.iana.org/rdap/ipv4.json"},
	"ipv6":   {"https://data.iana.org/rdap/ipv6.json"},
	"asn":    {"https://data.iana.org/rdap/asn.json"},
}

// classOrder is the lookup order for an IP address. IPv4 first because a v4
// literal cannot match a v6 prefix and vice versa; the registry for the other
// family is still consulted only when the first has no covering prefix.
var classOrder = []string{"ipv4", "ipv6"}

// Bootstrap is a parsed IANA bootstrap registry.
//
// The document shape is defined by RFC 9224 §3.1 and is nested:
//
//	"services": [
//	  [ ["com"], ["https://rdap.verisign.com/com/v1/"] ],
//	  [ ["kg","mg"], ["http://rdap.cctld.kg/"] ]
//	]
//
// The first inner array holds registry keys and the second holds base URLs. An
// earlier assumption that the keys and URLs were flattened into one array is
// exactly the kind of mistake a hand-written fixture hides, so the parser is
// tested against the real published shape.
type Bootstrap struct {
	class    string
	services map[string][]string
	// prefixes keeps CIDR keys with their parsed form so an address lookup can find
	// the most specific covering allocation instead of an exact string match.
	prefixes []prefixEntry
	// ranges keeps ASN keys as numeric intervals, because the registry publishes
	// allocations as "36864-37887" rather than as individual numbers.
	ranges      []rangeEntry
	version     string
	publication string
	fetchedAt   time.Time
}

type prefixEntry struct {
	prefix netip.Prefix
	urls   []string
	key    string
}

type rangeEntry struct {
	lo, hi uint64
	urls   []string
	key    string
}

// rawBootstrap is the subset of the document that matters here.
type rawBootstrap struct {
	Version     string       `json:"version"`
	Publication string       `json:"publication"`
	Services    [][][]string `json:"services"`
}

// parseBootstrap decodes a bootstrap document for a class.
func parseBootstrap(raw []byte, class string) (*Bootstrap, error) {
	var doc rawBootstrap
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("rdap: parse %s bootstrap: %w", class, err)
	}

	b := &Bootstrap{
		class:       class,
		services:    map[string][]string{},
		version:     doc.Version,
		publication: doc.Publication,
	}

	for _, entry := range doc.Services {
		if len(entry) < 2 {
			continue
		}
		keys := nonEmpty(entry[0])
		urls := nonEmpty(entry[1])
		if len(keys) == 0 || len(urls) == 0 {
			continue
		}
		urls = preferSecure(urls)

		for _, key := range keys {
			k := normalizeKey(class, key)
			if k == "" {
				continue
			}
			b.services[k] = append(b.services[k], urls...)

			switch class {
			case "ipv4", "ipv6":
				p, err := netip.ParsePrefix(k)
				if err != nil {
					continue
				}
				b.prefixes = append(b.prefixes, prefixEntry{prefix: p.Masked(), urls: urls, key: k})
			case "asn":
				lo, hi, ok := parseASNRange(k)
				if !ok {
					continue
				}
				b.ranges = append(b.ranges, rangeEntry{lo: lo, hi: hi, urls: urls, key: k})
			}
		}
	}

	if len(b.services) == 0 {
		return nil, fmt.Errorf("rdap: %s bootstrap contains no services", class)
	}
	return b, nil
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// preferSecure returns the endpoints Argus will actually try.
//
// Registries routinely publish both schemes for the same host, and this module is
// about to grade the answer as authoritative. Falling back to cleartext would let
// anyone on the path forge a registration record -- a different registrar, a
// different abuse contact -- and Argus would emit it graded A. So an http endpoint
// is dropped whenever the same host is also served over https.
//
// A registry offering only http is still reachable: refusing it outright would turn
// a genuine data gap into a silent one. The downgrade stays visible in the audit
// record and in the evidence provenance, which is the honest way to expose it.
func preferSecure(urls []string) []string {
	secureHosts := map[string]bool{}
	for _, u := range urls {
		if strings.HasPrefix(strings.ToLower(u), "https://") {
			secureHosts[hostOf(u)] = true
		}
	}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		https := strings.HasPrefix(strings.ToLower(u), "https://")
		if !https && secureHosts[hostOf(u)] {
			continue
		}
		out = append(out, u)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.HasPrefix(strings.ToLower(out[i]), "https://") &&
			!strings.HasPrefix(strings.ToLower(out[j]), "https://")
	})
	return out
}

// hostOf extracts the host[:port] portion of an endpoint URL.
func hostOf(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// normalizeKey lower-cases and strips a redundant ASN prefix.
func normalizeKey(class, key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	if class == "asn" {
		k = strings.TrimPrefix(k, "asn")
		k = strings.TrimPrefix(k, "as")
	}
	return k
}

// parseASNRange accepts both a single number and an interval.
func parseASNRange(k string) (lo, hi uint64, ok bool) {
	if i := strings.IndexByte(k, '-'); i > 0 {
		lo, err1 := strconv.ParseUint(strings.TrimSpace(k[:i]), 10, 32)
		hi, err2 := strconv.ParseUint(strings.TrimSpace(k[i+1:]), 10, 32)
		if err1 != nil || err2 != nil || lo == 0 || hi < lo {
			return 0, 0, false
		}
		return lo, hi, true
	}
	n, err := strconv.ParseUint(k, 10, 32)
	if err != nil || n == 0 {
		return 0, 0, false
	}
	return n, n, true
}

// Size reports how many registry keys the document holds.
func (b *Bootstrap) Size() int { return len(b.services) }

// Provenance renders a one-line description for evidence records.
func (b *Bootstrap) Provenance() string {
	return fmt.Sprintf("iana-rdap-bootstrap class=%s version=%s keys=%d", b.class, b.version, len(b.services))
}

// bootstrapCache holds parsed registries per class.
//
// The documents are large and republished rarely, so they are fetched once per
// process. The expiry keeps a long-lived daemon from pinning a superseded registry.
type bootstrapCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	ttl     time.Duration
	now     func() time.Time
}

type cacheEntry struct {
	boot      *Bootstrap
	fetchedAt time.Time
}

var caches sync.Map // class -> *bootstrapCache

func cacheFor(class string) *bootstrapCache {
	if v, ok := caches.Load(class); ok {
		return v.(*bootstrapCache)
	}
	c := &bootstrapCache{entries: map[string]*cacheEntry{}, ttl: 24 * time.Hour, now: time.Now}
	actual, _ := caches.LoadOrStore(class, c)
	return actual.(*bootstrapCache)
}

// resetCaches clears every registry. Tests call this so one test's cached document
// cannot satisfy another's expectation.
func resetCaches() {
	caches.Range(func(_, v any) bool {
		c := v.(*bootstrapCache)
		c.mu.Lock()
		c.entries = map[string]*cacheEntry{}
		c.mu.Unlock()
		return true
	})
}

// get returns a cached registry, fetching it when absent or stale.
func (c *bootstrapCache) get(ctx context.Context, m *Module, e sdk.Emitter, class string) (*Bootstrap, error) {
	c.mu.Lock()
	if entry, ok := c.entries[class]; ok && c.now().Sub(entry.fetchedAt) < c.ttl {
		c.mu.Unlock()
		return entry.boot, nil
	}
	c.mu.Unlock()

	urls := m.bootstrapURLs[class]
	if len(urls) == 0 {
		return nil, fmt.Errorf("rdap: no bootstrap URL configured for class %q", class)
	}

	var lastErr error
	for _, u := range urls {
		raw, err := m.get(ctx, e, u, "bootstrap.fetch", sdk.EvidenceMeta{
			Source: u, Method: "bootstrap.fetch", MediaType: "application/json",
		})
		if err != nil {
			lastErr = err
			continue
		}
		boot, err := parseBootstrap(raw, class)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.entries[class] = &cacheEntry{boot: boot, fetchedAt: c.now()}
		c.mu.Unlock()
		return boot, nil
	}
	return nil, fmt.Errorf("rdap: bootstrap for %s: %w", class, lastErr)
}

// --- lookup ---

// lookupClass maps a target to the bootstrap class and key it resolves under.
//
// For a domain the key is the TLD, because that is how registries are
// delegated. For an ASN it is the bare number, without the "AS" prefix that IANA
// does not use.
func lookupClass(t sdk.EntityType, value string) (class, key string, ok bool) {
	switch t {
	case sdk.TypeDomain, sdk.TypeSubdomain:
		tld, found := tldOf(value)
		if !found {
			return "", "", false
		}
		return "domain", tld, true
	case sdk.TypeASN:
		n := strings.TrimPrefix(strings.ToUpper(value), "AS")
		if _, err := strconv.ParseUint(n, 10, 32); err != nil {
			return "", "", false
		}
		return "asn", n, true
	}
	return "", "", false
}

// tldOf returns the final label of a domain name.
func tldOf(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	i := strings.LastIndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		// A single label has no delegation point and therefore no registry.
		return "", false
	}
	return name[i+1:], true
}

// ipKeyOf returns the address part of an IP or CIDR target.
func ipKeyOf(value string) (string, bool) {
	if i := strings.IndexByte(value, '/'); i > 0 {
		value = value[:i]
	}
	a, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil {
		return "", false
	}
	return a.String(), true
}

// classForAddr returns which IP registry should be consulted first.
func classForAddr(addr string) (string, bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return "", false
	}
	if a.Is4() {
		return "ipv4", true
	}
	return "ipv6", true
}

// EndpointsForDomain returns the base URLs serving a TLD.
func (b *Bootstrap) EndpointsForDomain(tld string) []string {
	return b.services[strings.ToLower(tld)]
}

// EndpointsForAddr returns the base URLs whose allocation most specifically covers
// an address.
//
// Most specific wins: RIRs publish both /8 blocks and more specific allocations, and
// querying the wrong one returns an error or, worse, an unrelated record.
func (b *Bootstrap) EndpointsForAddr(addr string) ([]string, string) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, ""
	}
	best := -1
	for i := range b.prefixes {
		p := b.prefixes[i].prefix
		if p.Addr().Is4() != a.Is4() {
			continue
		}
		if !p.Contains(a) {
			continue
		}
		if best < 0 || p.Bits() > b.prefixes[best].prefix.Bits() {
			best = i
		}
	}
	if best < 0 {
		return nil, ""
	}
	return b.prefixes[best].urls, b.prefixes[best].key
}

// EndpointsForASN returns the base URLs whose allocation contains an ASN.
//
// The registry publishes intervals, so containment rather than equality is the test.
func (b *Bootstrap) EndpointsForASN(n string) ([]string, string) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(n), "AS"), 10, 32)
	if err != nil {
		return nil, ""
	}
	for i := range b.ranges {
		if v >= b.ranges[i].lo && v <= b.ranges[i].hi {
			return b.ranges[i].urls, b.ranges[i].key
		}
	}
	return nil, ""
}

// endpointURL builds the query URL for an object under a base endpoint.
func endpointURL(base, class, key string) string {
	switch class {
	case "domain":
		return base + "domain/" + key
	case "ipv4", "ipv6":
		// The IP registries describe networks, and RFC 9082 names the path /ip/.
		return base + "ip/" + key
	case "asn":
		return base + "autnum/" + strings.TrimPrefix(strings.ToUpper(key), "AS")
	}
	return base + class + "/" + key
}

// sortedEndpoints returns endpoints in a stable order.
func sortedEndpoints(urls []string) []string {
	out := append([]string(nil), urls...)
	sort.Strings(out)
	return out
}
