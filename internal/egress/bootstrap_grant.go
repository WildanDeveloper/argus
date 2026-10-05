package egress

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
	"sync"
)

// BootstrapGrant authorizes additional egress hosts for one module, derived from a
// document the broker itself fetched and validated.
//
// The problem it solves: a module that must discover its own endpoints cannot name
// them in a static manifest without the manifest going stale, and a module that is
// simply trusted to reach whatever it discovers has no least-privilege boundary at
// all. Enumerating hosts by hand is not an option either; the IANA RDAP bootstrap
// alone names several hundred, and it changes.
//
// So the derivation is deliberately one-directional. The broker fetches the
// bootstrap from a host the module already declared, and only then extends that
// module's allow-list with hosts named inside the document. The module never gets to
// assert a host, so a compromised collector cannot widen its own reach: it would
// need to forge the response of a host it was already permitted to contact.
//
// The residual trust is the bootstrap host itself. That is the whole content of the
// grant, so a deployment that does not trust IANA should not enable this for that
// module.
type BootstrapGrant struct {
	mu      sync.RWMutex
	granted map[string]map[string]bool // module -> host -> true
	// maxHosts bounds a single module's derived set. A malformed or hostile
	// document must not be able to grow the allow-list without limit.
	maxHosts int
}

// defaultMaxGrantedHosts is generous for a real registry ecosystem and small enough
// that a runaway document is obvious.
const defaultMaxGrantedHosts = 1024

// NewBootstrapGrant builds an empty grant table.
func NewBootstrapGrant() *BootstrapGrant {
	return &BootstrapGrant{granted: map[string]map[string]bool{}, maxHosts: defaultMaxGrantedHosts}
}

// Allows reports whether host was granted to module.
func (g *BootstrapGrant) Allows(module, host string) bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.granted[module][strings.ToLower(host)]
}

// Hosts returns the derived hosts granted to a module, sorted. The CLI surfaces it so
// an operator can see what a scan was actually permitted to reach.
func (g *BootstrapGrant) Hosts(module string) []string {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	set := g.granted[module]
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sortStrings(out)
	return out
}

// maxHostsFor reports the per-module cap.
func (g *BootstrapGrant) maxHostsFor() int {
	if g == nil || g.maxHosts <= 0 {
		return defaultMaxGrantedHosts
	}
	return g.maxHosts
}

// Absorb extends a module's allow-list from a bootstrap document.
//
// Only https endpoints are taken. A bootstrap naming an http endpoint is not
// granting it: an on-path attacker could forge that endpoint's answer, and this
// module's whole purpose is to treat registry answers as authoritative.
func (g *BootstrapGrant) Absorb(module string, raw []byte) []string {
	if g == nil {
		return nil
	}
	hosts := hostsFromBootstrap(raw)

	g.mu.Lock()
	defer g.mu.Unlock()
	set := g.granted[module]
	if set == nil {
		set = map[string]bool{}
		g.granted[module] = set
	}
	added := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if set[h] {
			continue
		}
		if len(set) >= g.maxHostsFor() {
			break
		}
		set[h] = true
		added = append(added, h)
	}
	sortStrings(added)
	return added
}

// hostsFromBootstrap extracts hosts from every https URL appearing anywhere in a
// bootstrap document.
//
// It walks the decoded JSON generically rather than assuming the published shape.
// A collector that breaks when IANA reorders a field would be a collector that
// silently stops working, which is worse than being liberal about structure.
func hostsFromBootstrap(raw []byte) []string {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if h := httpsHost(t); h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(doc)
	return out
}

// httpsHost returns the host of an https URL, or an empty string for anything else.
func httpsHost(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 9 || !strings.EqualFold(s[:8], "https://") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
		return ""
	}
	// A document naming a loopback or private endpoint must not be able to steer
	// egress there. The SSRF guard still applies at dial time, but refusing it here
	// keeps the granted set honest.
	if isInternalHost(h) {
		return ""
	}
	return h
}

func isInternalHost(h string) bool {
	switch {
	case h == "localhost", h == "localhost.localdomain", h == "metadata.google.internal":
		return true
	case strings.HasSuffix(h, ".localhost"), strings.HasSuffix(h, ".internal"),
		strings.HasSuffix(h, ".local"):
		return true
	}
	ip, err := parseIPHost(h)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// parseIPHost parses a host as an IP address.
func parseIPHost(h string) (netip.Addr, error) {
	return netip.ParseAddr(strings.Trim(h, "[]"))
}
