package passive

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// adapter is one passive source.
//
// weight is how much a single sighting from this source is worth relative to the
// others. It is a property of the source, not of the answer: RapidDNS indexes
// certificate transparency and historical DNS and so overlaps heavily with sources
// already queried, while HackerTarget resolves names against live DNS. Two sources
// with the same corpus should not be able to outvote an independent one between them,
// and a weight is the only place that distinction can live.
type adapter interface {
	name() string
	host() string
	// weight is this source's contribution to an aggregate score.
	weight() float64
	buildURL(domain string) string
	// parse turns the response into host names and, where the source publishes them,
	// the address reported alongside each name.
	parse(raw []byte) ([]string, map[string]string, error)
	// wantsHTML reports the Accept header this source expects. It is part of the
	// adapter rather than a lookup table so a source cannot be added without saying
	// what it speaks.
	wantsHTML() bool
}

func fetchOne(ctx context.Context, a adapter, m *Module, e sdk.Emitter, domain string) ([]string, map[string]string, error) {
	url := a.buildURL(domain)
	raw, err := m.get(ctx, e, url, acceptFor(a), "passive."+a.name())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", a.name(), err)
	}
	return a.parse(raw)
}

func acceptFor(a adapter) string {
	if a.wantsHTML() {
		return "text/html"
	}
	return "text/plain"
}

func defaultAdapters() []adapter {
	// Only the sources that need no key are configured. The rest are named in
	// unavailableSources rather than being absent, because "this module looked in three
	// places" and "this module looked everywhere it could" are different claims.
	return []adapter{
		newRapidDNS(),
		newHackerTarget(),
	}
}

// keylessButUnavailable names the sources that would extend this module's coverage
// but need a key this build does not have.
//
// They are reported rather than omitted. An operator reading a report that says three
// passive sources were consulted should not conclude that three is all there is.
func unavailableSources() []string {
	return []string{
		"alienvault-otx (optional key)",
		"binaryedge (key)",
		"censys (key)",
		"chaos (key)",
		"circl-passive-dns (approved account)",
		"commoncrawl (no key; index returned 504 on every attempt when this was written)",
		"fullhunt (key)",
		"netlas (key)",
		"rapiddns (covered)",
		"shodan (key)",
		"urlscan.io (optional key)",
		"virustotal (key)",
		"whoisxml (key)",
	}
}

// --- HackerTarget ---

// hackertarget reads HackerTarget's hostsearch endpoint.
//
// Its answer is CSV of "host,address" and it resolves names against live DNS, so its
// sightings are more likely to correspond to something currently reachable than a
// historical index's. That is why it carries the higher weight.
type hackertarget struct{ base string }

func newHackerTarget() *hackertarget {
	return &hackertarget{base: "https://api.hackertarget.com/hostsearch"}
}

func (h *hackertarget) name() string { return "hackertarget" }
func (h *hackertarget) host() string { return "api.hackertarget.com" }
func (h *hackertarget) weight() float64 {
	return 0.6
}

func (h *hackertarget) wantsHTML() bool { return false }

func (h *hackertarget) buildURL(domain string) string {
	return h.base + "/?q=" + queryEscape(domain)
}

func (h *hackertarget) parse(raw []byte) ([]string, map[string]string, error) {
	var names []string
	ips := map[string]string{}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// The service answers over its quota with an HTML or plain sentence rather
		// than CSV. Parsing that as a record would produce one hostname-shaped token
		// at most, and reporting zero found names while having been told nothing would
		// be the worst outcome.
		if looksLikeRefusal(line) {
			return nil, nil, fmt.Errorf("service returned a refusal: %s", truncate(line, 120))
		}
		host, addr, _ := strings.Cut(line, ",")
		host = strings.TrimSpace(host)
		if host == "" || !strings.Contains(host, ".") {
			continue
		}
		names = append(names, host)
		if addr = strings.TrimSpace(addr); addr != "" && looksLikeAddress(addr) {
			ips[host] = addr
		}
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("response carried no host rows; the endpoint is CSV and this was not")
	}
	return names, ips, nil
}

// looksLikeAddress checks for a dotted quad. Anything else in that column is not an
// address and must not become an IP entity.
func looksLikeAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

var refusalPatterns = []string{
	"api count exceeded", "exceeded the maximum", "error", "invalid",
	"rate limit", "too many requests", "quota", "upgrade", "unauthorized",
	"api key", "please contact", "try again later", "unavailable",
	"no results", "check your query", "invalid query",
}

// looksLikeRefusal recognizes a service answering in prose instead of data.
//
// The list is deliberately broad and leans toward false positives, because the cost of
// skipping a source is a warning while the cost of parsing a refusal is a silently
// invented result.
func looksLikeRefusal(line string) bool {
	l := strings.ToLower(line)
	if strings.Contains(l, ",") {
		// A real CSV row has a comma; a refusal rarely does.
		return false
	}
	for _, p := range refusalPatterns {
		if strings.Contains(l, p) {
			return true
		}
	}
	// A row of prose is long, contains spaces, and is not a host name.
	if strings.Contains(l, " ") && !strings.Contains(l, ".") {
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- RapidDNS ---

// rapiddns reads RapidDNS's subdomain table.
//
// The page is HTML with a table whose first column is the name, so the names come from
// cells rather than from links. Parsing it as a document is fragile in a way JSON is
// not, and that fragility is stated in the manifest rate hint rather than hidden: a
// markup change produces an empty result with a warning, not a silent one.
type rapiddns struct{ base string }

func newRapidDNS() *rapiddns {
	return &rapiddns{base: "https://rapiddns.io/subdomain"}
}

func (r *rapiddns) name() string { return "rapiddns" }
func (r *rapiddns) host() string { return "rapiddns.io" }

// RapidDNS aggregates certificate transparency and historical DNS, so its corpus
// overlaps sources already in the graph. A single sighting from it is a weaker lead
// than one from a source that resolves against live DNS.
func (r *rapiddns) weight() float64 { return 0.4 }

func (r *rapiddns) wantsHTML() bool { return true }

func (r *rapiddns) buildURL(domain string) string {
	return r.base + "/" + queryEscape(domain) + "?full=1"
}

// tdPattern captures the contents of a table cell.
var tdPattern = regexp.MustCompile(`(?is)<td[^>]*>(.*?)</td>`)

// linkPattern captures the anchor text of a cell, which is where the address is.
var linkPattern = regexp.MustCompile(`(?is)<a[^>]*>(.*?)</a>`)

func (r *rapiddns) parse(raw []byte) ([]string, map[string]string, error) {
	body := string(raw)

	// The table only appears when there are results. Its absence with an HTTP 200 is
	// the service's way of saying it holds nothing.
	if !strings.Contains(body, "<td") {
		if looksLikeChallenge(body) {
			return nil, nil, fmt.Errorf("the endpoint returned an interstitial rather than results")
		}
		return nil, nil, fmt.Errorf("no result table in the response")
	}

	var names []string
	ips := map[string]string{}
	for _, cell := range tdPattern.FindAllStringSubmatch(body, -1) {
		value := strings.TrimSpace(unescape(stripTags(cell[1])))
		if value == "" || !looksLikeHost(value) {
			continue
		}
		// The name cell carries the host; the following cell carries a link whose text
		// is the address. Matching by column would break on any stray cell, so the
		// address is taken from within the same cell only when it appears there.
		names = append(names, value)
		if m := linkPattern.FindStringSubmatch(cell[1]); len(m) == 2 {
			if addr := strings.TrimSpace(unescape(stripTags(m[1]))); looksLikeAddress(addr) {
				ips[value] = addr
			}
		}
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("the result table carried no host names")
	}
	return names, ips, nil
}

var tagPattern = regexp.MustCompile(`(?s)<[^>]*>`)

func stripTags(s string) string { return tagPattern.ReplaceAllString(s, " ") }

func looksLikeHost(s string) bool {
	if !strings.Contains(s, ".") || strings.Contains(s, " ") || strings.Contains(s, "/") {
		return false
	}
	// A number with dots is an address in the name column, which would be an error in
	// the source rather than a host.
	return !looksLikeAddress(s)
}

func looksLikeChallenge(body string) bool {
	l := strings.ToLower(body)
	for _, m := range []string{"captcha", "are you a human", "cloudflare", "checking your browser", "cf-browser-verification"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// queryEscape percent-encodes a value for use in a query string or path segment.
func queryEscape(s string) string {
	const hexdigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexdigits[c>>4])
		b.WriteByte(hexdigits[c&0x0f])
	}
	return b.String()
}
