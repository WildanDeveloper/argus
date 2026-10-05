package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// DoHResolver resolves DNS over HTTPS through the egress broker.
//
// A module must never open a socket itself, so DNS goes through the same broker
// as HTTP: scope checks, rate limits, caching, and the audit log apply to name
// resolution exactly as they do to a web request. A scan that resolved DNS
// outside the broker would leak every target name to an unlogged path.
type DoHResolver struct {
	client *Client
	// providers are queried in order until `consensus` agree.
	providers []dohProvider
	// consensus is how many independent providers must return the same answer
	// before a name is trusted. Requiring agreement is what makes a poisoned
	// answer unlikely: an attacker must control every provider consulted.
	consensus int
	timeout   time.Duration
}

type dohProvider struct {
	name string
	// urlTemplate takes a wire-format query in base64url (no padding).
	urlTemplate string
}

// defaultDoHProviders are the two most widely deployed resolvers. Using more than
// one is the point: a single provider's view is an opinion, not a fact.
// Three providers, so one being down or slow does not cost a lookup: consensus is
// two, and a third supplies the redundancy that makes two achievable in practice.
var defaultDoHProviders = []dohProvider{
	{name: "cloudflare", urlTemplate: "https://cloudflare-dns.com/dns-query?name=%s&type=%s"},
	{name: "google", urlTemplate: "https://dns.google/resolve?name=%s&type=%s"},
	{name: "adguard", urlTemplate: "https://dns.adguard-dns.com/resolve?name=%s&type=%s"},
}

// ResolverHosts returns the hosts a DNS lookup will contact, for the scope guard
// and for module manifests.
func ResolverHosts(providers []dohProvider) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range providers {
		host := hostFromURL(p.urlTemplate)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func hostFromURL(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?"); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.LastIndexByte(rest, ':'); j >= 0 && !strings.Contains(rest[j:], "]") {
		if _, err := netipPort(rest[j+1:]); err == nil {
			rest = rest[:j]
		}
	}
	return strings.ToLower(rest)
}

func netipPort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty port")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("bad port")
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, nil
}

var _ sdk.DNSResolver = (*DoHResolver)(nil)

// NewDoHResolver builds a resolver over the supplied broker client.
func NewDoHResolver(client *Client, consensus int) *DoHResolver {
	if consensus < 1 {
		consensus = 2
	}
	return &DoHResolver{
		client:    client,
		providers: defaultDoHProviders,
		consensus: consensus,
		timeout:   10 * time.Second,
	}
}

// Providers exposes the configured providers for scope wiring.
func (r *DoHResolver) Providers() []string {
	out := make([]string, len(r.providers))
	for i, p := range r.providers {
		out[i] = p.name
	}
	return out
}

// Hosts returns the hosts the resolver contacts.
func (r *DoHResolver) Hosts() []string { return ResolverHosts(r.providers) }

// dnsJSONResponse is the shared JSON shape served by Cloudflare, Google, and
// Quad9. Only the fields Argus needs are decoded.
type dnsJSONResponse struct {
	Status int `json:"Status"` // 0 NOERROR, 3 NXDOMAIN
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
	Authority []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Authority"`
}

// rrTypes maps the record type names Argus uses to the numeric DNS types, so a
// caller can pass either.
var rrTypes = map[string]int{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
	"AAAA": 28, "SRV": 33, "DS": 43, "SSHFP": 44, "RRSIG": 46, "NSEC": 47,
	"DNSKEY": 48, "NSEC3": 50, "TLSA": 52, "SVCB": 64, "HTTPS": 65, "CAA": 257,
}

// rrTypeNames maps numeric DNS types back to names.
var rrTypeNames = map[int]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 43: "DS", 44: "SSHFP", 46: "RRSIG", 47: "NSEC",
	48: "DNSKEY", 50: "NSEC3", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 257: "CAA",
}

// Lookup resolves name/rrType with multi-provider consensus.
func (r *DoHResolver) Lookup(ctx context.Context, name, rrType string) ([]sdk.DNSRecord, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil, fmt.Errorf("egress: empty DNS name")
	}
	rrType = strings.ToUpper(strings.TrimSpace(rrType))
	if rrType == "" {
		rrType = "A"
	}
	if _, ok := rrTypes[rrType]; !ok {
		return nil, fmt.Errorf("egress: unsupported record type %q", rrType)
	}

	// Query providers concurrently: a sequential loop would make a 3-provider
	// consensus take three timeouts when the first provider is slow.
	type result struct {
		provider string
		status   int
		answers  []sdk.DNSRecord
		err      error
	}
	results := make(chan result, len(r.providers))
	qctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	for _, p := range r.providers {
		p := p
		go func() {
			status, answers, err := r.query(qctx, p, name, rrType)
			results <- result{provider: p.name, status: status, answers: answers, err: err}
		}()
	}

	// agreement counts how many providers produced this exact answer set.
	agreement := map[string]int{}
	firstByKey := map[string][]sdk.DNSRecord{}
	agreedProviders := map[string][]string{}
	var lastErr error
	var nxdomain bool

	for range r.providers {
		res := <-results
		if res.err != nil {
			lastErr = res.err
			continue
		}
		if res.status == 3 { // NXDOMAIN
			nxdomain = true
			continue
		}
		if len(res.answers) == 0 {
			continue
		}
		key := answerKey(res.answers)
		agreement[key]++
		firstByKey[key] = res.answers
		agreedProviders[key] = append(agreedProviders[key], res.provider)
	}

	// Pick the answer set with the most provider agreement, breaking ties by
	// provider name so the result is deterministic.
	bestKey := ""
	bestCount := 0
	for k, c := range agreement {
		if c > bestCount || (c == bestCount && k < bestKey) {
			bestKey, bestCount = k, c
		}
	}

	if bestCount == 0 {
		if nxdomain {
			// NXDOMAIN agreed (or was the only answer) is a real, reportable
			// result: the name does not exist.
			return nil, nil
		}
		if lastErr != nil {
			return nil, fmt.Errorf("egress: DNS lookup %s %s failed: %w", name, rrType, lastErr)
		}
		// No answer, but also no NXDOMAIN: the name exists with no records of this
		// type, or every provider failed silently.
		return nil, nil
	}
	if bestCount < r.consensus {
		return nil, fmt.Errorf("egress: no resolver consensus for %s %s (only %d of %d providers agreed: %v)",
			name, rrType, bestCount, r.consensus, agreedProviders[bestKey])
	}

	answers := firstByKey[bestKey]
	// Stamp the record name and type so consumers do not have to re-derive them.
	for i := range answers {
		if answers[i].Name == "" {
			answers[i].Name = name
		}
		if answers[i].Type == "" {
			answers[i].Type = rrType
		}
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].Data < answers[j].Data })
	return answers, nil
}

// query performs one DoH request.
func (r *DoHResolver) query(ctx context.Context, p dohProvider, name, rrType string) (int, []sdk.DNSRecord, error) {
	u := fmt.Sprintf(p.urlTemplate, urlQueryEscape(name), urlQueryEscape(rrType))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	// An honest Accept and a JSON response: no attempt to look like a browser.
	req.Header.Set("User-Agent", "Argus/doh")

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	data, truncated, err := ReadAllBounded(resp.Body, 1<<20)
	if err != nil {
		return 0, nil, err
	}
	if truncated {
		return 0, nil, fmt.Errorf("egress: DoH response from %s exceeded 1 MiB", p.name)
	}

	var parsed dnsJSONResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return 0, nil, fmt.Errorf("egress: parse DoH response from %s: %w", p.name, err)
	}
	if parsed.Status != 0 && parsed.Status != 3 {
		return parsed.Status, nil, fmt.Errorf("egress: %s returned DNS status %d", p.name, parsed.Status)
	}

	out := make([]sdk.DNSRecord, 0, len(parsed.Answer))
	for _, a := range parsed.Answer {
		rec := sdk.DNSRecord{
			Name: strings.TrimSuffix(strings.ToLower(a.Name), "."),
			Type: rrTypeNames[a.Type],
			Data: a.Data,
		}
		if rec.Type == "" {
			rec.Type = rrType
		}
		if a.TTL > 0 {
			rec.TTL = uint32(a.TTL)
		}
		// Normalize the provider's presentation formats into the canonical forms
		// the SDK expects, so a consumer never has to know which resolver answered.
		switch rec.Type {
		case "A", "AAAA":
			ip, err := sdk.Canonicalize(sdk.TypeIP, rec.Data)
			if err != nil {
				continue // skip an unparsable address rather than storing garbage
			}
			rec.Data = ip
		case "CNAME", "NS", "PTR":
			rec.Data = strings.TrimSuffix(strings.ToLower(rec.Data), ".")
		case "MX", "SRV":
			pref, host := splitPreference(rec.Data)
			rec.Pref = pref
			rec.Data = host
		case "TXT":
			rec.Data = unquoteTXT(rec.Data)
		case "CAA":
			// "<flags> <tag> <value>"
			if f := strings.Fields(rec.Data); len(f) == 3 {
				rec.Data = f[1] + ";" + f[2]
			}
		}
		out = append(out, rec)
	}
	return parsed.Status, out, nil
}

// answerKey renders an answer set as a comparable key for agreement counting.
//
// TTL is deliberately excluded. It is cache metadata, not part of the answer: two
// resolvers answering identically will report different remaining TTLs, so
// including it would mean two correct resolvers could never agree and every
// lookup would fail consensus. Preference is kept, because for MX and SRV it
// genuinely changes which host is tried first.
func answerKey(recs []sdk.DNSRecord) string {
	parts := make([]string, 0, len(recs))
	for _, r := range recs {
		parts = append(parts, fmt.Sprintf("%s:%d:%s", r.Type, r.Pref, r.Data))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// splitPreference parses "10 mail.example.com." into preference and host.
func splitPreference(data string) (uint16, string) {
	f := strings.Fields(data)
	if len(f) != 2 {
		return 0, strings.TrimSuffix(strings.ToLower(data), ".")
	}
	var pref uint16
	fmt.Sscanf(f[0], "%d", &pref)
	return pref, strings.TrimSuffix(strings.ToLower(f[1]), ".")
}

// unquoteTXT normalizes a TXT record's presentation format.
//
// A TXT record is a sequence of quoted character-strings, and a record longer than
// 255 bytes is split across several of them, so the parts must be concatenated.
// Resolvers disagree about whether to quote: Cloudflare returns "v=spf1 -all" and
// Google returns v=spf1 -all for the same record, and the two must become one value
// or consensus between those providers can never be reached.
//
// Whitespace is only stripped between quoted strings, never inside them: a TXT
// value such as "v=spf1 -all" contains a meaningful space, and dropping it would
// corrupt SPF, DKIM, and verification-token records.
func unquoteTXT(data string) string {
	if !strings.Contains(data, `"`) {
		// No quoting at all: the value is already bare, so copy it verbatim.
		return strings.TrimSpace(data)
	}
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch c {
		case '"':
			inQuote = !inQuote
		case '\\':
			// A backslash escapes the next character; keep it literally.
			if i+1 < len(data) {
				i++
				b.WriteByte(data[i])
			}
		case ' ', '\t':
			// Separators between character-strings only.
			if inQuote {
				b.WriteByte(c)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// urlQueryEscape percent-encodes a DNS name or type for a query string.
func urlQueryEscape(s string) string {
	const hexdigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '*' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexdigits[c>>4])
		b.WriteByte(hexdigits[c&0x0f])
	}
	return b.String()
}
