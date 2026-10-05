package ctsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// A certificate log entry proves one thing: a certificate bearing these names was
// logged. It does not prove the target operates those hosts, that the certificate
// is still valid, or that whoever requested it was authorized. Those are different
// claims with different grades, and conflating them is how a CT module ends up
// reporting a stranger's test certificate as an asset.
const (
	// gradeLogged proves a name appeared in a transparency log.
	gradeReliability = 'B'
	gradeCredibility = '1'
)

// entry is one certificate observation, normalized across providers.
type entry struct {
	// names are the subject alternative names the certificate carried.
	names []string
	// issuerDName is the certificate authority's directory name.
	issuerDName string
	// issuerOrg is the CA organization when the provider publishes one separately.
	issuerOrg string
	// certSHA256 is a real DER digest. It is empty unless the provider supplies one:
	// a serial number is not a fingerprint, and inventing one would create a
	// certificate entity that looks verifiable but is not.
	certSHA256 string
	// serialNumber is the certificate serial, in hex.
	serialNumber string
	notBefore    string
	notAfter     string
	// revoked marks a certificate the CA has revoked. It is a finding in its own
	// right: a revoked certificate still appears in the log, so treating it as live
	// would report a credential the holder is no longer entitled to use.
	revoked bool
	// provider records which adapter produced this entry, so independence grouping
	// in the scorer does not count one log twice.
	provider string
}

// adapter is one CT data source. Each is independently testable and independently
// killable, because these providers are volunteer-run and go down without notice.
type adapter interface {
	// name identifies the adapter.
	name() string
	// hosts returns the domains this adapter may contact.
	hosts() []string
	// requiresKey reports whether the adapter is unusable without an API key.
	requiresKey() bool
	// fetch retrieves entries for a registrable domain. The emitter is supplied so
	// the raw response can be retained through the engine's evidence path, which is
	// what links the artifact to the findings derived from it. Retaining it via
	// Deps.Blobs instead would lose the scan and case binding.
	fetch(ctx context.Context, d sdk.Deps, e sdk.Emitter, domain string, method, url string) ([]entry, error)
	// buildURL returns the request URL, exposed so tests can assert it without a
	// network round trip.
	buildURL(domain string) string
}

// --- crt.sh ---

// crtSh reads crt.sh's JSON search index.
//
// The index is enormous, slow, and frequently returns 502 under load, so it is
// treated as best-effort: partial results with a visible warning beat a failed
// lookup presented as "nothing found".
type crtSh struct {
	baseURL string
}

func newCrtSh() *crtSh {
	return &crtSh{baseURL: "https://crt.sh/"}
}

func (c *crtSh) name() string      { return "crtsh" }
func (c *crtSh) hosts() []string   { return []string{"crt.sh"} }
func (c *crtSh) requiresKey() bool { return false }

// buildURL returns crt.sh's search URL.
//
// The leading %. is crt.sh's own wildcard syntax: a plain query returns only
// certificates whose common name matches exactly, so searching for a registrable
// domain without it would miss every subdomain certificate. That is the single
// most common way a CT collector silently returns almost nothing.
func (c *crtSh) buildURL(domain string) string {
	return c.baseURL + "?q=" + urlEscape("%."+domain) + "&output=json"
}

// crtShRow is one row of crt.sh's JSON output. name_value carries every name in the
// certificate, newline separated.
type crtShRow struct {
	IssuerCaID   json.Number `json:"issuer_ca_id"`
	IssuerName   string      `json:"issuer_name"`
	IssuerOrg    string      `json:"issuer_org"`
	CommonName   string      `json:"common_name"`
	NameValue    string      `json:"name_value"`
	ID           json.Number `json:"id"`
	CertID       json.Number `json:"cert_id"`
	SerialNumber string      `json:"serial_number"`
	EntryTime    string      `json:"entry_timestamp"`
	NotBefore    string      `json:"not_before"`
	NotAfter     string      `json:"not_after"`
	ResultCount  json.Number `json:"result_count"`
}

func (c *crtSh) fetch(ctx context.Context, d sdk.Deps, e sdk.Emitter, domain, method, _ string) ([]entry, error) {
	if d.HTTP == nil {
		return nil, fmt.Errorf("ct-search: no HTTP client")
	}
	url := c.buildURL(domain)
	raw, err := getJSON(ctx, d, e, url, "application/json", method)
	if err != nil {
		return nil, err
	}
	var rows []crtShRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("ct-search: parse crt.sh response: %w", err)
	}

	out := make([]entry, 0, len(rows))
	for _, r := range rows {
		names := splitNames(r.NameValue)
		if len(names) == 0 {
			names = splitNames(r.CommonName)
		}
		if len(names) == 0 {
			continue
		}
		e := entry{
			names:        names,
			issuerDName:  strings.TrimSpace(r.IssuerName),
			issuerOrg:    strings.TrimSpace(r.IssuerOrg),
			serialNumber: normalizeSerial(r.SerialNumber),
			notBefore:    r.NotBefore,
			notAfter:     r.NotAfter,
			provider:     c.name(),
		}
		out = append(out, e)
	}
	return out, nil
}

// splitNames parses the newline-separated name field these providers use.
func splitNames(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		for _, part := range strings.Split(line, "\r") {
			n := strings.ToLower(strings.TrimSpace(part))
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// normalizeSerial strips the colons and case registries vary on.
func normalizeSerial(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return ""
	}
	return s
}

// --- Certspotter ---

// certspotter reads SSLMate's Certspotter API.
//
// It publishes a real certificate digest, so this is the adapter that can produce
// verifiable certificate entities.
type certspotter struct {
	baseURL string
	apiKey  string
}

func newCertspotter(apiKey string) *certspotter {
	return &certspotter{baseURL: "https://api.certspotter.com/v1/issuances", apiKey: apiKey}
}

func (c *certspotter) name() string      { return "certspotter" }
func (c *certspotter) hosts() []string   { return []string{"api.certspotter.com"} }
func (c *certspotter) requiresKey() bool { return false }

// buildURL returns Certspotter's query URL.
//
// The expand parameter must be repeated rather than comma-joined. Commas look like
// they should work and do not: the API silently ignores the malformed value and
// returns its default response, which omits dns_names entirely. A collector sending
// the comma form gets zero names back and no error at all, which is the worst
// possible failure for a discovery module -- it reports a clean result while having
// looked at nothing.
func (c *certspotter) buildURL(domain string) string {
	return c.baseURL +
		"?domain=" + urlEscape(domain) +
		"&include_subdomains=true" +
		"&expand=dns_names" +
		"&expand=issuer"
}

type certspotterIssuance struct {
	ID         string   `json:"id"`
	CertSHA256 string   `json:"cert_sha256"`
	TBSSHA256  string   `json:"tbs_sha256"`
	DNSNames   nameList `json:"dns_names"`
	Revoked    bool     `json:"revoked"`
	Issuer     struct {
		// FriendlyName is the CA's display name; Name is the full DN.
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
		PubKeySHA256 string `json:"pubkey_sha256"`
	} `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// nameList decodes a name field that providers publish either as a JSON array or as
// one newline-separated string. Certspotter returns an array and crt.sh returns a
// string; accepting both means a provider changing its encoding does not turn into a
// parse failure that reads as "no names found".
type nameList []string

func (n *nameList) UnmarshalJSON(data []byte) error {
	// Try an array first.
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*n = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// A null field is legitimate and means no names.
		*n = nil
		return nil
	}
	*n = splitNames(s)
	return nil
}

func (c *certspotter) fetch(ctx context.Context, d sdk.Deps, e sdk.Emitter, domain, method, _ string) ([]entry, error) {
	if d.HTTP == nil {
		return nil, fmt.Errorf("ct-search: no HTTP client")
	}
	url := c.buildURL(domain)
	raw, err := getJSONWithHeaders(ctx, d, e, url, nil, "application/json", method)
	if err != nil {
		return nil, err
	}
	var issuances []certspotterIssuance
	if err := json.Unmarshal(raw, &issuances); err != nil {
		return nil, fmt.Errorf("ct-search: parse certspotter response: %w", err)
	}

	out := make([]entry, 0, len(issuances))
	for _, i := range issuances {
		names := splitNames(i.DNSNames.join())
		if len(names) == 0 {
			continue
		}
		out = append(out, entry{
			names:       names,
			issuerDName: strings.TrimSpace(i.Issuer.Name),
			issuerOrg:   issuerLabel(i.Issuer.FriendlyName, i.Issuer.Name),
			certSHA256:  strings.ToLower(strings.TrimSpace(i.CertSHA256)),
			notBefore:   i.NotBefore,
			notAfter:    i.NotAfter,
			revoked:     i.Revoked,
			provider:    c.name(),
		})
	}
	return out, nil
}

// join renders a decoded name list back into the newline-separated form splitNames
// expects.
func (n nameList) join() string { return strings.Join(n, "\n") }

// issuerLabel picks the most readable name a provider published for a CA.
func issuerLabel(friendly, dn string) string {
	if f := strings.TrimSpace(friendly); f != "" {
		return f
	}
	// The DN is the only fallback. Its organization component is the closest thing
	// to a name, so extract that rather than emitting the whole DN as an
	// organization entity.
	if o := dnComponent(dn, "O"); o != "" {
		return o
	}
	if cn := dnComponent(dn, "CN"); cn != "" {
		return cn
	}
	return ""
}

// dnComponent pulls one component out of an RFC 4514 distinguished name.
//
// The grammar allows escaped commas inside a value, so a plain split on "," would
// truncate any name containing one. This walks the string instead.
func dnComponent(dn, key string) string {
	var cur strings.Builder
	var want strings.Builder
	type field struct{ k, v string }
	var fields []field
	escaped := false
	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" {
			return
		}
		k, v, found := strings.Cut(s, "=")
		if !found {
			return
		}
		fields = append(fields, field{k: strings.ToUpper(strings.TrimSpace(k)), v: unescapeDN(strings.TrimSpace(v))})
	}
	for i := 0; i < len(dn); i++ {
		ch := dn[i]
		switch {
		case escaped:
			cur.WriteByte(ch)
			escaped = false
		case ch == '\\':
			escaped = true
		case ch == ',':
			flush()
		default:
			cur.WriteByte(ch)
		}
	}
	flush()

	want.Reset()
	for _, f := range fields {
		if f.k == strings.ToUpper(key) {
			if want.Len() > 0 {
				want.WriteString(", ")
			}
			want.WriteString(f.v)
		}
	}
	return want.String()
}

func unescapeDN(v string) string {
	if !strings.Contains(v, "\\") {
		return v
	}
	var b strings.Builder
	esc := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if esc {
			b.WriteByte(c)
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// --- shared helpers ---

// getJSON performs a bounded GET, retains the response, and returns it.
//
// The raw body is retained before it is parsed or size-checked, so that even a
// response Argus refused to use remains available for an analyst to inspect.
func getJSON(ctx context.Context, d sdk.Deps, e sdk.Emitter, url, accept, method string) ([]byte, error) {
	return getJSONWithHeaders(ctx, d, e, url, nil, accept, method)
}

func getJSONWithHeaders(ctx context.Context, d sdk.Deps, e sdk.Emitter, url string, headers map[string]string, accept, method string) ([]byte, error) {
	req, err := newGet(ctx, url, accept, headers)
	if err != nil {
		return nil, err
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, truncated, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 400 && d.Blobs != nil {
		if _, perr := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source: url, Method: method, MediaType: accept,
		}, data); perr != nil {
			e.Warn("evidence capture failed", "url", url, "err", perr.Error())
		}
	}

	if truncated {
		// A truncated CT index parses into a plausible but incomplete name list,
		// which reads as "these are all the hosts" rather than "I lost data here".
		return nil, fmt.Errorf("ct-search: response from %s exceeded the size limit", url)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ct-search: %s returned HTTP %d", url, resp.StatusCode)
	}
	return data, nil
}

// sortedUnique returns a sorted, deduplicated copy.
func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func urlEscape(s string) string {
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
