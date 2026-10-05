// Package wayback reads the Internet Archive's CDX index for historical host names
// and URLs under a domain.
//
// This module's defining constraint is that its evidence is inherently about the
// past. A capture proves the archive fetched a URL on a date; it says nothing about
// whether the host resolves today. Reporting an archived name as a live subdomain
// without that qualifier would put a dead host into the graph as if it were a
// finding, and every downstream module would then treat it as a real pivot target.
package wayback

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/canon"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// Archive grades: the CDX index is authoritative about its own holdings but is a
// volunteer-run third party, so it is "usually reliable" rather than authoritative.
// A capture is probably-not-corroborated evidence that the host once served
// something, which is credibility 2.
const (
	gradeReliability = 'B'
	gradeCredibility = '2'
)

// Module is the wayback collector.
type Module struct {
	http sdk.HTTPDoer
	now  func() time.Time

	baseURL string
	// maxCaptures bounds how many CDX rows one run will request and parse. The index
	// holds hundreds of millions of rows for a popular domain; a bounded read with a
	// visible truncation is honest, an unbounded one stalls the pipeline.
	maxCaptures int
	// maxHosts bounds how many distinct host names are emitted.
	maxHosts     int
	keepEvidence bool
}

// Option configures the module.
type Option func(*Module)

// WithHTTPDoer injects the brokered client.
func WithHTTPDoer(h sdk.HTTPDoer) Option { return func(m *Module) { m.http = h } }

// WithBaseURL overrides the CDX endpoint so tests make no outbound request.
func WithBaseURL(u string) Option { return func(m *Module) { m.baseURL = u } }

// WithMaxCaptures bounds the rows requested and parsed.
func WithMaxCaptures(n int) Option {
	return func(m *Module) {
		if n > 0 {
			m.maxCaptures = n
		}
	}
}

// WithMaxHosts bounds the distinct host names emitted.
func WithMaxHosts(n int) Option {
	return func(m *Module) {
		if n > 0 {
			m.maxHosts = n
		}
	}
}

// WithEvidence turns artifact retention on or off.
func WithEvidence(on bool) Option { return func(m *Module) { m.keepEvidence = on } }

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{
		now:          time.Now,
		baseURL:      "https://web.archive.org/cdx/search/cdx",
		maxCaptures:  5000,
		maxHosts:     2000,
		keepEvidence: true,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "wayback",
		Version:     Version,
		Category:    "domain",
		Description: "Historical host names and URLs from the Internet Archive CDX index",
		Consumes:    []sdk.EntityType{sdk.TypeDomain},
		Produces:    []sdk.EntityType{sdk.TypeSubdomain, sdk.TypeURL, sdk.TypeFinding},
		// The Archive is a third party reading its own public index. The target is
		// never contacted, so this is passive.
		Mode:        sdk.ModePassive,
		Sensitivity: sdk.SensLow,
		EgressHosts: []string{"web.archive.org"},
		RateHints: map[string]sdk.Rate{
			// The Archive asks for well under one request per second and throttles
			// or blocks sustained callers. Being a good citizen here is the point of
			// the hint, not staying under a quota.
			"web.archive.org": {Requests: 1, Per: 2 * time.Second, Burst: 2},
		},
		Tags: []string{"historical", "passive", "discovery"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.HTTP == nil {
		return fmt.Errorf("wayback: no HTTP client injected")
	}
	m.http = d.HTTP
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// Run queries the CDX index and reports what it holds for the domain.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("wayback: task has no target")
	}
	domain := canon.RegistrableDomain(t.Target.Value)
	if domain == "" {
		return nil
	}

	query := m.buildURL(domain)
	raw, err := m.get(ctx, e, query)
	if err != nil {
		return err
	}

	rows, err := parseCDX(raw)
	if err != nil {
		return err
	}

	hosts := aggregate(rows, domain)
	// Nothing archived is a fact about the Archive's holdings, not about the
	// target. It is reported so a reader does not mistake an empty result for a
	// claim that no such host ever existed.
	if len(hosts) == 0 {
		return m.emitNoCaptures(t, e, domain, query, len(rows))
	}

	sorted := make([]*hostRecord, 0, len(hosts))
	for _, h := range hosts {
		sorted = append(sorted, h)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].host < sorted[j].host })

	truncated := false
	if len(sorted) > m.maxHosts {
		sorted = sorted[:m.maxHosts]
		truncated = true
		e.Warn("host set truncated", "domain", domain, "found", len(hosts), "limit", m.maxHosts)
	}

	source := sdk.Source{Module: "wayback", Provider: "web.archive.org", Method: "cdx.search"}
	newObs := func(predicate string, object any) sdk.Observation {
		return sdk.Observation{
			Predicate:   predicate,
			Object:      object,
			Source:      source,
			Reliability: gradeReliability,
			Credibility: gradeCredibility,
			ObservedAt:  m.now(),
		}
	}

	emitted := 0
	for _, h := range sorted {
		if h.host == domain {
			// The apex is already in the graph. Emitting it as its own subdomain
			// would be a self-loop.
			continue
		}
		ent, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, h.host)
		if err != nil {
			continue
		}
		obs := newObs("archived_in_wayback", h.host)
		// Rendered as RFC 3339 rather than the raw CDX stamp: the raw form is a
		// number that sorts correctly as a string but reads as noise, and a consumer
		// parsing it as a date gets nonsense.
		obs.AddAttr("first_seen", cdTimestamp(h.firstSeen))
		obs.AddAttr("last_seen", cdTimestamp(h.lastSeen))
		obs.AddAttr("capture_count", h.captures)
		// Every finding from this module is about the past. The flag is on the
		// observation rather than left implicit so a consumer cannot mistake an
		// archived name for a resolved host.
		obs.AddAttr("historical", true)
		if err := e.Emit(sdk.Finding{
			Entity:      ent,
			Relations:   []sdk.Relation{sdk.HeuristicRel(ent.ID, t.Target.ID, sdk.RelSubdomainOf)},
			Observation: obs,
			Kind:        "wayback-archived-host",
			Severity:    sdk.SevInfo,
		}); err != nil {
			return err
		}
		emitted++
	}

	summary := newObs("wayback_summary", domain)
	summary.AddAttr("rows_parsed", len(rows))
	summary.AddAttr("hosts_found", len(hosts))
	summary.AddAttr("hosts_emitted", emitted)
	summary.AddAttr("query_limit", m.maxCaptures)
	// The window is the span of what was actually read, not the domain's lifetime.
	// The two are wildly different for a popular domain.
	summary.AddAttr("sampled", true)
	summary.AddAttr("truncated", truncated)
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: summary,
		Kind:        "wayback-summary",
	})
}

// emitNoCaptures reports an index with no holdings for the domain.
func (m *Module) emitNoCaptures(t sdk.Task, e sdk.Emitter, domain, query string, rows int) error {
	obs := sdk.Observation{
		Predicate:   "no_archived_captures",
		Object:      domain,
		Source:      sdk.Source{Module: "wayback", Provider: "web.archive.org", Method: "cdx.search"},
		Reliability: gradeReliability,
		Credibility: gradeCredibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("query", query)
	obs.AddAttr("rows_seen", rows)
	// The Archive having nothing is a statement about the Archive. Saying so
	// explicitly is what stops an empty result from reading as "no such host".
	obs.AddAttr("note", "the index holds no captures for this domain; this is not a claim that the hosts never existed")
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "wayback-no-captures",
		Severity:    sdk.SevInfo,
	})
}

// buildURL returns the CDX query URL.
//
// collapse=urlkey keeps one row per distinct URL rather than one per capture, which
// is what makes a bounded read useful: without it the limit is spent on repeat
// captures of a single page.
func (m *Module) buildURL(domain string) string {
	v := url.Values{}
	// matchType=domain with the bare registrable domain is how the Archive is asked
	// for every host beneath it.
	//
	// The wildcard must NOT be combined with matchType=domain. That combination
	// returns HTTP 200 and an empty array rather than an error, so a module using it
	// reports that nothing was ever archived while having asked a question the index
	// does not understand. The two forms are alternatives, not synonyms.
	v.Set("url", domain)
	v.Set("matchType", "domain")
	v.Set("output", "json")
	v.Set("fl", "original,timestamp,statuscode")
	v.Set("collapse", "urlkey")
	// The index stores the 404s it hit while crawling, and for a domain like this
	// they outnumber the real pages several hundred to one. Without a server-side
	// filter the entire row limit is spent on rows that are then discarded, and a
	// bounded read returns almost nothing. The anchored pattern matches the same
	// range the client-side filter accepts.
	v.Set("filter", "statuscode:^(2|3)")
	v.Set("limit", itoa(m.maxCaptures))
	return m.baseURL + "?" + v.Encode()
}

// capture is one CDX row that survived filtering.
type capture struct {
	original string
	stamp    string
	status   int
}

// parseCDX decodes a CDX response.
//
// The first row is a header naming the requested fields. It is easy to mistake for
// data and would produce one phantom host named "original".
func parseCDX(raw []byte) ([]capture, error) {
	var table [][]string
	if err := json.Unmarshal(raw, &table); err != nil {
		return nil, fmt.Errorf("wayback: parse CDX response: %w", err)
	}
	if len(table) == 0 {
		return nil, nil
	}
	header := table[0]
	col := map[string]int{}
	for i, name := range header {
		col[strings.ToLower(strings.TrimSpace(name))] = i
	}
	origCol, hasOrig := col["original"]
	stampCol, hasStamp := col["timestamp"]
	if !hasOrig {
		return nil, fmt.Errorf("wayback: CDX response has no 'original' column; got %v", header)
	}

	var out []capture
	for _, row := range table[1:] {
		if len(row) <= origCol {
			continue
		}
		c := capture{original: row[origCol]}
		if hasStamp && len(row) > stampCol {
			c.stamp = row[stampCol]
		}
		if sc, ok := col["statuscode"]; ok && len(row) > sc {
			c.status = atoi(row[sc])
		}
		out = append(out, c)
	}
	return out, nil
}

// hostRecord aggregates every capture seen for one host name.
type hostRecord struct {
	host      string
	firstSeen string
	lastSeen  string
	captures  int
}

// aggregate turns captures into per-host records, discarding the ones that do not
// prove a host served anything.
func aggregate(rows []capture, domain string) map[string]*hostRecord {
	out := map[string]*hostRecord{}
	for _, c := range rows {
		if !successfulStatus(c.status) {
			// The Archive records the 404s it encountered while crawling. A 404 row
			// means the Archive probed a URL and found nothing, which is evidence of
			// a probe and not of a host. Counting these is the single largest source
			// of phantom subdomains in a capture index.
			continue
		}
		host := hostOf(c.original)
		if host == "" {
			continue
		}
		canonHost, err := sdk.Canonicalize(sdk.TypeSubdomain, host)
		if err != nil {
			continue
		}
		if canonHost != domain && !strings.HasSuffix(canonHost, "."+domain) {
			// A wildcard domain query still returns stray rows. Attributing another
			// organization's hosts to the target is the failure this check prevents.
			continue
		}
		rec := out[canonHost]
		if rec == nil {
			rec = &hostRecord{host: canonHost, firstSeen: c.stamp, lastSeen: c.stamp}
			out[canonHost] = rec
		}
		rec.captures++
		if c.stamp < rec.firstSeen {
			rec.firstSeen = c.stamp
		}
		if c.stamp > rec.lastSeen {
			rec.lastSeen = c.stamp
		}
	}
	return out
}

// successfulStatus reports whether a status code shows something was served.
//
// 2xx is a body, 3xx is a redirect the Archive followed a hop for. Anything else is
// the Archive recording its own failure to reach something.
//
// The client-side check duplicates the query's server-side filter on purpose. A
// filter that is only ever applied at one end is a filter that silently stops
// applying the moment that end is bypassed, and nothing here should depend on the
// Archive honouring a parameter.
func successfulStatus(code int) bool {
	if code == 0 {
		// No status column requested. Treat as unknown rather than as success, so a
		// malformed row cannot become a phantom host.
		return false
	}
	return (code >= 200 && code < 400) || code == 403
}

// hostOf extracts the host name from a captured URL.
//
// The Archive's rows carry explicit default ports such as "http://www.kernel.org:80/",
// which would otherwise create a second entity for the same host.
func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// get issues a bounded GET and retains the response.
func (m *Module) get(ctx context.Context, e sdk.Emitter, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, truncated, err := readBounded(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("wayback: read CDX response: %w", err)
	}
	if truncated {
		return nil, fmt.Errorf("wayback: CDX response exceeded the size limit; refusing to parse a partial index")
	}
	if resp.StatusCode >= 400 {
		// The Archive returns 429 and 403 to sustained callers. That is a real
		// failure, not an empty result, and must not be reported as "no captures".
		return nil, fmt.Errorf("wayback: web.archive.org returned HTTP %d", resp.StatusCode)
	}

	if m.keepEvidence {
		if _, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source: rawURL, Method: "cdx.search", MediaType: "application/json",
		}, data); err != nil {
			e.Warn("evidence capture failed", "url", rawURL, "err", err.Error())
		}
	}
	return data, nil
}

func readBounded(r io.Reader) ([]byte, bool, error) {
	const limit = 32 << 20
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// cdTimestamp renders a CDX timestamp as RFC 3339.
//
// CDX stamps are YYYYMMDDHHMMSS with no zone, and they are UTC.
func cdTimestamp(s string) string {
	if len(s) < 8 {
		return s
	}
	t, err := time.ParseInLocation("20060102150405", s, time.UTC)
	if err != nil {
		return s
	}
	return t.Format(time.RFC3339)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

func atoi(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<30 {
			return 1 << 30
		}
	}
	return n
}

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}
