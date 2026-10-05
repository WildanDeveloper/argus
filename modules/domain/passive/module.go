// Package passive aggregates several independent passive subdomain sources into one
// deduplicated set, with a weight per source.
//
// It exists because passive sources overlap heavily and each is wrong in a different
// way. A name in one source is a lead; a name in three independent ones is
// substantially stronger evidence. Aggregating properly means that difference has to
// be visible in the record rather than flattened away, because flattening it is how an
// aggregator ends up presenting every name it saw with the same confidence.
//
// Two sources in this build are deliberately absent: certificate transparency is
// covered by ct-search and the Wayback index by wayback, both of which grade their
// own evidence properly. Folding them in here would mean parsing the same data twice
// and scoring it twice.
package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/canon"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// Grading. Passive indexes are third-party datasets of uneven provenance and
// completeness, so reliability is C no matter how many agree; credibility is where
// corroboration registers.
const gradeReliability = 'C'

// Module is the subdomain-passive collector.
type Module struct {
	http sdk.HTTPDoer
	now  func() time.Time

	adapters     []adapter
	keepEvidence bool
	maxBody      int64
	// maxNames bounds what one run emits. A large organisation appears in passive
	// indexes thousands of times, and materialising all of it stalls the pipeline.
	maxNames int
}

// Option configures the module.
type Option func(*Module)

// WithHTTPDoer injects the brokered client.
func WithHTTPDoer(h sdk.HTTPDoer) Option { return func(m *Module) { m.http = h } }

// WithAdapters replaces the source set.
func WithAdapters(as ...adapter) Option { return func(m *Module) { m.adapters = as } }

// WithEvidence turns artifact retention on or off.
func WithEvidence(on bool) Option { return func(m *Module) { m.keepEvidence = on } }

// WithMaxNames bounds the distinct names emitted.
func WithMaxNames(n int) Option {
	return func(m *Module) {
		if n > 0 {
			m.maxNames = n
		}
	}
}

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{
		now:          time.Now,
		adapters:     defaultAdapters(),
		keepEvidence: true,
		maxBody:      16 << 20,
		maxNames:     5000,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	hosts := []string{}
	for _, a := range m.adapters {
		hosts = append(hosts, a.host())
	}
	sort.Strings(hosts)

	return sdk.Manifest{
		Name:        "subdomain-passive",
		Version:     Version,
		Category:    "domain",
		Description: "Aggregate passive subdomain indexes with per-source weights and dedupe",
		Consumes:    []sdk.EntityType{sdk.TypeDomain},
		Produces:    []sdk.EntityType{sdk.TypeSubdomain, sdk.TypeIP, sdk.TypeFinding},
		Mode:        sdk.ModePassive,
		Sensitivity: sdk.SensLow,
		EgressHosts: hosts,
		RateHints: map[string]sdk.Rate{
			// HackerTarget's free tier is a handful of queries per day per address, and
			// RapidDNS is a small volunteer-run index. Both limits are reasons to be
			// sparing rather than quotas to stay under.
			"api.hackertarget.com": {Requests: 1, Per: 10 * time.Second, Burst: 1},
			"rapiddns.io":          {Requests: 1, Per: 3 * time.Second, Burst: 2},
		},
		Tags: []string{"subdomains", "passive", "multi-source"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.HTTP == nil {
		return fmt.Errorf("subdomain-passive: no HTTP client injected")
	}
	m.http = d.HTTP
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// name is one host, with the sources that reported it.
type name struct {
	value string
	// sources maps a source name to its weight. A weight is the source's own
	// reliability as a lead, not a vote count: a source that systematically reports
	// names that do not resolve should not be able to outvote one that does not.
	sources map[string]float64
	// ips is the set of addresses reported alongside the name, when the source
	// publishes them.
	ips map[string]bool
}

// Run queries every source and emits the union.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("subdomain-passive: task has no target")
	}
	domain := canon.RegistrableDomain(t.Target.Value)
	if domain == "" {
		return nil
	}

	type result struct {
		source string
		weight float64
		names  []string
		ips    map[string]string // host -> address
		err    error
	}
	results := make(chan result, len(m.adapters))
	for _, a := range m.adapters {
		a := a
		go func() {
			names, ips, err := fetchOne(ctx, a, m, e, domain)
			results <- result{source: a.name(), weight: a.weight(), names: names, ips: ips, err: err}
		}()
	}

	found := map[string]*name{}
	var failures []string

	for range m.adapters {
		r := <-results
		if r.err != nil {
			// A source being unavailable is ordinary. One failure must not discard the
			// others, and must not be reported as "nothing found".
			failures = append(failures, fmt.Sprintf("%s: %v", r.source, r.err))
			e.Warn("passive source failed", "source", r.source, "err", r.err.Error())
			continue
		}
		for _, raw := range r.names {
			host, ok := normalize(raw, domain)
			if !ok {
				continue
			}
			n := found[host]
			if n == nil {
				n = &name{value: host, sources: map[string]float64{}, ips: map[string]bool{}}
				found[host] = n
			}
			// The same source repeating a name is one vote, not several. Counting
			// repeats would let a source that lists a host on fifty lines outweigh two
			// independent sources that each found it once.
			if _, seen := n.sources[r.source]; !seen {
				n.sources[r.source] = r.weight
			}
			if ip, ok := r.ips[raw]; ok {
				n.ips[ip] = true
			}
		}
	}

	if len(found) == 0 && len(failures) == len(m.adapters) {
		return fmt.Errorf("subdomain-passive: every source failed for %s: %s",
			domain, strings.Join(failures, "; "))
	}

	ordered := make([]*name, 0, len(found))
	for _, n := range found {
		ordered = append(ordered, n)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].value < ordered[j].value })

	truncated := false
	if len(ordered) > m.maxNames {
		ordered = ordered[:m.maxNames]
		truncated = true
		e.Warn("name set truncated", "domain", domain, "found", len(found), "limit", m.maxNames)
	}

	source := sdk.Source{Module: "subdomain-passive", Provider: "aggregate", Method: "index.search"}
	emitted := 0
	for _, n := range ordered {
		if n.value == domain {
			// The registrable domain is already in the graph; re-emitting it as its own
			// subdomain would be a self-loop.
			continue
		}
		ent, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, n.value)
		if err != nil {
			continue
		}
		cred := credibility(len(n.sources), len(m.adapters))
		obs := sdk.Observation{
			Predicate:   "found_in_passive_index",
			Object:      n.value,
			Source:      source,
			Reliability: gradeReliability,
			Credibility: cred,
			ObservedAt:  m.now(),
		}
		obs.AddAttr("sources", sortedSources(n.sources))
		obs.AddAttr("source_count", len(n.sources))
		// The weights travel with the record. An aggregate that publishes a total
		// score without showing how it was reached is a score nobody can audit, and
		// the per-source weights are what let a reader discount the weakest source.
		obs.AddAttr("source_weights", n.sources)
		obs.AddAttr("aggregate_weight", round2(totalWeight(n.sources)))
		if len(n.ips) > 0 {
			obs.AddAttr("addresses", sortedSet(n.ips))
		}
		// A passive index is a historical record. It is evidence the name was seen, not
		// evidence the host exists now, and a name found only in an old index is
		// exactly the one that will not resolve.
		obs.AddAttr("requires_resolution", true)

		if err := e.Emit(sdk.Finding{
			Entity:      ent,
			Relations:   []sdk.Relation{sdk.HeuristicRel(ent.ID, t.Target.ID, sdk.RelSubdomainOf)},
			Observation: obs,
			Kind:        "passive-subdomain",
			Severity:    sdk.SevInfo,
		}); err != nil {
			return err
		}
		emitted++
	}

	// Coverage is reported even when nothing new was found. Silence is
	// indistinguishable from "these sources hold nothing".
	summary := sdk.Observation{
		Predicate:   "passive_summary",
		Object:      domain,
		Source:      source,
		Reliability: gradeReliability,
		Credibility: credibility(len(found), len(m.adapters)),
		ObservedAt:  m.now(),
	}
	summary.AddAttr("sources_configured", sourceNames(m.adapters))
	summary.AddAttr("sources_succeeded", len(m.adapters)-len(failures))
	summary.AddAttr("sources_failed", len(failures))
	summary.AddAttr("distinct_names", len(found))
	summary.AddAttr("emitted", emitted)
	summary.AddAttr("truncated", truncated)
	summary.AddAttr("uncorrelated_count", uncorrelatedCount(found))
	summary.AddAttr("unavailable_sources", unavailableSources())
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: summary,
		Kind:        "passive-summary",
		Severity:    sdk.SevInfo,
	})
}

// credibility maps how many sources agreed onto the Admiralty credibility axis.
//
// One source is "possibly true" rather than "probably true": every passive index
// carries names that have long since been deleted, and presenting a single-source name
// with the same confidence as a three-source one is the failure this module exists to
// avoid.
//
// A proportion alone is not enough to grade on. With two sources configured, one
// agreeing is a ratio of one half, and a coin flip is not a majority in any sense that
// belongs in a confidence score. So a grade above "possibly true" needs at least two
// sources and a strict majority of them.
func credibility(agreeing, configured int) byte {
	if configured <= 0 || agreeing <= 0 {
		return '3'
	}
	switch {
	case agreeing == configured && agreeing >= 2:
		// Every configured source saw it. Confirmed by independent sources.
		return '1'
	case agreeing >= 2 && agreeing*2 > configured:
		// A clear majority, but not unanimity.
		return '2'
	default:
		return '3'
	}
}

// uncorrelatedCount reports how many names only one source saw, which is the honest
// measure of how much of an aggregate is actually corroborated.
func uncorrelatedCount(found map[string]*name) int {
	n := 0
	for _, v := range found {
		if len(v.sources) == 1 {
			n++
		}
	}
	return n
}

func totalWeight(sources map[string]float64) float64 {
	var t float64
	for _, w := range sources {
		t += w
	}
	return t
}

func normalize(raw, domain string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if n == "" || strings.Contains(n, "*") {
		// A wildcard proves the holder could cover names below it, which is not a host.
		return "", false
	}
	if n == domain || !strings.HasSuffix(n, "."+domain) {
		// Matching on a label boundary, or a stranger's host becomes the target's.
		return "", false
	}
	canonName, err := sdk.Canonicalize(sdk.TypeSubdomain, n)
	if err != nil {
		return "", false
	}
	return canonName, true
}

func sortedSources(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sourceNames(as []adapter) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.name())
	}
	sort.Strings(out)
	return out
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// get issues a bounded GET and retains the response.
func (m *Module) get(ctx context.Context, e sdk.Emitter, url, accept, method string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)

	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, truncated, err := readBounded(resp.Body, m.maxBody)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if truncated {
		return nil, fmt.Errorf("response from %s exceeded %d bytes; refusing to parse a partial index", url, m.maxBody)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}

	if m.keepEvidence {
		// Every source's answer is kept, because the disagreement between them is only
		// auditable if each side can be read back.
		if _, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source: url, Method: method, MediaType: accept,
		}, data); err != nil {
			e.Warn("evidence capture failed", "url", url, "err", err.Error())
		}
	}
	return data, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 16 << 20
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

func decodeJSON(raw []byte, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return nil
}

func unescape(s string) string { return html.UnescapeString(s) }

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}
