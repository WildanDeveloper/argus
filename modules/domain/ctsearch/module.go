package ctsearch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/canon"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Module is the ct-search collector.
//
// Its whole value is finding host names nobody has mentioned yet, which makes
// correctness here unusually consequential: a name that does not exist becomes a
// pivot target, and a name that exists but is irrelevant becomes noise that costs
// an analyst time.
type Module struct {
	adapters []adapter
	deps     sdk.Deps
	now      func() time.Time

	// keepEvidence controls artifact retention.
	keepEvidence bool
	// maxNames bounds how many distinct names one run will emit. A large
	// organization can have tens of thousands of logged names, and a collector that
	// materializes all of them stalls the pipeline and drowns the useful signal.
	maxNames int
	// maxEntriesPerAdapter bounds parsing work before truncation.
	maxEntriesPerAdapter int
}

// Option configures the module.
type Option func(*Module)

// WithAdapters replaces the provider set. Tests use this to avoid the network.
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
		adapters:             []adapter{newCrtSh(), newCertspotter("")},
		now:                  time.Now,
		keepEvidence:         true,
		maxNames:             2000,
		maxEntriesPerAdapter: 20000,
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
		hosts = append(hosts, a.hosts()...)
	}
	sort.Strings(hosts)

	return sdk.Manifest{
		Name:        "ct-search",
		Version:     "1.0.0",
		Category:    "domain",
		Description: "Find host names from certificate transparency logs",
		Consumes:    []sdk.EntityType{sdk.TypeDomain},
		Produces: []sdk.EntityType{sdk.TypeSubdomain, sdk.TypeCert,
			sdk.TypeOrg, sdk.TypeFinding},
		// CT data is a public append-only log read through a third-party index. The
		// target is never contacted, so this is passive.
		Mode:        sdk.ModePassive,
		Sensitivity: sdk.SensLow,
		EgressHosts: hosts,
		RateHints: map[string]sdk.Rate{
			// crt.sh is volunteer-run and slow. Rate limiting here is a matter of
			// being a good citizen, not of staying under a quota.
			"crt.sh":              {Requests: 1, Per: 2 * time.Second, Burst: 2},
			"api.certspotter.com": {Requests: 5, Per: time.Second, Burst: 10},
		},
		Tags: []string{"subdomains", "passive", "discovery"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.HTTP == nil {
		return fmt.Errorf("ct-search: no HTTP client injected")
	}
	m.deps = d
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// Run queries every adapter and emits the names they found.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("ct-search: task has no target")
	}
	// CT search is for a registrable domain. Searching a subdomain's own name finds
	// almost nothing, because certificates are issued for the registrable name.
	domain := registrableOf(t.Target.Value)
	if domain == "" {
		return nil
	}

	type result struct {
		adapter string
		entries []entry
		err     error
	}
	results := make(chan result, len(m.adapters))

	for _, a := range m.adapters {
		a := a
		go func() {
			entries, err := a.fetch(ctx, m.deps, e, domain, "ct.index.search", a.buildURL(domain))
			results <- result{adapter: a.name(), entries: entries, err: err}
		}()
	}

	// names accumulates what each provider saw, so the same host found by two
	// providers is emitted once with both attributed. The scorer then treats the two
	// as independent corroboration, which is the whole reason to query more than one.
	names := map[string][]string{}
	issuers := map[string]bool{}
	certs := map[string]entry{}

	var failures []string
	for range m.adapters {
		r := <-results
		if r.err != nil {
			// A provider being down is normal. Report it and continue, because
			// failing the task would discard the providers that did answer.
			failures = append(failures, fmt.Sprintf("%s: %v", r.adapter, r.err))
			e.Warn("CT source failed", "adapter", r.adapter, "err", r.err.Error())
			continue
		}
		for _, en := range r.entries {
			if len(en.names) > m.maxEntriesPerAdapter {
				en.names = en.names[:m.maxEntriesPerAdapter]
			}
			for _, raw := range en.names {
				norm, kind, ok := normalizeName(raw, domain)
				if !ok {
					continue
				}
				if kind == nameWildcard {
					// A wildcard proves the certificate could cover names below it; it
					// does not prove any specific host exists. Recording *.example.com
					// as a discovered subdomain is the classic CT false positive.
					continue
				}
				names[norm] = appendUniqueString(names[norm], r.adapter)
			}
			if en.issuerOrg != "" {
				issuers[en.issuerOrg] = true
			} else if en.issuerDName != "" {
				issuers[en.issuerDName] = true
			}
			if en.certSHA256 != "" {
				if _, seen := certs[en.certSHA256]; !seen {
					certs[en.certSHA256] = en
				}
			}
		}
	}

	if len(names) == 0 && len(failures) == len(m.adapters) {
		return fmt.Errorf("ct-search: every source failed for %s", domain)
	}

	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)

	truncated := false
	if len(ordered) > m.maxNames {
		truncated = true
		ordered = ordered[:m.maxNames]
		e.Warn("name set truncated", "domain", domain, "found", len(names), "limit", m.maxNames)
	}

	source := sdk.Source{Module: "ct-search", Provider: "ct-logs", Method: "index.search"}
	newObs := func(predicate string, object any) sdk.Observation {
		return sdk.Observation{
			Predicate: predicate,
			Object:    object,
			Source:    source,
			// A transparency log is append-only and independently auditable, but we
			// are reading it through an index that may lag or omit entries.
			Reliability: gradeReliability,
			Credibility: gradeCredibility,
			ObservedAt:  m.now(),
		}
	}

	emitted := 0
	for _, name := range ordered {
		if emitted >= m.maxNames {
			break
		}
		ent, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, name)
		if err != nil {
			continue
		}
		if ent.Value == domain {
			// The registrable domain is already in the graph; re-emitting it as its
			// own subdomain would be a self-loop.
			continue
		}
		providers := sortedUnique(names[name])
		obs := newObs("observed_in_ct_log", name)
		obs.AddAttr("ct_providers", providers)
		obs.AddAttr("sources_count", len(providers))

		if err := e.Emit(sdk.Finding{
			Entity:      ent,
			Relations:   []sdk.Relation{sdk.Rel(ent.ID, t.Target.ID, sdk.RelSubdomainOf)},
			Observation: obs,
			Kind:        "ct-discovered-subdomain",
		}); err != nil {
			return err
		}
		emitted++
	}

	// Certificate authorities, so the report can say who issued for a target.
	for _, name := range sortedSet(issuers) {
		orge, err := sdk.NewEntityOrErr(sdk.TypeOrg, name)
		if err != nil {
			continue
		}
		obs := newObs("issued_for", domain)
		obs.AddAttr("issuer", name)
		if err := e.Emit(sdk.Finding{
			Entity:      orge,
			Relations:   []sdk.Relation{sdk.HeuristicRel(t.Target.ID, orge.ID, sdk.RelOwnedBy)},
			Observation: obs,
			Kind:        "ct-issuer",
		}); err != nil {
			return err
		}
	}

	// Certificate entities, only where a real DER digest was published. A serial
	// number is not a fingerprint, and presenting one as a certificate hash would
	// create an entity that looks verifiable and is not.
	for _, sum := range sortedSet(certKeys(certs)) {
		cert, err := sdk.NewEntityOrErr(sdk.TypeCert, sum)
		if err != nil {
			continue
		}
		en := certs[sum]
		obs := newObs("certificate_observed", sum)
		obs.AddAttr("sha256", sum)
		obs.AddAttr("not_before", en.notBefore)
		obs.AddAttr("not_after", en.notAfter)
		if en.issuerDName != "" {
			obs.AddAttr("issuer", en.issuerDName)
		}
		sev := ""
		if en.revoked {
			// A revoked certificate stays in the log forever. Reporting it as live
			// would tell an analyst to trust a credential the CA has withdrawn, so
			// it is recorded as revoked and rated above the informational default.
			obs.AddAttr("revoked", true)
			sev = sdk.SevMedium
		}
		rels := []sdk.Relation{sdk.HeuristicRel(cert.ID, t.Target.ID, sdk.RelIssuedFor)}
		if err := e.Emit(sdk.Finding{
			Entity:      cert,
			Relations:   rels,
			Observation: obs,
			Kind:        "ct-certificate",
			Severity:    sev,
		}); err != nil {
			return err
		}
	}

	// A summary observation, so a report can state coverage even when no names were
	// new. Silence is indistinguishable from "nothing exists" otherwise.
	summary := newObs("ct_search_summary", domain)
	summary.AddAttr("distinct_names", len(names))
	summary.AddAttr("emitted", emitted)
	summary.AddAttr("adapters", len(m.adapters))
	summary.AddAttr("adapters_failed", len(failures))
	summary.AddAttr("truncated", truncated)
	if err := e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: summary,
		Kind:        "ct-search-summary",
	}); err != nil {
		return err
	}
	return nil
}

// nameKind classifies a name found in a log.
type nameKind int

const (
	nameOther nameKind = iota
	nameWildcard
	nameOutside
)

// normalizeName decides whether a logged name is a host under the queried domain.
//
// A certificate log is global. It contains names for every organization on earth,
// and it will happily contain a certificate for example.com issued by a party with
// no relationship to it. Emitting names outside the queried domain would turn every
// scan into a scan of the whole log.
func normalizeName(raw, domain string) (string, nameKind, bool) {
	n := strings.ToLower(strings.TrimSpace(raw))
	if n == "" {
		return "", nameOther, false
	}
	// Strip a trailing root dot.
	n = strings.TrimSuffix(n, ".")

	if strings.HasPrefix(n, "*.") {
		return "*." + n[2:], nameWildcard, false
	}
	if strings.Contains(n, "*") {
		// A partial wildcard such as "dev-*.example.com" proves nothing about any
		// concrete host.
		return "", nameWildcard, false
	}
	if n != domain && !strings.HasSuffix(n, "."+domain) {
		return "", nameOutside, false
	}
	if n == domain {
		return "", nameOther, false
	}
	// Canonicalize so punycode and Unicode forms of one name become one entity.
	canon, err := sdk.Canonicalize(sdk.TypeSubdomain, n)
	if err != nil {
		return "", nameOutside, false
	}
	return canon, nameOther, true
}

// registrableOf reduces a name to what a CT search should query.
//
// Certificates are issued against the registrable domain, so searching a subdomain's
// own name finds almost nothing. The Public Suffix List is required for this rather
// than a last-label split: for "shop.example.co.uk" the registrable domain is
// "example.co.uk", and treating "co.uk" as the domain would query the wrong registry
// scope and discard every name found under it.
func registrableOf(value string) string {
	c, err := sdk.Canonicalize(sdk.TypeSubdomain, value)
	if err != nil {
		return ""
	}
	return canon.RegistrableDomain(c)
}

// readBody reads a bounded response body.
func readBody(r io.Reader) ([]byte, bool, error) {
	const limit = 32 << 20 // 32 MiB
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

func newGet(ctx context.Context, url, accept string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func appendUniqueString(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func certKeys(m map[string]entry) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}
