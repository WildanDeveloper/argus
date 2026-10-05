// Package rdap queries the Registration Data Access Protocol for registration
// data on domains, IP ranges, and autonomous systems.
//
// This is passive in the strict sense: it reads the authoritative registry through
// the IANA bootstrap and never contacts the target. That makes it the only
// first-party source in this build that can legitimately claim top Admiralty
// reliability, and also the only one whose answers anyone can independently
// re-check against the same public endpoint.
package rdap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// errNotRegistered means the registry answered authoritatively that no such object
// exists. That is a definitive negative, not a failure, and the caller must be able
// to tell the two apart.
var errNotRegistered = errors.New("rdap: no such object in the registry")

// Module is the rdap collector.
type Module struct {
	http sdk.HTTPDoer
	now  func() time.Time

	// bootstrapURLs is overridable so tests make no outbound request.
	bootstrapURLs map[string][]string
	keepEvidence  bool
	maxBodyBytes  int64
}

// Option configures the module.
type Option func(*Module)

// WithHTTPDoer injects the brokered client.
func WithHTTPDoer(h sdk.HTTPDoer) Option { return func(m *Module) { m.http = h } }

// WithBootstrapURLs overrides the IANA bootstrap locations.
func WithBootstrapURLs(urls map[string][]string) Option {
	return func(m *Module) { m.bootstrapURLs = urls }
}

// WithEvidence turns artifact retention on or off.
func WithEvidence(on bool) Option { return func(m *Module) { m.keepEvidence = on } }

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{
		now:           time.Now,
		bootstrapURLs: bootstrapURLs,
		keepEvidence:  true,
		maxBodyBytes:  4 << 20,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "rdap",
		Version:     Version,
		Category:    "domain",
		Description: "RDAP registration data for domains, IP ranges, and ASNs via the IANA bootstrap",
		Consumes: []sdk.EntityType{sdk.TypeDomain, sdk.TypeSubdomain,
			sdk.TypeIP, sdk.TypeCIDR, sdk.TypeASN},
		Produces: []sdk.EntityType{sdk.TypeOrg, sdk.TypeSubdomain, sdk.TypeEmail,
			sdk.TypeFinding, sdk.TypeText},
		Mode:        sdk.ModePassive,
		Sensitivity: sdk.SensLow,
		// The bootstrap registry is the only fixed host. RDAP server hosts are
		// discovered at run time, and the registry alone names several hundred of
		// them across every TLD, so they cannot be enumerated here without going
		// stale immediately.
		EgressHosts: []string{"data.iana.org"},
		// The bootstrap is what authorizes those server hosts. The broker derives the
		// grant from the document it fetches; this module never asserts a host.
		BootstrapHosts: []string{
			"https://data.iana.org/rdap/dns.json",
			"https://data.iana.org/rdap/ipv4.json",
			"https://data.iana.org/rdap/ipv6.json",
			"https://data.iana.org/rdap/asn.json",
		},
		RateHints: map[string]sdk.Rate{
			"rdap": {Requests: 2, Per: time.Second, Burst: 5},
		},
		Tags: []string{"registration", "authoritative"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.HTTP == nil {
		return fmt.Errorf("rdap: no HTTP client injected")
	}
	m.http = d.HTTP
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// Run looks up registration data for the task target.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("rdap: task has no target")
	}

	endpoints, key, err := m.resolve(ctx, e, t.Target)
	if err != nil {
		return err
	}
	if len(endpoints) == 0 {
		// Not every TLD, address block, or ASN block has an RDAP service. That is an
		// ordinary fact about the registry ecosystem, not a failure.
		e.Warn("no RDAP service published for this registry key",
			"type", string(t.Target.Type), "value", t.Target.Value)
		return nil
	}

	var lastErr error
	for _, base := range sortedEndpoints(endpoints) {
		if err := ctx.Err(); err != nil {
			return err
		}
		url := endpointURL(base, classForEndpoint(t.Target), key)
		raw, err := m.get(ctx, e, url, "rdap.query", sdk.EvidenceMeta{
			Source: url, Method: "rdap.query", MediaType: "application/rdap+json",
		})
		if err != nil {
			if errors.Is(err, errNotRegistered) {
				return m.emitNotRegistered(t, e, key, url)
			}
			// One endpoint failing is normal: registries publish redundant servers
			// and any of them may be down or rate limiting us.
			lastErr = err
			e.Warn("RDAP endpoint failed", "url", url, "err", err.Error())
			continue
		}
		return m.emit(t, e, key, url, raw)
	}
	return fmt.Errorf("rdap: every endpoint failed for %s: %w", t.Target.Value, lastErr)
}

// classForEndpoint picks the path segment used when querying a base endpoint.
func classForEndpoint(target sdk.Entity) string {
	switch target.Type {
	case sdk.TypeDomain, sdk.TypeSubdomain:
		return "domain"
	case sdk.TypeASN:
		return "asn"
	default:
		return "ip"
	}
}

// resolve finds the RDAP base URLs and the object key for a target.
//
// The returned key is what goes into the query URL, which is not always the lookup
// key: an ASN resolves through a published interval, and the object the registry
// returns is the whole allocation.
func (m *Module) resolve(ctx context.Context, e sdk.Emitter, target sdk.Entity) ([]string, string, error) {
	switch target.Type {
	case sdk.TypeDomain, sdk.TypeSubdomain:
		class, tld, ok := lookupClass(target.Type, target.Value)
		if !ok {
			return nil, "", nil
		}
		boot, err := cacheFor(class).get(ctx, m, e, class)
		if err != nil {
			return nil, "", err
		}
		return boot.EndpointsForDomain(tld), target.Value, nil

	case sdk.TypeASN:
		class, asn, ok := lookupClass(target.Type, target.Value)
		if !ok {
			return nil, "", nil
		}
		boot, err := cacheFor(class).get(ctx, m, e, class)
		if err != nil {
			return nil, "", err
		}
		urls, _ := boot.EndpointsForASN(asn)
		return urls, asn, nil

	case sdk.TypeIP, sdk.TypeCIDR:
		addr, ok := ipKeyOf(target.Value)
		if !ok {
			return nil, "", nil
		}
		first, ok := classForAddr(addr)
		if !ok {
			return nil, "", nil
		}
		boot, err := cacheFor(first).get(ctx, m, e, first)
		if err != nil {
			return nil, "", err
		}
		urls, _ := boot.EndpointsForAddr(addr)
		if len(urls) > 0 {
			return urls, addr, nil
		}
		// No covering prefix in this family. Consult the other one before giving up,
		// since an operator may hand us a mapped or mis-typed address.
		for _, class := range classOrder {
			if class == first {
				continue
			}
			other, err := cacheFor(class).get(ctx, m, e, class)
			if err != nil {
				continue
			}
			if urls, _ := other.EndpointsForAddr(addr); len(urls) > 0 {
				return urls, addr, nil
			}
		}
		return nil, addr, nil
	}

	// An account handle, a hash, or a file has no registration data. Reporting that
	// would be noise rather than a finding.
	return nil, "", nil
}

// get issues a bounded GET through the broker and retains the response.
//
// A 404 becomes errNotRegistered because for RDAP it is an authoritative statement
// that the object does not exist, not a transient failure worth retrying.
func (m *Module) get(ctx context.Context, e sdk.Emitter, url, method string, meta sdk.EvidenceMeta) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// RDAP responses are JSON; asking explicitly avoids a server returning HTML,
	// which would parse as a confusing "no identifiable object" error.
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9")

	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, truncated, err := readBounded(resp.Body, m.maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("rdap: read %s: %w", url, err)
	}
	if truncated {
		// A partial registry object parses into missing fields and yields
		// confident-looking but wrong conclusions. Refuse rather than guess.
		return nil, fmt.Errorf("rdap: response from %s exceeded %d bytes; refusing to parse a partial object",
			url, m.maxBodyBytes)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", errNotRegistered, url)
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("rdap: %s returned HTTP %d", url, resp.StatusCode)
	}

	// Retain the raw response. A registration record is the primary artifact for
	// every conclusion drawn from it, and the one source an analyst can re-query
	// independently to check Argus.
	if m.keepEvidence {
		meta.CapturedAt = m.now()
		if _, err := e.PutEvidence(ctx, meta, data); err != nil {
			e.Warn("evidence capture failed", "url", url, "err", err.Error())
		}
	}
	return data, nil
}

// emitNotRegistered records an authoritative negative answer.
//
// This is a finding, not an omission. "No registration record exists" distinguishes
// a registry gap from a withdrawal, and reporting it stops the two from looking
// identical in a report.
func (m *Module) emitNotRegistered(t sdk.Task, e sdk.Emitter, key, url string) error {
	obs := sdk.Observation{
		Predicate: "not_registered",
		Source:    sdk.Source{Module: "rdap", Provider: url, Method: "rdap.query"},
		// The registry is authoritative about its own data, and "does not exist"
		// needs no corroboration.
		Reliability: 'A',
		Credibility: '1',
		ObservedAt:  m.now(),
	}
	obs.AddAttr("object_class", classForEndpoint(t.Target))
	obs.AddAttr("key", key)

	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "rdap-not-registered",
		Severity:    sdk.SevInfo,
	})
}

// emit converts a parsed registry object into findings.
func (m *Module) emit(t sdk.Task, e sdk.Emitter, key, url string, raw []byte) error {
	r, err := parseResponse(raw)
	if err != nil {
		return err
	}

	source := sdk.Source{Module: "rdap", Provider: url, Method: "rdap.query"}
	newObs := func(predicate string, object any) sdk.Observation {
		return sdk.Observation{
			Predicate:   predicate,
			Object:      object,
			Source:      source,
			Reliability: 'A',
			Credibility: '1',
			ObservedAt:  m.now(),
		}
	}

	obs := newObs("registered", t.Target.Value)
	obs.AddAttr("handle", r.Handle)
	if ldh := r.LDHName; ldh != "" {
		obs.AddAttr("ldh_name", ldh)
	}
	if status := r.statusList(); len(status) > 0 {
		obs.AddAttr("status", status)
	}
	if d, ok := r.eventDate("registration"); ok {
		obs.AddAttr("registered_at", d.Format(time.RFC3339))
	}
	if d, ok := r.eventDate("expiration"); ok {
		obs.AddAttr("expires_at", d.Format(time.RFC3339))
		// An expiry inside a month is the single most actionable fact a registry
		// publishes, so it is recorded explicitly rather than left for the reader
		// to derive from a timestamp.
		days := d.Sub(m.now()).Hours() / 24
		switch {
		case days < 0:
			obs.AddAttr("expired", true)
		case days <= 30:
			obs.AddAttr("days_to_expiry", int(days))
		}
	}
	if d, ok := r.eventDate("last changed"); ok {
		obs.AddAttr("last_changed_at", d.Format(time.RFC3339))
	}
	if r.SecureDNS.DelegationSigned {
		obs.AddAttr("dnssec", "signed")
	} else {
		obs.AddAttr("dnssec", "unsigned")
	}
	if r.Name != "" {
		obs.AddAttr("network_name", r.Name)
	}
	if r.Country != "" {
		obs.AddAttr("country", r.Country)
	}
	if r.StartAddress != "" && r.EndAddress != "" {
		obs.AddAttr("range_start", r.StartAddress)
		obs.AddAttr("range_end", r.EndAddress)
	}
	if held, status := r.isHeld(); held {
		obs.AddAttr("held", status)
	}
	if rem := r.remarkText(); rem != "" {
		obs.AddAttr("remarks", rem)
	}

	// Redaction is reported as a stated fact and never inferred. A registry that
	// withholds the registrant has said the data exists and is withheld; recording
	// that as an absent registrant would misrepresent the registry, and guessing the
	// value would fabricate personal data.
	if fields := r.redactedFields(); len(fields) > 0 {
		obs.AddAttr("redacted_fields", fields)
		obs.AddAttr("redaction_methods", r.redactionMethods())
	}

	findings := []sdk.Finding{{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "rdap-registration",
		Severity:    severityFor(t.Target, r),
	}}

	for _, ns := range r.nameservers() {
		nse, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, ns)
		if err != nil {
			continue
		}
		findings = append(findings, sdk.Finding{
			Entity: nse,
			// ns_for runs nameserver -> domain, matching dns-records. An inverted edge
			// would make the graph claim the domain is authoritative for the
			// nameserver.
			Relations:   []sdk.Relation{sdk.Rel(nse.ID, t.Target.ID, sdk.RelNSFor)},
			Observation: withAttr(newObs("ns_for", t.Target.Value), "ldh_name", ns),
		})
	}

	if name := r.registrarName(); name != "" && !isRedactedPlaceholder(name) {
		if orge, err := sdk.NewEntityOrErr(sdk.TypeOrg, name); err == nil {
			findings = append(findings, sdk.Finding{
				Entity:      orge,
				Relations:   []sdk.Relation{sdk.Rel(t.Target.ID, orge.ID, sdk.RelRegisteredBy)},
				Observation: newObs("registered_by", name),
			})
		}
	}

	if abuse := r.abuseContact(); abuse != nil {
		for _, addr := range abuse.emails() {
			ee, err := sdk.NewEntityOrErr(sdk.TypeEmail, addr)
			if err != nil {
				continue
			}
			ao := withAttr(newObs("abuse_contact", addr), "role", "abuse")
			if n := abuse.name(); n != "" && !isRedactedPlaceholder(n) {
				ao.AddAttr("contact_name", n)
			}
			if phones := abuse.phones(); len(phones) > 0 {
				ao.AddAttr("phones", phones)
			}
			// The address is the registrar's, not the domain owner's, so the edge is
			// heuristic: the RDAP record states the contact, but not that the domain
			// owner is reachable at it.
			findings = append(findings, sdk.Finding{
				Entity:      ee,
				Relations:   []sdk.Relation{sdk.HeuristicRel(t.Target.ID, ee.ID, sdk.RelUsesEmail)},
				Observation: ao,
				Kind:        "rdap-abuse-contact",
				Severity:    sdk.SevInfo,
			})
		}
	}

	for _, f := range findings {
		if err := e.Emit(f); err != nil {
			return err
		}
	}
	return nil
}

func withAttr(o sdk.Observation, k string, v any) sdk.Observation {
	o.AddAttr(k, v)
	return o
}

// isRedactedPlaceholder recognizes the literal strings registries publish in place of
// a withheld value. Treating one as a real name would put a nonsense organization
// into the graph.
func isRedactedPlaceholder(s string) bool {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return true
	case strings.EqualFold(s, "REDACTED FOR PRIVACY"):
		return true
	case strings.EqualFold(s, "DATA REDACTED"):
		return true
	case strings.EqualFold(s, "NOT DISCLOSED"):
		return true
	case strings.EqualFold(s, "PRIVACY REDACTED"):
		return true
	}
	return false
}

// severityFor rates a registration state.
func severityFor(target sdk.Entity, r *response) string {
	switch target.Type {
	case sdk.TypeDomain, sdk.TypeSubdomain:
		// A hold or redemption period means the name is at risk of being dropped or
		// has effectively been. That is materially more than a routine record.
		if held, _ := r.isHeld(); held {
			return sdk.SevMedium
		}
	}
	return sdk.SevInfo
}

// readBounded reads at most limit bytes and reports truncation.
func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 4 << 20
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

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}
