// Package dnsrecords resolves common DNS record types with multi-resolver
// consensus over DNS-over-HTTPS.
//
// This is semi-active: it sends queries about the target, which is ordinary use
// of a public endpoint, but it does contact infrastructure the asset owner
// operates. Mode gating and authorization are enforced by the orchestrator, so
// the module only has to declare them honestly.
package dnsrecords

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// defaultRecordTypes is the set the specification names for this module.
// DNSSEC record types are deliberately excluded: dns-security owns those.
var defaultRecordTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"}

// evidenceMediaType labels the retained raw answer.
const evidenceMediaType = "application/json"

// Module is the dns-records collector.
type Module struct {
	dns         sdk.DNSResolver
	recordTypes []string
	// maxRecords bounds one (name, type) answer set. An unconstrained CNAME chain
	// or a wildcard TXT scheme can return thousands of records, and a collector that
	// materializes all of them stalls the pipeline.
	maxRecords int
	// keepEvidence controls whether raw answers are retained. It defaults to true:
	// without a retrievable artifact every finding is capped as unverified, which
	// is the honest outcome but a much less useful one.
	keepEvidence bool
	// now is the clock, injected so tests are deterministic.
	now func() time.Time
}

// Option configures the module. Options exist so tests and `argus modules test`
// can point the module at a local fixture without touching global state.
type Option func(*Module)

// WithRecordTypes overrides the queried record types.
func WithRecordTypes(types ...string) Option {
	return func(m *Module) { m.recordTypes = normalizeTypes(types) }
}

// WithResolver injects a resolver, so tests never touch the network.
func WithResolver(r sdk.DNSResolver) Option {
	return func(m *Module) { m.dns = r }
}

// WithMaxRecords bounds the answer set per query.
func WithMaxRecords(n int) Option {
	return func(m *Module) {
		if n > 0 {
			m.maxRecords = n
		}
	}
}

// WithEvidence retention on or off. Off is only for a scan that must not write
// artifacts to disk.
func WithEvidence(on bool) Option {
	return func(m *Module) { m.keepEvidence = on }
}

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{
		recordTypes:  append([]string(nil), defaultRecordTypes...),
		maxRecords:   500,
		keepEvidence: true,
		now:          time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

func normalizeTypes(types []string) []string {
	if len(types) == 0 {
		return append([]string(nil), defaultRecordTypes...)
	}
	out := make([]string, 0, len(types))
	seen := map[string]bool{}
	for _, t := range types {
		t = strings.ToUpper(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "dns-records",
		Version:     Version,
		Category:    "domain",
		Description: "Resolve common record types with multi-resolver consensus",
		Consumes:    []sdk.EntityType{sdk.TypeDomain, sdk.TypeSubdomain},
		Produces: []sdk.EntityType{sdk.TypeIP, sdk.TypeSubdomain, sdk.TypeDomain,
			sdk.TypeText, sdk.TypeFinding},
		Mode:        sdk.ModeSemiActive,
		Sensitivity: sdk.SensLow,
		// The default DoH resolvers. Consensus needs two of these to agree, so the
		// list is three: one provider being down or slow must not cost a lookup.
		// A deployment using self-hosted resolvers overrides this through module
		// configuration, and the broker refuses anything not listed here.
		EgressHosts: []string{
			"cloudflare-dns.com",
			"dns.google",
			"dns.adguard-dns.com",
		},
		RateHints: map[string]sdk.Rate{
			"dns": {Requests: 50, Per: time.Second, Burst: 100},
		},
		Tags: []string{"dns", "infrastructure"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.DNS == nil {
		// A resolver is mandatory. Returning an error here means the orchestrator
		// marks this module unavailable instead of letting it run and silently
		// produce nothing.
		return fmt.Errorf("dns-records: no DNS resolver injected")
	}
	m.dns = d.DNS
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing: the resolver is owned by the engine.
func (m *Module) Close() error { return nil }

// Run resolves the target's record types.
//
// One failing record type must not abort the task: a domain with no MX but a valid
// A is a normal domain, and losing the A because the MX lookup failed would be a
// silent under-report.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("dns-records: task has no target")
	}
	name := strings.TrimSuffix(t.Target.Value, ".")
	if name == "" {
		return fmt.Errorf("dns-records: target has no value")
	}

	types := m.recordTypes
	if override := t.Params["types"]; override != "" {
		types = normalizeTypes(strings.Split(override, ","))
	}

	var resolved, failed int
	for _, rr := range types {
		if err := ctx.Err(); err != nil {
			return err
		}
		records, err := m.dns.Lookup(ctx, name, rr)
		if err != nil {
			failed++
			e.Warn("lookup failed", "type", rr, "name", name, "err", err.Error())
			continue
		}
		if len(records) == 0 {
			// A name with no records of this type is a fact, not a gap: record the
			// absence so an analyst can tell "no MX" from "never looked".
			e.Warn("no records", "type", rr, "name", name)
			continue
		}
		if len(records) > m.maxRecords {
			e.Warn("answer set truncated", "type", rr, "records", len(records), "limit", m.maxRecords)
			records = records[:m.maxRecords]
		}

		// Retain the answer before emitting, so the findings derived from it carry a
		// retrievable artifact and may exceed the unverified cap.
		if m.keepEvidence {
			if err := m.retain(ctx, e, name, rr, records); err != nil {
				// A failure to retain evidence must not lose the finding itself. The
				// observations are still emitted; they simply stay capped.
				e.Warn("evidence capture failed", "type", rr, "name", name, "err", err.Error())
			}
		}

		for _, rec := range records {
			if err := emitRecord(t, e, rec); err != nil {
				return err
			}
			resolved++
		}
		e.Progress(resolved+failed, len(types))
	}
	return nil
}

// retain stores the raw answer set as evidence.
//
// The payload is a deterministic re-encoding of the records rather than the
// transport's bytes: it records what Argus actually relied on, so a reviewer can
// re-derive every finding from the artifact without trusting the parser.
func (m *Module) retain(ctx context.Context, e sdk.Emitter, name, rrType string, records []sdk.DNSRecord) error {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString(fmt.Sprintf("  \"name\": %q,\n", name))
	b.WriteString(fmt.Sprintf("  \"type\": %q,\n", rrType))
	b.WriteString("  \"records\": [\n")
	for i, r := range records {
		comma := ","
		if i == len(records)-1 {
			comma = ""
		}
		b.WriteString(fmt.Sprintf("    {\"type\": %q, \"data\": %q, \"ttl\": %d, \"pref\": %d}%s\n",
			r.Type, r.Data, r.TTL, r.Pref, comma))
	}
	b.WriteString("  ]\n}\n")

	_, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
		Source:     fmt.Sprintf("doh:resolve?name=%s&type=%s", name, rrType),
		Method:     "doh.resolve",
		MediaType:  evidenceMediaType,
		CapturedAt: m.now(),
	}, []byte(b.String()))
	return err
}

// observation builds a source-attributed observation. The Admiralty grades are
// declared here and are the only place a module may state them.
//
// Subject is deliberately left unset. The subject of a claim is the thing the claim
// is about, which for "dev.acme.example resolves to 203.0.113.10" is the address,
// not the name being queried. Leaving it to the emitter means a module cannot
// accidentally attribute every claim to the scan root, which would leave each
// discovered entity without evidence and therefore with zero confidence.
func observation(t sdk.Task, predicate string, object any) sdk.Observation {
	return sdk.Observation{
		Predicate:   predicate,
		Object:      object,
		Source:      sdk.Source{Module: "dns-records", Provider: "doh", Method: "doh.resolve"},
		Reliability: 'B', // usually reliable: resolver answers, but not authoritative
		Credibility: '2', // probably true: multi-resolver consensus, unsigned
		// ObservedAt is left zero; the emitter stamps it from the injected clock so
		// the SDK stays free of a direct dependency on time.Now.
	}
}

// emitRecord turns one DNS record into entities, relations, and an observation.
func emitRecord(t sdk.Task, e sdk.Emitter, rec sdk.DNSRecord) error {
	data := strings.TrimSpace(rec.Data)
	if data == "" {
		return nil
	}
	obs := observation(t, predicateFor(rec.Type), data)
	obs.Attrs = map[string]any{"rrtype": rec.Type, "ttl": rec.TTL}

	findings := []sdk.Finding{}

	switch rec.Type {
	case "A", "AAAA":
		ip, err := sdk.NewEntityOrErr(sdk.TypeIP, data)
		if err != nil {
			// A resolver answering with an unparsable address is a data quality
			// problem. Skip the record rather than storing a nonsense entity.
			return nil
		}
		rel := sdk.Rel(t.Target.ID, ip.ID, sdk.RelResolvesTo)
		rel.Obs = []string{obs.ID}
		findings = append(findings, sdk.Finding{
			Entity:      ip,
			Relations:   []sdk.Relation{rel},
			Observation: obs,
		})

	case "CNAME":
		tgt, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, data)
		if err != nil {
			return nil
		}
		rel := sdk.Rel(t.Target.ID, tgt.ID, sdk.RelCNAMETo)
		rel.Obs = []string{obs.ID}
		findings = append(findings, sdk.Finding{
			Entity:      tgt,
			Relations:   []sdk.Relation{rel},
			Observation: obs,
		})

	case "MX":
		mx, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, data)
		if err != nil {
			return nil
		}
		rel := sdk.Rel(mx.ID, t.Target.ID, sdk.RelMXFor)
		rel.Obs = []string{obs.ID}
		findings = append(findings, sdk.Finding{
			Entity:      mx,
			Relations:   []sdk.Relation{rel},
			Observation: obs,
		})

	case "NS":
		ns, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, data)
		if err != nil {
			return nil
		}
		rel := sdk.Rel(ns.ID, t.Target.ID, sdk.RelNSFor)
		rel.Obs = []string{obs.ID}
		findings = append(findings, sdk.Finding{
			Entity:      ns,
			Relations:   []sdk.Relation{rel},
			Observation: obs,
		})

	case "TXT", "CAA":
		// TXT records carry SPF, DMARC, verification tokens, and occasionally
		// secrets pasted by mistake. The value becomes a content-addressed text
		// entity, so it is searchable and linkable without pasting raw content into
		// every report.
		txt := sdk.NewTextEntity(data)
		if txt.ID == "" {
			return nil
		}
		findings = append(findings, sdk.Finding{
			Entity:      txt,
			Observation: obs,
			Kind:        "dns-" + strings.ToLower(rec.Type),
		})

	case "SOA":
		// SOA carries the zone serial, which is what makes zone-transfer
		// comparison possible later.
		txt := sdk.NewTextEntity(data)
		if txt.ID == "" {
			return nil
		}
		findings = append(findings, sdk.Finding{
			Entity:      txt,
			Observation: obs,
			Kind:        "dns-soa",
		})
	}

	for _, f := range findings {
		if err := e.Emit(f); err != nil {
			return err
		}
	}
	return nil
}

func predicateFor(rrType string) string {
	switch rrType {
	case "A", "AAAA":
		return "resolves_to"
	case "CNAME":
		return "cname_to"
	case "MX":
		return "mx_recorded"
	case "NS":
		return "ns_recorded"
	default:
		return "dns_" + strings.ToLower(rrType)
	}
}

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}
