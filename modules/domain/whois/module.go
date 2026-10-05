package whois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// Grading. A registry WHOIS record is authoritative about its own data in the same
// sense RDAP is, but a thin record is only a pointer to another server, and the
// registrar's own record is less regulated in what it must publish. The registrar
// record is therefore graded lower.
const (
	registryReliability  = 'A'
	registryCredibility  = '1'
	registrarReliability = 'B'
	registrarCredibility = '2'
)

// Errors that callers and tests must be able to tell apart. The distinction matters
// throughout: "no record exists", "this server refused to answer", and "that was not
// a WHOIS response" are three different facts and a module that collapses them turns
// a rate limit into a clean negative.
var (
	// errNoRecord is an authoritative statement that no record exists.
	errNoRecord = errors.New("whois: no record for this name")
	// errRateLimited means the server refused for volume rather than answering.
	errRateLimited = errors.New("whois: server refused the query for volume")
	// errThinResponse means the registry answered with only a registrar pointer.
	errThinResponse = errors.New("whois: thin response; the registry returned no registration data")
)

// Module is the whois collector.
type Module struct {
	dial sdk.Dialer
	now  func() time.Time

	// ianaHost is the server RFC 3912 designates for finding any TLD's registry.
	ianaHost string
	// registryHosts maps a TLD to its registry WHOIS server. There is no published
	// bootstrap for WHOIS the way there is for RDAP, so the servers that matter are
	// listed explicitly.
	registryHosts map[string]string
	keepEvidence  bool
	maxBytes      int64
	// maxQueries bounds registry and registrar lookups for one name. WHOIS servers
	// enforce volume limits by blocking the caller, so a scan must not be the reason
	// an operator loses access to a registry for the rest of the day.
	maxQueries int
}

// Option configures the module.
type Option func(*Module)

// WithDialer injects the brokered TCP client.
func WithDialer(d sdk.Dialer) Option { return func(m *Module) { m.dial = d } }

// WithIANAHost overrides the referral server.
func WithIANAHost(h string) Option { return func(m *Module) { m.ianaHost = h } }

// WithRegistryHosts overrides the TLD to server table.
func WithRegistryHosts(h map[string]string) Option {
	return func(m *Module) { m.registryHosts = h }
}

// WithEvidence turns artifact retention on or off.
func WithEvidence(on bool) Option { return func(m *Module) { m.keepEvidence = on } }

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{
		now:           time.Now,
		ianaHost:      "whois.iana.org:43",
		registryHosts: defaultRegistryHosts(),
		keepEvidence:  true,
		maxBytes:      128 << 10,
		maxQueries:    3,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// defaultRegistryHosts lists the registry WHOIS servers for the TLDs this build
// expects to see most.
//
// It is a table rather than a bootstrap because no published bootstrap exists for
// WHOIS the way one does for RDAP. Scrapeing a list from a web page would be
// fragile and would depend on markup that can change without notice. Every entry here
// changes on a scale of years, and a TLD with no entry falls back to the IANA
// referral server, which exists precisely for that case.
func defaultRegistryHosts() map[string]string {
	return map[string]string{
		"com":  "whois.verisign-grs.com:43",
		"net":  "whois.verisign-grs.com:43",
		"org":  "whois.publicinterestregistry.org:43",
		"info": "whois.afilias.net:43",
		"io":   "whois.nic.io:43",
		"dev":  "whois.nic.google:43",
		"app":  "whois.nic.google:43",
		"xyz":  "whois.nic.xyz:43",
		"de":   "whois.denic.de:43",
		"uk":   "whis.dnscert.gtld.uk:43",
		"nl":   "whois.domain-registry.nl:43",
		"fr":   "whois.nic.fr:43",
		"it":   "whois.nic.it:43",
		"ru":   "whois.tcinet.ru:43",
		"br":   "whois.registro.br:43",
		"jp":   "whois.jprs.jp:43",
		"cn":   "whois.cnnic.cn:43",
		"in":   "whois.registry.in:43",
		"au":   "whois.auda.org.au:43",
		"ca":   "whois.cira.ca:43",
		"pl":   "whois.dns.pl:43",
		"se":   "whois.iis.se:43",
		"ch":   "whois.nic.ch:43",
		"id":   "whois.pandi.id:43",
	}
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	hosts := []string{hostOfAddress(m.ianaHost)}
	for _, h := range m.registryHosts {
		hosts = append(hosts, hostOfAddress(h))
	}
	sort.Strings(hosts)
	hosts = dedupe(hosts)

	return sdk.Manifest{
		Name:        "whois",
		Version:     Version,
		Category:    "domain",
		Description: "Legacy WHOIS registration data, following thin records to the registrar",
		Consumes:    []sdk.EntityType{sdk.TypeDomain},
		Produces: []sdk.EntityType{sdk.TypeOrg, sdk.TypeSubdomain, sdk.TypeEmail,
			sdk.TypeFinding},
		// WHOIS reads a public registry and never contacts the domain being looked up.
		// Declaring it semi-active would wrongly imply it probes the target.
		Mode:        sdk.ModePassive,
		Sensitivity: sdk.SensLow,
		EgressHosts: hosts,
		RateHints: map[string]sdk.Rate{
			// This rate is about being a good citizen, not staying under a quota.
			// WHOIS servers enforce volume by blocking the caller outright, and a
			// blocked operator loses access to a registry for the rest of the day.
			// The IANA referral server in particular is aggressively limited.
			"*": {Requests: 1, Per: 5 * time.Second, Burst: 1},
		},
		Tags: []string{"registration", "legacy", "rate-limited"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.Dial == nil {
		// A module needing port 43 without the brokered dialer would have to hold a
		// raw socket, which is the one thing the egress layer exists to prevent.
		return fmt.Errorf("whois: no TCP dialer injected; refusing to open a raw socket")
	}
	m.dial = d.Dial
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// Run looks up a domain, following a thin record to the registrar when needed.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("whois: task has no target")
	}
	if t.Target.Type != sdk.TypeDomain {
		return nil
	}
	name := normalizeName(t.Target.Value)
	tld := tldOf(name)
	if tld == "" {
		return nil
	}

	addr, known := m.registryHosts[tld]
	via := "registry table"
	if !known {
		// RFC 3912 designates this server for exactly the case of a TLD with no
		// locally configured entry.
		addr = m.ianaHost
		via = "IANA referral"
	}

	queries := 0
	raw, grade, err := m.query(ctx, e, name, addr, &queries)
	if err != nil {
		if errors.Is(err, errNoRecord) {
			return m.emitNoRecord(t, e, addr)
		}
		return err
	}

	rec := parseRecord(string(raw))
	if rec.isEmpty() {
		// An authoritative "I hold nothing for this name" is a finding, not an empty
		// success. Silence would leave the reader unable to tell it from a server that
		// was never asked.
		return m.emitNoRecord(t, e, addr)
	}
	if rec.isRateLimited() {
		// Reported as its own failure rather than an empty result. Treating a block as
		// "no record" would tell an analyst a domain is unregistered when the truth
		// is that this operator was throttled.
		return fmt.Errorf("%w: %s", errRateLimited, addr)
	}
	rec.reliability, rec.credibility = grade.reliability, grade.credibility

	if err := m.emit(t, e, name, rec, addr, via); err != nil {
		return err
	}

	// A thin record is only a pointer. Following it is what makes the module a
	// registration source rather than a directory of referral addresses.
	referral := rec.registrarServer()
	if referral == "" {
		return nil
	}
	if queries >= m.maxQueries {
		e.Warn("query budget spent before following the registrar referral",
			"target", name, "limit", m.maxQueries)
		return nil
	}

	raw2, err := m.queryRaw(ctx, e, name, referral, &queries)
	if err != nil {
		// The registry answer is already recorded. Failing the whole task over the
		// registrar lookup would discard it, so the follow-up failure is reported and
		// the partial answer stands.
		e.Warn("registrar lookup failed", "target", name, "server", referral, "err", err.Error())
		return nil
	}
	rec2 := parseRecord(string(raw2))
	if rec2.isRateLimited() {
		e.Warn("registrar refused the query for volume", "target", name, "server", referral)
		return nil
	}
	rec2.merge(rec)
	// The referral answer is graded as a registrar's, not as the registry's the first
	// query went to. A registrar is not bound by what a registry must publish, and
	// carrying the registry grade across would overstate the merged record.
	rec2.reliability, rec2.credibility = registrarReliability, registrarCredibility
	return m.emit(t, e, name, rec2, referral, "registrar referral")
}

// query performs one lookup, preferring the registry address and falling back to the
// IANA referral server when the configured registry is unreachable.
func (m *Module) query(ctx context.Context, e sdk.Emitter, name, addr string, queries *int) ([]byte, grade, error) {
	raw, err := m.queryRaw(ctx, e, name, addr, queries)
	if err == nil {
		// The configured registry answered. It is authoritative about its own data.
		return raw, grade{registryReliability, registryCredibility}, nil
	}
	// A thin TLD's registry may be unreachable from here. The referral server answers
	// for every TLD, so one attempt there is worth more than failing the domain.
	if addr != m.ianaHost && !strings.Contains(err.Error(), "rate limit") {
		if raw2, err2 := m.queryRaw(ctx, e, name, m.ianaHost, queries); err2 == nil {
			// The referral server answered. It is a registry, but it is answering on
			// another's behalf, so the claim is graded as a registrar's.
			return raw2, grade{registrarReliability, registrarCredibility}, nil
		}
	}
	return nil, grade{}, err
}

// grade is a reliability and credibility pair. It is returned together rather than as
// two values because getting the two the wrong way round is a silent mis-grading: the
// module would emit reliability '1' and credibility 'A', neither of which a reader can
// interpret.
type grade struct {
	reliability byte
	credibility byte
}

// queryRaw opens a brokered connection and reads the answer.
func (m *Module) queryRaw(ctx context.Context, e sdk.Emitter, name, addr string, queries *int) ([]byte, error) {
	if *queries >= m.maxQueries {
		return nil, fmt.Errorf("whois: query budget of %d spent", m.maxQueries)
	}
	*queries++

	conn, err := m.dial.DialText(ctx, addr, sdk.DialQuery{
		Query:    name,
		MaxBytes: m.maxBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("whois: query %s: %w", addr, err)
	}
	defer conn.Close()

	// The broker refuses an over-long response rather than returning a partial record,
	// so a truncated one cannot be parsed into a plausible WHOIS answer.
	raw, truncated, err := readBoundedResponse(conn, m.maxBytes)
	if err != nil {
		return nil, fmt.Errorf("whois: read %s: %w", addr, err)
	}
	if truncated {
		return nil, fmt.Errorf("whois: response from %s exceeded %d bytes; refusing to parse a partial record", addr, m.maxBytes)
	}

	if m.keepEvidence {
		// The raw record is the only artifact behind every field parsed from it, and
		// it is the one an analyst can re-read to check a parse.
		if _, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source: "whois://" + addr, Method: "whois.query", MediaType: "text/plain",
		}, raw); err != nil {
			e.Warn("evidence capture failed", "server", addr, "err", err.Error())
		}
	}
	return raw, nil
}

// emit records what a parsed answer contains.
func (m *Module) emit(t sdk.Task, e sdk.Emitter, name string, rec *record, server, via string) error {
	source := sdk.Source{Module: "whois", Provider: server, Method: "whois.query"}

	obs := sdk.Observation{
		Predicate:   "whois_record",
		Object:      name,
		Source:      source,
		Reliability: rec.reliability,
		Credibility: rec.credibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("server", server)
	obs.AddAttr("resolved_via", via)
	obs.AddAttr("thick", rec.isThick())
	if rec.registrarName != "" {
		obs.AddAttr("registrar", rec.registrarName)
	}
	if len(rec.status) > 0 {
		obs.AddAttr("status", rec.status)
	}
	if d, ok := rec.date("creation"); ok {
		obs.AddAttr("created_at", d)
	}
	if d, ok := rec.date("expiry"); ok {
		obs.AddAttr("expires_at", d)
		// An expiry inside thirty days is the most actionable thing a WHOIS record
		// says, and it is stated rather than left for the reader to derive.
		if days := d.Sub(m.now()).Hours() / 24; days < 0 {
			obs.AddAttr("expired", true)
		} else if days <= 30 {
			obs.AddAttr("days_to_expiry", int(days))
		}
	}
	if d, ok := rec.date("updated"); ok {
		obs.AddAttr("updated_at", d)
	}
	// A name that was withheld is recorded as withheld. The registry has said the data
	// exists and is not being published; recording it as absent would misrepresent the
	// registry, and guessing would fabricate personal data.
	if len(rec.redacted) > 0 {
		obs.AddAttr("redacted_fields", rec.redacted)
		obs.AddAttr("note", "the registry withheld these fields; this is a statement of withholding, not of absence")
	}

	if err := e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "whois-record",
		Severity:    severityFor(rec),
	}); err != nil {
		return err
	}

	if rec.registrarName != "" {
		if orge, err := sdk.NewEntityOrErr(sdk.TypeOrg, rec.registrarName); err == nil {
			o := sdk.Observation{
				Predicate:   "registrar_of",
				Object:      rec.registrarName,
				Source:      source,
				Reliability: rec.reliability,
				Credibility: rec.credibility,
				ObservedAt:  m.now(),
			}
			if err := e.Emit(sdk.Finding{
				Entity:      orge,
				Relations:   []sdk.Relation{sdk.Rel(t.Target.ID, orge.ID, sdk.RelRegisteredBy)},
				Observation: o,
				Kind:        "whois-registrar",
				Severity:    sdk.SevInfo,
			}); err != nil {
				return err
			}
		}
	}

	for _, ns := range rec.nameServers {
		nse, err := sdk.NewEntityOrErr(sdk.TypeSubdomain, ns)
		if err != nil {
			continue
		}
		o := sdk.Observation{
			Predicate:   "ns_for",
			Object:      ns,
			Source:      source,
			Reliability: rec.reliability,
			Credibility: rec.credibility,
			ObservedAt:  m.now(),
		}
		if err := e.Emit(sdk.Finding{
			Entity:      nse,
			Relations:   []sdk.Relation{sdk.Rel(nse.ID, t.Target.ID, sdk.RelNSFor)},
			Observation: o,
			Kind:        "whois-nameserver",
			Severity:    sdk.SevInfo,
		}); err != nil {
			return err
		}
	}

	for _, email := range rec.emails {
		ee, err := sdk.NewEntityOrErr(sdk.TypeEmail, email.address)
		if err != nil {
			continue
		}
		o := sdk.Observation{
			Predicate:   "contact_email",
			Object:      email,
			Source:      source,
			Reliability: rec.reliability,
			Credibility: rec.credibility,
			ObservedAt:  m.now(),
		}
		o.AddAttr("field", email.field)
		if err := e.Emit(sdk.Finding{
			Entity:      ee,
			Relations:   []sdk.Relation{sdk.HeuristicRel(t.Target.ID, ee.ID, sdk.RelUsesEmail)},
			Observation: o,
			Kind:        "whois-contact",
			// A registrant address is personal data a registry chose to publish, but
			// publishing it is still not a statement that the target uses it.
			Severity: sdk.SevInfo,
		}); err != nil {
			return err
		}
	}
	return nil
}

// emitNoRecord records an authoritative negative answer.
func (m *Module) emitNoRecord(t sdk.Task, e sdk.Emitter, server string) error {
	obs := sdk.Observation{
		Predicate: "no_whois_record",
		Object:    t.Target.Value,
		Source:    sdk.Source{Module: "whois", Provider: server, Method: "whois.query"},
		// The registry is authoritative about its own holdings, and "there is no
		// record" needs no corroboration.
		Reliability: registryReliability,
		Credibility: registryCredibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("server", server)
	// This is distinct from a name that was registered and later deleted, and from a
	// name the server was not authoritative for. It says only what this server holds.
	obs.AddAttr("note", "this server holds no record for the name; this is not a claim about whether the name was ever registered")
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "whois-no-record",
		Severity:    sdk.SevInfo,
	})
}

// severityFor rates a record state.
func severityFor(rec *record) string {
	if rec.holdsLock() {
		// An expiry date in the past, or an explicit expired status, means the name may
		// already be available for someone else to take.
		return sdk.SevLow
	}
	return sdk.SevInfo
}

func normalizeName(v string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}

func tldOf(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return name[i+1:]
}

func hostOfAddress(addr string) string {
	h, _, found := strings.Cut(addr, ":")
	if !found {
		return addr
	}
	return h
}

func dedupe(in []string) []string {
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

// readBoundedResponse reads a WHOIS answer, reporting truncation.
//
// A truncated WHOIS record parses into a plausible-looking but incomplete one, most
// dangerously by losing the contact block so the name appears to have no registrant
// at all. Truncation is therefore surfaced rather than absorbed.
func readBoundedResponse(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 128 << 10
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
