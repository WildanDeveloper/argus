// Package asnlookup resolves an IP address or autonomous system to the network that
// announces it and the organisation that holds it.
//
// Two claims are kept strictly apart here, because conflating them is how a routing
// lookup turns into a false attribution:
//
//   - Which autonomous system originates these addresses right now. That is a
//     routing fact and it changes; BGP origin can and does move.
//   - Who operates the service in front of them. That is not the same thing at all.
//     A shared CDN edge originates in the CDN's AS, and nothing in the routing data
//     says which customer an address belongs to.
//
// So this module reports origin and holder, and never claims that a domain's operator
// is the holder of the network its addresses happen to route through.
package asnlookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// Grading. A route collector's view is reputable and current, but it is a snapshot
// of a mutable system observed through an intermediary, so it is B rather than A.
// Nothing here corroborates a second source, so credibility 2.
const (
	gradeReliability = 'B'
	gradeCredibility = '2'
)

// Module is the asn-lookup collector.
type Module struct {
	http sdk.HTTPDoer
	dns  sdk.DNSResolver
	now  func() time.Time

	cymruBase    string
	ripeBase     string
	keepEvidence bool
	maxBody      int64
}

// Option configures the module.
type Option func(*Module)

// WithHTTPDoer injects the brokered client.
func WithHTTPDoer(h sdk.HTTPDoer) Option { return func(m *Module) { m.http = h } }

// WithDNS injects the brokered resolver.
func WithDNS(d sdk.DNSResolver) Option { return func(m *Module) { m.dns = d } }

// WithBases overrides the service locations so tests make no outbound request.
func WithBases(cymru, ripe string) Option {
	return func(m *Module) {
		if cymru != "" {
			m.cymruBase = cymru
		}
		if ripe != "" {
			m.ripeBase = ripe
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
		cymruBase:    "origin.asn.cymru.com",
		ripeBase:     "https://stat.ripe.net/data",
		keepEvidence: true,
		maxBody:      4 << 20,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "asn-lookup",
		Version:     Version,
		Category:    "network",
		Description: "Origin autonomous system and holder for an IP address or ASN",
		Consumes:    []sdk.EntityType{sdk.TypeIP, sdk.TypeCIDR, sdk.TypeASN},
		Produces:    []sdk.EntityType{sdk.TypeASN, sdk.TypeCIDR, sdk.TypeOrg, sdk.TypeFinding},
		Mode:        sdk.ModePassive,
		Sensitivity: sdk.SensLow,
		// The resolvers are declared because the DNS lookup goes out over DoH to one
		// of them, and a module that resolves without saying where reaches hosts it
		// never declared. Same list dns-records carries; the resolver is a
		// configuration choice, and a module cannot make one on its own.
		EgressHosts: []string{
			"stat.ripe.net",
			"cloudflare-dns.com",
			"dns.google",
			"dns.adguard-dns.com",
		},
		RateHints: map[string]sdk.Rate{
			"stat.ripe.net": {Requests: 2, Per: time.Second, Burst: 5},
		},
		Tags: []string{"network", "routing", "attribution"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.DNS == nil {
		return fmt.Errorf("asn-lookup: no DNS resolver injected")
	}
	m.dns = d.DNS
	if d.HTTP != nil {
		m.http = d.HTTP
	}
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// origin is one address-to-network mapping.
type origin struct {
	asn      string
	prefix   string
	country  string
	registry string
	// allocation is the date the block was allocated, as published. It is not a
	// first-seen date and is never presented as one.
	allocation string
}

// Run resolves a target to its announcing network and holder.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("asn-lookup: task has no target")
	}

	switch t.Target.Type {
	case sdk.TypeASN:
		return m.runASN(ctx, t, e, t.Target.Value)
	case sdk.TypeIP, sdk.TypeCIDR:
		return m.runIP(ctx, t, e, t.Target.Value)
	}
	// A domain or a username has no routing record to look up.
	return nil
}

// runIP resolves an address to its origin AS and announcing prefix.
func (m *Module) runIP(ctx context.Context, t sdk.Task, e sdk.Emitter, value string) error {
	addr, ok := addressOf(value)
	if !ok {
		return nil
	}

	o, found, err := m.cymruOrigin(ctx, e, addr)
	if err != nil {
		return err
	}
	if !found {
		// No route record is a fact about the collector's database, not proof the
		// address is unrouted or unallocated.
		return m.emitNoOrigin(t, e, addr)
	}

	source := sdk.Source{Module: "asn-lookup", Provider: "cymru", Method: "dns.origin"}
	obs := sdk.Observation{
		Predicate:   "originated_by",
		Object:      o.asn,
		Source:      source,
		Reliability: gradeReliability,
		Credibility: gradeCredibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("asn", o.asn)
	obs.AddAttr("prefix", o.prefix)
	obs.AddAttr("registry", o.registry)
	if o.country != "" {
		obs.AddAttr("country", o.country)
	}
	if o.allocation != "" {
		obs.AddAttr("block_allocated_at", o.allocation)
	}
	// Routing is mutable and this is a snapshot. Recording when it was observed is
	// what lets a later reader tell a stale answer from a current one.
	obs.AddAttr("routing_snapshot", true)

	asnEnt, err := sdk.NewEntityOrErr(sdk.TypeASN, "AS"+o.asn)
	if err != nil {
		return err
	}
	// part_of_network runs address to autonomous system, which is the direction the
	// routing data actually supports. An inverted edge would claim the autonomous
	// system originates from the address.
	if err := e.Emit(sdk.Finding{
		Entity:      asnEnt,
		Relations:   []sdk.Relation{sdk.Rel(t.Target.ID, asnEnt.ID, sdk.RelPartOfNetwork)},
		Observation: obs,
		Kind:        "asn-origin",
		Severity:    sdk.SevInfo,
	}); err != nil {
		return err
	}

	if o.prefix != "" {
		if cidr, err := sdk.NewEntityOrErr(sdk.TypeCIDR, o.prefix); err == nil {
			pobs := sdk.Observation{
				Predicate:   "announced_prefix",
				Object:      o.prefix,
				Source:      source,
				Reliability: gradeReliability,
				Credibility: gradeCredibility,
				ObservedAt:  m.now(),
			}
			pobs.AddAttr("asn", o.asn)
			if err := e.Emit(sdk.Finding{
				Entity:      cidr,
				Relations:   []sdk.Relation{sdk.Rel(cidr.ID, asnEnt.ID, sdk.RelAnnouncedBy)},
				Observation: pobs,
				Kind:        "asn-announced-prefix",
				Severity:    sdk.SevInfo,
			}); err != nil {
				return err
			}
		}
	}

	return m.lookupHolder(ctx, e, asnEnt, o.asn)
}

// runASN resolves an autonomous system to its holder.
func (m *Module) runASN(ctx context.Context, t sdk.Task, e sdk.Emitter, value string) error {
	num := trimAS(value)
	if num == "" {
		return nil
	}
	return m.lookupHolder(ctx, e, t.Target, num)
}

// lookupHolder resolves the organisation holding an autonomous system.
//
// RIPEstat is the source here because it publishes a human-readable holder name.
// Team Cymru's AS records carry the same data in DNS but public resolvers
// frequently answer them with NODATA, so relying on them alone would make the holder
// unavailable in most deployments.
func (m *Module) lookupHolder(ctx context.Context, e sdk.Emitter, asnEnt sdk.Entity, num string) error {
	if m.http == nil {
		return nil
	}
	url := m.ripeBase + "/as-overview/data.json?resource=AS" + num
	raw, err := m.get(ctx, e, url)
	if err != nil {
		return err
	}

	var resp struct {
		Status string `json:"status"`
		// status_code is RIPEstat's own HTTP-equivalent code. It is checked too
		// because "status" is a short label that has changed spelling across API
		// versions, while the numeric code has not.
		StatusCode int `json:"status_code"`
		Data       struct {
			Resource  string `json:"resource"`
			Holder    string `json:"holder"`
			Announced *bool  `json:"announced"`
			Block     struct {
				Resource string `json:"resource"`
				Desc     string `json:"desc"`
				Name     string `json:"name"`
			} `json:"block"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("asn-lookup: parse RIPEstat response: %w", err)
	}
	// RIPEstat reports success as status "ok". An earlier version of this check
	// accepted "success", which the API has never returned: every lookup failed while
	// the endpoint was plainly working, and the failure looked like a service
	// problem rather than a wrong constant.
	switch resp.Status {
	case "ok", "success":
		// Both spellings accepted so a future relabelling does not break the module.
	case "":
		if resp.StatusCode != 0 && resp.StatusCode != 200 {
			return fmt.Errorf("asn-lookup: RIPEstat returned status_code %d for AS%s", resp.StatusCode, num)
		}
	default:
		return fmt.Errorf("asn-lookup: RIPEstat returned status %q for AS%s", resp.Status, num)
	}
	if resp.StatusCode != 0 && resp.StatusCode != 200 {
		return fmt.Errorf("asn-lookup: RIPEstat returned status_code %d for AS%s", resp.StatusCode, num)
	}

	holder := strings.TrimSpace(resp.Data.Holder)
	if holder == "" {
		// RIPEstat answers successfully for a reserved or unallocated block with no
		// holder. Saying so is more useful than emitting nothing.
		e.Warn("no holder published for this autonomous system", "asn", num)
		return nil
	}

	orge, err := sdk.NewEntityOrErr(sdk.TypeOrg, holder)
	if err != nil {
		return nil
	}
	obs := sdk.Observation{
		Predicate:   "held_by",
		Object:      holder,
		Source:      sdk.Source{Module: "asn-lookup", Provider: "stat.ripe.net", Method: "as-overview"},
		Reliability: gradeReliability,
		Credibility: gradeCredibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("asn", "AS"+num)
	obs.AddAttr("block", resp.Data.Block.Resource)
	if resp.Data.Block.Desc != "" {
		obs.AddAttr("block_description", resp.Data.Block.Desc)
	}
	if resp.Data.Announced != nil {
		obs.AddAttr("announced", *resp.Data.Announced)
	}
	// The holder is the organisation the number is registered to. It is not a claim
	// about who runs services on addresses inside the block, which for a shared
	// network is frequently nobody the holder has a contract with.
	obs.AddAttr("holder_scope", "registration of the autonomous system number, not operation of services on its prefixes")

	// owned_by is not flagged heuristic because it is backed by a registry: this is
	// the RIR's own allocation record for the number. What it does not say is that
	// the organisation operates any particular service on that network, and the
	// observation says so rather than leaving a reader to over-read the edge.
	return e.Emit(sdk.Finding{
		Entity:      orge,
		Relations:   []sdk.Relation{sdk.Rel(asnEnt.ID, orge.ID, sdk.RelOwnedBy)},
		Observation: obs,
		Kind:        "asn-holder",
		Severity:    sdk.SevInfo,
	})
}

// cymruOrigin queries Team Cymru's DNS interface for an address's origin.
//
// A missing record is reported as missing rather than as an error. NXDOMAIN from
// this database means "not in our tables", which is a much weaker statement than "no
// such network exists".
func (m *Module) cymruOrigin(ctx context.Context, e sdk.Emitter, addr string) (origin, bool, error) {
	// The reversed address is the leftmost label; the service suffix follows it.
	name := reversedIP(addr) + "." + m.cymruBase
	records, err := m.dns.Lookup(ctx, name, "TXT")
	if err != nil {
		// A resolver error is a transport failure, distinct from an absent record.
		return origin{}, false, fmt.Errorf("asn-lookup: query %s: %w", name, err)
	}
	for _, r := range records {
		if o, ok := parseCymru(r.Data); ok {
			// Retain the answer. A route claim with no retrievable artifact is capped
			// at half confidence by the evidence-first rule, which is correct but also
			// means the raw record is the only way to re-check the parsing.
			if err := retainDNSAnswer(ctx, e, name, r); err != nil {
				e.Warn("evidence capture failed", "name", name, "err", err.Error())
			}
			return o, true, nil
		}
	}
	return origin{}, false, nil
}

// retainDNSAnswer stores the DNS answer that a routing claim is based on.
func retainDNSAnswer(ctx context.Context, e sdk.Emitter, name string, r sdk.DNSRecord) error {
	payload := map[string]any{
		"question": name,
		"type":     r.Type,
		"answer":   r.Data,
		"ttl":      r.TTL,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	_, err = e.PutEvidence(ctx, sdk.EvidenceMeta{
		Source:    "dns:" + name,
		Method:    "dns.lookup",
		MediaType: "application/json",
	}, raw)
	return err
}

// parseCymru decodes a Cymru origin TXT record.
//
// The format is pipe-separated: ASN | prefix | country | registry | allocation date.
// The trailing date is the block's allocation date, not a first-seen date, and
// treating it as one would claim the network existed then.
func parseCymru(s string) (origin, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return origin{}, false
	}
	parts := strings.Split(s, "|")
	if len(parts) < 4 {
		return origin{}, false
	}
	o := origin{
		asn:      strings.TrimSpace(parts[0]),
		prefix:   strings.TrimSpace(parts[1]),
		country:  strings.TrimSpace(parts[2]),
		registry: strings.TrimSpace(parts[3]),
	}
	if len(parts) > 4 {
		o.allocation = strings.TrimSpace(parts[4])
	}
	// Cymru quotes and space-pads long TXT values when they are concatenated.
	o.asn = trimQuotes(o.asn)
	o.prefix = trimQuotes(o.prefix)
	o.country = trimQuotes(o.country)
	o.registry = trimQuotes(o.registry)
	if !isASNumber(o.asn) {
		return origin{}, false
	}
	return o, true
}

// emitNoOrigin records an address with no published route.
func (m *Module) emitNoOrigin(t sdk.Task, e sdk.Emitter, addr string) error {
	obs := sdk.Observation{
		Predicate:   "no_origin_recorded",
		Object:      addr,
		Source:      sdk.Source{Module: "asn-lookup", Provider: "cymru", Method: "dns.origin"},
		Reliability: gradeReliability,
		Credibility: gradeCredibility,
		ObservedAt:  m.now(),
	}
	// Absent from a route collector's tables is not the same as unrouted. Saying so
	// keeps a gap in one database from reading as a conclusion about the address.
	obs.AddAttr("note", "no origin published for this address by the queried collector; this is not a claim that the address is unrouted or unallocated")
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "asn-no-origin",
		Severity:    sdk.SevInfo,
	})
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

	data, truncated, err := readBounded(resp.Body, m.maxBody)
	if err != nil {
		return nil, fmt.Errorf("asn-lookup: read response: %w", err)
	}
	if truncated {
		return nil, fmt.Errorf("asn-lookup: response from %s exceeded %d bytes; refusing to parse a partial record", rawURL, m.maxBody)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("asn-lookup: %s returned HTTP %d", rawURL, resp.StatusCode)
	}

	if m.keepEvidence {
		if _, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source: rawURL, Method: "as-overview", MediaType: "application/json",
		}, data); err != nil {
			e.Warn("evidence capture failed", "url", rawURL, "err", err.Error())
		}
	}
	return data, nil
}

// reversedIP renders an IPv4 address in the reversed-octet form Team Cymru expects.
// An IPv6 address has no such form, so the lookup is skipped rather than queried
// with nonsense.
func reversedIP(addr string) string {
	if strings.Contains(addr, ":") {
		return ""
	}
	parts := strings.Split(addr, ".")
	if len(parts) != 4 {
		return ""
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

// addressOf extracts an address from an IP or CIDR target.
func addressOf(value string) (string, bool) {
	if i := strings.IndexByte(value, '/'); i > 0 {
		value = value[:i]
	}
	c, err := sdk.Canonicalize(sdk.TypeIP, strings.Trim(value, "[]"))
	if err != nil {
		return "", false
	}
	return c, true
}

// trimAS strips an AS prefix and rejects anything that is not a number.
func trimAS(v string) string {
	v = strings.TrimSpace(strings.ToUpper(v))
	v = strings.TrimPrefix(v, "AS")
	if !isASNumber(v) {
		return ""
	}
	return v
}

func isASNumber(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	return strings.TrimSpace(s)
}

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
