// Package ipgeo geolocates an IP address using several independent providers and
// scoring their agreement rather than trusting any one of them.
//
// The reason this is not a lookup is that no single provider is right. IP
// geolocation databases are built from a mixture of BGP announcements, WHOIS
// registrations, traceroutes, user submissions and commercial deals, and for an
// address on shared or anycast infrastructure the answers legitimately differ. A
// module that returns one provider's city as a fact is reporting an artefact of
// which database happened to be consulted.
//
// So agreement is the measurement. A field every provider agrees on is reported as
// corroborated; a field where they split is either omitted or reported with the
// spread, because a single answer chosen from a disagreement is arbitrary.
package ipgeo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// Reliability is fixed at C for every aggregated observation. These are commercial
// databases of uneven provenance, so even unanimous agreement among three of them
// is "fairly reliable" and not more. Credibility is what agreement moves: three
// independent databases saying the same thing is a materially stronger claim than
// one database saying anything at all, and that difference belongs in the
// credibility axis rather than being smeared across both.
const gradeReliability = 'C'

// Module is the ip-geo collector.
type Module struct {
	http sdk.HTTPDoer
	now  func() time.Time

	adapters     []adapter
	keepEvidence bool
	maxBody      int64
}

// Option configures the module.
type Option func(*Module)

// WithHTTPDoer injects the brokered client.
func WithHTTPDoer(h sdk.HTTPDoer) Option { return func(m *Module) { m.http = h } }

// WithAdapters replaces the provider set.
func WithAdapters(as ...adapter) Option { return func(m *Module) { m.adapters = as } }

// WithEvidence turns artifact retention on or off.
func WithEvidence(on bool) Option { return func(m *Module) { m.keepEvidence = on } }

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{
		now:          time.Now,
		adapters:     defaultAdapters(),
		keepEvidence: true,
		maxBody:      1 << 20,
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
		Name:        "ip-geo",
		Version:     Version,
		Category:    "network",
		Description: "IP geolocation from independent providers, scored by their agreement",
		Consumes:    []sdk.EntityType{sdk.TypeIP, sdk.TypeCIDR},
		Produces:    []sdk.EntityType{sdk.TypeLocation, sdk.TypeOrg, sdk.TypeASN, sdk.TypeFinding},
		Mode:        sdk.ModePassive,
		Sensitivity: sdk.SensLow,
		EgressHosts: hosts,
		RateHints: map[string]sdk.Rate{
			"ipwho.is":      {Requests: 2, Per: time.Second, Burst: 5},
			"ipinfo.io":     {Requests: 2, Per: time.Second, Burst: 5},
			"freeipapi.com": {Requests: 2, Per: time.Second, Burst: 5},
		},
		Tags: []string{"geo", "attribution", "multi-source"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.HTTP == nil {
		return fmt.Errorf("ip-geo: no HTTP client injected")
	}
	m.http = d.HTTP
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// observation is one provider's answer, normalized.
type observation struct {
	provider    string
	country     string // ISO 3166-1 alpha-2
	countryName string
	region      string
	city        string
	lat         float64
	lon         float64
	hasPoint    bool
	org         string
	asn         string
	// anycast is reported by some providers and not others. A true value explains
	// disagreement rather than being an ordinary attribute, so it is carried up to
	// the aggregation instead of being merged into the country or city.
	anycast bool
	// hasAnycast distinguishes "reported false" from "not reported at all".
	hasAnycast bool
}

// Run geolocates the target and emits what the providers agree on.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("ip-geo: task has no target")
	}
	addr, ok := addressOf(t.Target.Value)
	if !ok {
		return nil
	}

	type result struct {
		obs *observation
		err error
	}
	results := make(chan result, len(m.adapters))
	for _, a := range m.adapters {
		a := a
		go func() {
			o, err := fetchOne(ctx, a, m, e, addr)
			results <- result{obs: o, err: err}
		}()
	}

	var (
		obs      []*observation
		failures []string
	)
	for range m.adapters {
		r := <-results
		if r.err != nil {
			// A provider being unavailable is ordinary. One failure must not discard
			// the answers that did arrive, and must not be reported as a negative.
			failures = append(failures, r.err.Error())
			e.Warn("geolocation source failed", "err", r.err.Error())
			continue
		}
		if r.obs != nil {
			obs = append(obs, r.obs)
		}
	}

	if len(obs) == 0 {
		// Every source failed. Reporting "no location" here would be indistinguishable
		// from an address that genuinely has none.
		return fmt.Errorf("ip-geo: every source failed for %s: %s", addr, strings.Join(failures, "; "))
	}

	sort.Slice(obs, func(i, j int) bool { return obs[i].provider < obs[j].provider })
	return m.emit(t, e, addr, obs, len(failures))
}

// emit writes the agreed fields and reports the disagreements.
func (m *Module) emit(t sdk.Task, e sdk.Emitter, addr string, obs []*observation, failures int) error {
	anycast := anycastClaim(obs)

	source := sdk.Source{Module: "ip-geo", Provider: "multi", Method: "geo.aggregate"}

	fields := []string{}
	if c, ok := agreeString(obs, func(o *observation) string { return o.country }); ok {
		fields = append(fields, "country")
		o := buildObs(m.now(), source, "country", c.value, c.cred,
			"field", "country", "anycast", anycast,
			"providers_agreeing", c.agreeing, "providers_total", c.total)
		if err := e.Emit(sdk.Finding{Entity: t.Target, Observation: o}); err != nil {
			return err
		}
	}
	if c, ok := agreeString(obs, func(o *observation) string { return o.region }); ok {
		o := buildObs(m.now(), source, "region", c.value, c.cred,
			"field", "region", "anycast", anycast,
			"providers_agreeing", c.agreeing, "providers_total", c.total)
		if err := e.Emit(sdk.Finding{Entity: t.Target, Observation: o}); err != nil {
			return err
		}
	}

	if city, ok := agreeString(obs, func(o *observation) string { return o.city }); ok {
		o := buildObs(m.now(), source, "city", city.value, city.cred,
			"field", "city", "anycast", anycast,
			"providers_agreeing", city.agreeing, "providers_total", city.total)
		if anycast {
			// For anycast infrastructure there is no single correct city, and a
			// majority vote among databases does not make one right. The value is
			// still emitted because it is the best available lead, but the precision
			// claim is withdrawn.
			o.AddAttr("precision", "city-level, disputed: the address is anycast")
		}
		if err := e.Emit(sdk.Finding{Entity: t.Target, Observation: o}); err != nil {
			return err
		}
	}

	// Coordinates. When the providers disagree, picking one point is arbitrary, so
	// the centroid is published together with the radius that contains every
	// provider's answer. A reader then knows the area rather than being handed false
	// precision.
	if _, lat, lon, radiusKm, n := agreePoint(obs); n > 0 {
		o := buildObs(m.now(), source, "approximate_location",
			fmt.Sprintf("%.4f,%.4f", lat, lon), agreeCredibility(n, len(obs)),
			"field", "coordinates", "anycast", anycast, "centroid", true,
			"providers_agreeing", n, "providers_total", len(obs))
		o.AddAttr("latitude", round4(lat))
		o.AddAttr("longitude", round4(lon))
		if radiusKm > 0 {
			o.AddAttr("radius_km", round2(radiusKm))
			// Spelled out so a consumer that reads only the point still knows it is
			// not a precise fix.
			o.AddAttr("precision", fmt.Sprintf("within %.2f km of the centroid, not a point fix", round2(radiusKm)))
		} else {
			o.AddAttr("precision", "providers agree on a single point")
		}
		if err := e.Emit(sdk.Finding{Entity: t.Target, Observation: o}); err != nil {
			return err
		}
	}

	// Organisation and autonomous system, which providers agree on far more often
	// than they agree on a city. The org edge is heuristic: a geolocation database
	// records which network serves an address, not who operates the service behind it.
	if org, ok := agreeString(obs, func(o *observation) string { return o.org }); ok {
		if orge, err := sdk.NewEntityOrErr(sdk.TypeOrg, org.value); err == nil {
			o := buildObs(m.now(), source, "operated_by", org.value, org.cred,
				"field", "org",
				"providers_agreeing", org.agreeing, "providers_total", org.total)
			o.AddAttr("scope", "the organisation serving this address, not necessarily the operator of any service on it")
			if err := e.Emit(sdk.Finding{
				Entity:      orge,
				Relations:   []sdk.Relation{sdk.HeuristicRel(t.Target.ID, orge.ID, sdk.RelOwnedBy)},
				Observation: o,
			}); err != nil {
				return err
			}
		}
	}
	if asn, ok := agreeString(obs, func(o *observation) string { return o.asn }); ok {
		if asnEnt, err := sdk.NewEntityOrErr(sdk.TypeASN, "AS"+asn.value); err == nil {
			o := buildObs(m.now(), source, "origin_asn", "AS"+asn.value, asn.cred,
				"field", "asn",
				"providers_agreeing", asn.agreeing, "providers_total", asn.total)
			if err := e.Emit(sdk.Finding{
				Entity:      asnEnt,
				Relations:   []sdk.Relation{sdk.HeuristicRel(t.Target.ID, asnEnt.ID, sdk.RelPartOfNetwork)},
				Observation: o,
			}); err != nil {
				return err
			}
		}
	}

	// A location entity when the country is agreed, since that is the level worth
	// keying a graph node on. The edge is not heuristic: every provider placed the
	// address in this country, and country is the coarsest and most stable of the
	// geographic claims.
	if country, ok := agreeString(obs, func(o *observation) string { return o.country }); ok {
		if loc, err := sdk.NewEntityOrErr(sdk.TypeLocation, country.value); err == nil {
			o := buildObs(m.now(), source, "located_in", country.value, country.cred,
				"field", "country",
				"providers_agreeing", country.agreeing, "providers_total", country.total)
			if err := e.Emit(sdk.Finding{
				Entity:      loc,
				Relations:   []sdk.Relation{sdk.Rel(t.Target.ID, loc.ID, sdk.RelLocatedAt)},
				Observation: o,
			}); err != nil {
				return err
			}
		}
	}

	// The disagreement itself is a finding. Silently reporting only the agreed
	// fields would hide how uncertain the rest is.
	disputed := disputedFields(obs)
	summary := sdk.Observation{
		Predicate:   "geo_summary",
		Object:      addr,
		Source:      source,
		Reliability: gradeReliability,
		// The summary describes the providers' agreement, not a location, so it
		// carries the same grade as any single observation.
		Credibility: agreeCredibility(len(obs), len(obs)),
		ObservedAt:  m.now(),
	}
	summary.AddAttr("providers", providerNames(obs))
	summary.AddAttr("providers_succeeded", len(obs))
	summary.AddAttr("providers_failed", failures)
	summary.AddAttr("disputed_fields", disputed)
	summary.AddAttr("anycast", anycast)
	summary.AddAttr("geolocation_scope",
		"the location of the network or point of presence serving this address, not of the organisation that operates the service")
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: summary,
		Kind:        "ip-geo-summary",
		Severity:    sdk.SevInfo,
	})
}

// buildObs builds one aggregated finding.
func buildObs(now time.Time, source sdk.Source, predicate, value string, cred byte, attrs ...any) sdk.Observation {
	o := sdk.Observation{
		Predicate:   predicate,
		Object:      value,
		Source:      source,
		Reliability: gradeReliability,
		Credibility: cred,
		ObservedAt:  now,
	}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		o.AddAttr(k, attrs[i+1])
	}
	return o
}

// agreeString returns the consensus value of a string field.
//
// The rule is deliberately conservative: a value must be shared by a majority of the
// providers that answered. With two providers that means both, because a coin flip
// is not consensus. When there is no majority the field is omitted rather than
// guessed, and the caller records it as disputed.
func agreeString(obs []*observation, get func(*observation) string) (consensus, bool) {
	counts := map[string]int{}
	for _, o := range obs {
		if v := strings.TrimSpace(get(o)); v != "" {
			counts[v]++
		}
	}
	if len(counts) == 0 {
		return consensus{}, false
	}
	// Deterministic tie-break: highest count, then alphabetical, so the same input
	// always produces the same output and a tie is not decided by map order.
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	best := keys[0]
	if counts[best]*2 <= len(obs) {
		return consensus{}, false
	}
	// The count is carried through because reporting "three providers agree" when two
	// of three did is a misstatement of the evidence, and an observation whose own
	// attributes overstate its support is worse than no observation.
	return consensus{
		value:    best,
		cred:     agreeCredibility(counts[best], len(obs)),
		agreeing: counts[best],
		total:    len(obs),
	}, true
}

// consensus is the outcome of comparing one field across the providers.
type consensus struct {
	value    string
	cred     byte
	agreeing int
	total    int
}

// agreePoint returns the centroid of the reported coordinates and the radius that
// contains them all.
func agreePoint(obs []*observation) (string, float64, float64, float64, int) {
	var latSum, lonSum float64
	type pt struct{ lat, lon float64 }
	pts := []pt{}
	for _, o := range obs {
		if !o.hasPoint {
			continue
		}
		latSum += o.lat
		lonSum += o.lon
		pts = append(pts, pt{o.lat, o.lon})
	}
	n := len(pts)
	if n == 0 {
		return "", 0, 0, 0, 0
	}
	lat, lon := latSum/float64(n), lonSum/float64(n)
	maxKm := 0.0
	for _, p := range pts {
		if d := haversineKm(lat, lon, p.lat, p.lon); d > maxKm {
			maxKm = d
		}
	}
	return "", lat, lon, maxKm, n
}

// agreeCredibility converts an agreement count into an Admiralty credibility.
//
// Unanimity among every provider that answered is "confirmed by independent
// sources". A majority is "probably true". Nothing else is emitted as a fact.
func agreeCredibility(agreeing, total int) byte {
	if total == 0 || agreeing == 0 {
		return '3'
	}
	switch {
	case agreeing == total:
		return '1'
	case agreeing*2 > total:
		return '2'
	default:
		return '3'
	}
}

// anycastClaim reports whether any provider flagged the address as anycast.
func anycastClaim(obs []*observation) bool {
	for _, o := range obs {
		if o.anycast {
			return true
		}
	}
	return false
}

// disputedFields lists the fields the providers did not agree on.
func disputedFields(obs []*observation) []string {
	var out []string
	for _, f := range []struct {
		name string
		get  func(*observation) string
	}{
		{"country", func(o *observation) string { return o.country }},
		{"region", func(o *observation) string { return o.region }},
		{"city", func(o *observation) string { return o.city }},
		{"org", func(o *observation) string { return o.org }},
		{"asn", func(o *observation) string { return o.asn }},
	} {
		if _, ok := agreeString(obs, f.get); !ok {
			out = append(out, f.name)
		}
	}
	sort.Strings(out)
	return out
}

func providerNames(obs []*observation) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.provider)
	}
	sort.Strings(out)
	return out
}

// haversineKm is the great-circle distance between two points, in kilometres.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthKm = 6371.0
	dLat := (lat2 - lat1) * degToRad
	dLon := (lon2 - lon1) * degToRad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*degToRad)*math.Cos(lat2*degToRad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return earthKm * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

const degToRad = 0.017453292519943295

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

// get issues a bounded GET and retains the response.
func (m *Module) get(ctx context.Context, e sdk.Emitter, rawURL, provider string) ([]byte, error) {
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
		return nil, fmt.Errorf("%s: read response: %w", provider, err)
	}
	if truncated {
		return nil, fmt.Errorf("%s: response exceeded %d bytes; refusing to parse a partial record", provider, m.maxBody)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: returned HTTP %d", provider, resp.StatusCode)
	}
	if m.keepEvidence {
		if _, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source: rawURL, Method: "geo.lookup", MediaType: "application/json",
		}, data); err != nil {
			e.Warn("evidence capture failed", "url", rawURL, "err", err.Error())
		}
	}
	return data, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 1 << 20
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

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
func round4(f float64) float64 { return float64(int64(f*10000+0.5)) / 10000 }

// escapeQuery percent-encodes a value for use in a query string.
func escapeQuery(s string) string { return url.QueryEscape(s) }

// readJSON decodes a JSON body into v.
func readJSON(raw []byte, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return nil
}

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}
