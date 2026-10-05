package ipgeo

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// These three bodies are what the services returned for 8.8.8.8 when this module
// was written, kept as captured rather than as imagined. The disagreement between
// them is the reason the module exists: three databases, three cities, and one of
// them explaining why.
const ipwhoisBody = `{
  "ip": "8.8.8.8", "success": true, "type": "IPv4",
  "continent": "North America", "continent_code": "NA",
  "country": "United States", "country_code": "US",
  "region": "California", "region_code": "CA",
  "city": "San Jose", "latitude": 37.3393939, "longitude": -121.8949553,
  "is_eu": false, "postal": "95025",
  "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC", "domain": "google.com"},
  "timezone": {"id": "America/Los_Angeles"}
}`

const ipinfoBody = `{
  "ip": "8.8.8.8",
  "hostname": "dns.google",
  "city": "Mountain View",
  "region": "California",
  "country": "US",
  "loc": "38.0088,-122.1175",
  "org": "AS15169 Google LLC",
  "postal": "94043",
  "timezone": "America/Los_Angeles",
  "anycast": true
}`

const freeipapiBody = `{
  "ipVersion": 4, "ipAddress": "8.8.8.8",
  "latitude": 37.422, "longitude": -122.085,
  "countryName": "United States", "countryCode": "US",
  "regionCode": "CA", "regionName": "California", "cityName": "Mountain View",
  "zipCode": "94035", "asn": "15169", "asnOrganization": "Google LLC", "isProxy": false
}`

func newHarness(t *testing.T, opts ...Option) *sdktest.Harness {
	t.Helper()
	h := sdktest.NewHarness(t, New(opts...))
	h.HTTP.Respond("ipwho.is", http.StatusOK, ipwhoisBody, "application/json")
	h.HTTP.Respond("ipinfo.io", http.StatusOK, ipinfoBody, "application/json")
	h.HTTP.Respond("free.freeipapi.com", http.StatusOK, freeipapiBody, "application/json")
	return h
}

func TestManifestIsPassive(t *testing.T) {
	man := New().Manifest()
	if man.Mode != sdk.ModePassive {
		t.Errorf("mode = %v, want passive", man.Mode)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
	// Hosts are derived from the adapters rather than hardcoded, so a removed
	// provider cannot leave a stale permission behind.
	for _, want := range []string{"ipwho.is", "ipinfo.io", "free.freeipapi.com"} {
		if !containsStr(man.EgressHosts, want) {
			t.Errorf("EgressHosts = %v, missing %q", man.EgressHosts, want)
		}
	}
}

func TestOnlyHTTPSProvidersAreUsed(t *testing.T) {
	// ip-api.com would be a natural fourth source, but its unauthenticated tier is
	// cleartext only, and an on-path attacker able to rewrite a geolocation answer
	// would place an operator in a city they are not.
	for _, a := range defaultAdapters() {
		if !strings.HasPrefix(a.buildURL("8.8.8.8"), "https://") {
			t.Errorf("adapter %s builds a non-HTTPS URL: %s", a.name(), a.buildURL("8.8.8.8"))
		}
	}
}

func TestAgreedFieldsAreEmitted(t *testing.T) {
	// All three say US and California, so those are reported as corroborated.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	h.AssertEntities(sdk.TypeOrg, "Google LLC")
	h.AssertEntities(sdk.TypeASN, "AS15169")
	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()

	var sawCountry, sawRegion bool
	for _, f := range h.Out.Findings {
		switch f.Observation.Predicate {
		case "country":
			sawCountry = f.Observation.Object == "US"
		case "region":
			sawRegion = f.Observation.Object == "California"
		}
	}
	if !sawCountry {
		t.Error("the agreed country was not reported")
	}
	if !sawRegion {
		t.Error("the agreed region was not reported")
	}
}

func TestUnanimityIsCredibilityOne(t *testing.T) {
	// Three independent databases saying the same thing is the "confirmed by
	// independent sources" case on the Admiralty credibility axis.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "country" {
			continue
		}
		if f.Observation.Credibility != '1' {
			t.Errorf("unanimous country graded %q, want '1'", string(f.Observation.Credibility))
		}
		if f.Observation.Reliability != 'C' {
			t.Errorf("reliability = %q; these databases stay at C however much they agree",
				string(f.Observation.Reliability))
		}
	}
}

func TestMajorityIsCredibilityTwo(t *testing.T) {
	// Two providers say Mountain View and one says San Jose. That is probably true,
	// not confirmed, and the grade has to say so.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	found := false
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "city" {
			continue
		}
		found = true
		if f.Observation.Object != "Mountain View" {
			t.Errorf("city = %v, want the majority value", f.Observation.Object)
		}
		if f.Observation.Credibility != '2' {
			t.Errorf("majority city graded %q, want '2'", string(f.Observation.Credibility))
		}
	}
	if !found {
		t.Fatal("no city observation emitted")
	}
}

func TestSplitFieldIsOmittedNotGuessed(t *testing.T) {
	// When no value has a majority the field is dropped. Emitting one anyway would
	// be picking arbitrarily out of a disagreement.
	obs := []*observation{
		{provider: "a", country: "US"},
		{provider: "b", country: "DE"},
		{provider: "c", country: "FR"},
	}
	if c, ok := agreeString(obs, func(o *observation) string { return o.country }); ok {
		t.Errorf("agreeString accepted %q from a three-way split", c.value)
	}
}

func TestTwoProvidersRequireBothToAgree(t *testing.T) {
	// With two answers a coin flip is not consensus, so a split must produce
	// nothing rather than the alphabetically-first value.
	obs := []*observation{
		{provider: "a", city: "Zurich"},
		{provider: "b", city: "Amsterdam"},
	}
	if c, ok := agreeString(obs, func(o *observation) string { return o.city }); ok {
		t.Errorf("agreeString accepted %q from a two-way split", c.value)
	}
	// Unanimity between two is accepted at a lower credibility.
	obs = []*observation{
		{provider: "a", city: "Zurich"},
		{provider: "b", city: "Zurich"},
	}
	c, ok := agreeString(obs, func(o *observation) string { return o.city })
	if !ok || c.value != "Zurich" {
		t.Errorf("agreeString = %q ok=%v", c.value, ok)
	}
	if c.cred != '1' {
		t.Errorf("unanimity between two providers graded %q", string(c.cred))
	}
}

func TestTieIsBrokenDeterministically(t *testing.T) {
	// Map iteration order is random, so an unfixed tie-break would make the same
	// input produce different output on different runs.
	obs := []*observation{
		{provider: "a", org: "Zeta"},
		{provider: "b", org: "Alpha"},
		{provider: "c", org: "Beta"},
	}
	firstC, _ := agreeString(obs, func(o *observation) string { return o.org })
	first := firstC.value
	for i := 0; i < 20; i++ {
		gotC, _ := agreeString(obs, func(o *observation) string { return o.org })
		got := gotC.value
		if got != first {
			t.Fatalf("tie-break is not stable: %q then %q", first, got)
		}
	}
}

func TestEmptyValuesAreNotConsensus(t *testing.T) {
	// A provider that returned nothing has not agreed with anyone.
	obs := []*observation{
		{provider: "a", country: "US"},
		{provider: "b", country: "US"},
		{provider: "c", country: ""},
	}
	c, ok := agreeString(obs, func(o *observation) string { return o.country })
	if !ok || c.value != "US" {
		t.Fatalf("agreeString = %q ok=%v", c.value, ok)
	}
	// Two of three is a majority, so it is graded as probably true rather than
	// confirmed. Reporting it as unanimous would overstate the corroboration.
	if c.cred != '2' {
		t.Errorf("credibility = %q, want '2': one provider answered nothing", string(c.cred))
	}
	// The reported agreement count must be the real one. An observation claiming
	// three providers agreed when two did is a misstatement of its own support.
	if c.agreeing != 2 || c.total != 3 {
		t.Errorf("agreeing=%d total=%d, want 2 and 3", c.agreeing, c.total)
	}
}

func TestDisagreementBecomesACoordinateArea(t *testing.T) {
	// Choosing one provider's point would be arbitrary. The centroid plus the radius
	// that contains every answer tells a reader what is actually known.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "approximate_location" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no approximate location emitted")
	}
	if attrs["centroid"] != true {
		t.Error("the location is not marked as a centroid")
	}
	r, ok := attrs["radius_km"].(float64)
	if !ok || r <= 0 {
		t.Fatalf("radius_km = %v; the three providers are tens of kilometres apart", attrs["radius_km"])
	}
	prec, _ := attrs["precision"].(string)
	if !strings.Contains(prec, "not a point fix") {
		t.Errorf("precision = %q; a consumer reading only the point must still learn it is approximate", prec)
	}
}

func TestIdenticalCoordinatesReportAPoint(t *testing.T) {
	obs := []*observation{
		{provider: "a", lat: 10, lon: 20, hasPoint: true},
		{provider: "b", lat: 10, lon: 20, hasPoint: true},
	}
	_, _, _, radius, n := agreePoint(obs)
	if n != 2 {
		t.Fatalf("n = %d", n)
	}
	if radius != 0 {
		t.Errorf("radius = %v, want 0 when every provider agrees exactly", radius)
	}
}

func TestAnycastWithdrawsThePrecisionClaim(t *testing.T) {
	// For anycast infrastructure there is no single correct city. A majority vote
	// among databases does not make one right.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var cityAttrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "city" {
			cityAttrs = f.Observation.Attrs
		}
	}
	if cityAttrs == nil {
		t.Fatal("no city observation")
	}
	if flag, _ := cityAttrs["anycast"].(bool); !flag {
		t.Error("the anycast flag from ipinfo was not carried through")
	}
	if prec, _ := cityAttrs["precision"].(string); !strings.Contains(prec, "disputed") {
		t.Errorf("city precision = %q; anycast must withdraw the precision claim", prec)
	}
}

func TestSummaryRecordsTheDisagreement(t *testing.T) {
	// Emitting only the agreed fields would hide how uncertain the rest is.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "geo_summary" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no summary emitted")
	}
	if attrs["anycast"] != true {
		t.Error("the summary does not record the anycast flag")
	}
	if scope, _ := attrs["geolocation_scope"].(string); scope == "" {
		t.Error("the summary does not say what a geolocation answer actually locates")
	}
	providers, _ := attrs["providers"].([]string)
	if len(providers) != 3 {
		t.Errorf("providers = %v, want three", providers)
	}
}

func TestGeolocationScopeIsStatedOnOrgEdges(t *testing.T) {
	// A geolocation database records which network serves an address, not who runs
	// the service behind it.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	saw := false
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != sdk.RelOwnedBy {
				continue
			}
			saw = true
			if !r.Heuristic {
				t.Error("the organisation edge is not flagged heuristic; a geo database cannot establish ownership")
			}
		}
		if f.Observation.Predicate == "operated_by" {
			if scope, _ := f.Observation.Attrs["scope"].(string); scope == "" {
				t.Error("the operated_by observation does not state its scope")
			}
		}
	}
	if !saw {
		t.Fatal("no organisation edge emitted")
	}
}

func TestOneProviderFailingKeepsTheRest(t *testing.T) {
	// Sources go down and rate-limit. One failure must not discard the others, and
	// must not be reported as "no location".
	h := sdktest.NewHarness(t, New())
	h.HTTP.Respond("ipwho.is", http.StatusOK, ipwhoisBody, "application/json")
	h.HTTP.Respond("ipinfo.io", http.StatusTooManyRequests, `rate limited`, "text/plain")
	h.HTTP.Respond("free.freeipapi.com", http.StatusOK, freeipapiBody, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "geo_summary" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no summary emitted after a partial failure")
	}
	if n, _ := attrs["providers_succeeded"].(int); n != 2 {
		t.Errorf("providers_succeeded = %v, want 2", attrs["providers_succeeded"])
	}
	if n, _ := attrs["providers_failed"].(int); n != 1 {
		t.Errorf("providers_failed = %v, want 1", attrs["providers_failed"])
	}
	if h.CountEntities(sdk.TypeASN) != 1 {
		t.Error("the surviving providers' agreement was discarded along with the failure")
	}
}

func TestEveryProviderFailingIsAnError(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	for _, host := range []string{"ipwho.is", "ipinfo.io", "freeipapi.com"} {
		h.HTTP.Respond(host, http.StatusServiceUnavailable, `down`, "text/plain")
	}
	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))
	if err == nil {
		t.Fatal("a total failure must surface rather than report an address as having no location")
	}
}

func TestPlaceholderDocumentIsNotAnAnswer(t *testing.T) {
	// ipinfo answers an unauthenticated request with a valid document whose only
	// real field is a link to its documentation. Counting that as a provider that
	// answered would drag the agreement calculation down for no reason.
	h := sdktest.NewHarness(t, New())
	h.HTTP.Respond("ipwho.is", http.StatusOK, ipwhoisBody, "application/json")
	h.HTTP.Respond("ipinfo.io", http.StatusOK,
		`{"readme": "https://ipinfo.io/missingauth"}`, "application/json")
	h.HTTP.Respond("free.freeipapi.com", http.StatusOK, freeipapiBody, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "geo_summary" {
			attrs = f.Observation.Attrs
		}
	}
	if n, _ := attrs["providers_succeeded"].(int); n != 2 {
		t.Errorf("providers_succeeded = %v; the placeholder must not count as an answer", attrs["providers_succeeded"])
	}
}

func TestServiceLevelFailureInA200BodyIsNotAnAnswer(t *testing.T) {
	// ipwho.is reports its own failures inside a 200 response.
	h := sdktest.NewHarness(t, New())
	h.HTTP.Respond("ipwho.is", http.StatusOK,
		`{"success": false, "message": "Reserved range"}`, "application/json")
	h.HTTP.Respond("ipinfo.io", http.StatusOK, ipinfoBody, "application/json")
	h.HTTP.Respond("free.freeipapi.com", http.StatusOK, freeipapiBody, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeIP, "192.0.2.1"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "geo_summary" {
			attrs = f.Observation.Attrs
		}
	}
	if n, _ := attrs["providers_succeeded"].(int); n != 2 {
		t.Errorf("providers_succeeded = %v; a success:false body is not an answer", attrs["providers_succeeded"])
	}
}

func TestProxyFlagIsNotTreatedAsAnycast(t *testing.T) {
	// freeipapi publishes isProxy. Mapping it onto anycast would suppress a
	// legitimate city for every address behind a proxy, which is most of the
	// internet.
	o, err := freeipapi{}.parse([]byte(freeipapiBody))
	if err != nil {
		t.Fatal(err)
	}
	if o.anycast {
		t.Error("isProxy was read as an anycast claim")
	}
	if o.hasAnycast {
		t.Error("hasAnycast was set by a proxy flag")
	}
}

func TestAbsenceOfAnycastFlagIsNotANegative(t *testing.T) {
	o, err := ipwhoIs{}.parse([]byte(ipwhoisBody))
	if err != nil {
		t.Fatal(err)
	}
	if o.hasAnycast {
		t.Error("a provider that does not report anycast must not claim to have reported it as false")
	}
}

func TestAdapterParsing(t *testing.T) {
	for _, tc := range []struct {
		name        string
		a           adapter
		raw         string
		wantCountry string
		wantCity    string
		wantOrg     string
		wantASN     string
	}{
		{"ipwho.is", ipwhoIs{}, ipwhoisBody, "US", "San Jose", "Google LLC", "15169"},
		{"ipinfo.io", ipinfo{}, ipinfoBody, "US", "Mountain View", "Google LLC", "15169"},
		{"freeipapi", freeipapi{}, freeipapiBody, "US", "Mountain View", "Google LLC", "15169"},
	} {
		o, err := tc.a.parse([]byte(tc.raw))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if o.country != tc.wantCountry {
			t.Errorf("%s country = %q, want %q", tc.name, o.country, tc.wantCountry)
		}
		if o.city != tc.wantCity {
			t.Errorf("%s city = %q, want %q", tc.name, o.city, tc.wantCity)
		}
		if o.org != tc.wantOrg {
			t.Errorf("%s org = %q, want %q", tc.name, o.org, tc.wantOrg)
		}
		if o.asn != tc.wantASN {
			t.Errorf("%s asn = %q, want %q", tc.name, o.asn, tc.wantASN)
		}
		if !o.hasPoint {
			t.Errorf("%s reported no coordinate", tc.name)
		}
	}
}

func TestTrimASNumber(t *testing.T) {
	// ipinfo packs the number and the name into one field, so the number has to come
	// out of several shapes without dragging the name along.
	for in, want := range map[string]string{
		"15169": "15169", "AS15169": "15169", "as15169": "15169",
		"AS15169 Google LLC": "15169", "15169, US": "15169", "  15169 ": "15169",
		"": "", "Google LLC": "", "AS": "",
	} {
		if got := trimASNumber(in); got != want {
			t.Errorf("trimASNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOrgFromPackedField(t *testing.T) {
	if got := orgFromOrg("AS15169 Google LLC"); got != "Google LLC" {
		t.Errorf("orgFromOrg = %q", got)
	}
	if got := orgFromOrg("Google LLC"); got != "Google LLC" {
		t.Errorf("orgFromOrg = %q", got)
	}
}

func TestSplitLocRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "38.0088", "38.0088,-122.1175,extra", "north,west", "999,999", "38.0088,-122.1175x"} {
		if _, _, ok := splitLoc(s); ok {
			t.Errorf("splitLoc(%q) accepted a malformed pair", s)
		}
	}
	lat, lon, ok := splitLoc("38.0088,-122.1175")
	if !ok || lat != 38.0088 || lon != -122.1175 {
		t.Errorf("splitLoc = %v,%v ok=%v", lat, lon, ok)
	}
	if lat, lon, ok := splitLoc("-33.87,151.21"); !ok || lat != -33.87 || lon != 151.21 {
		t.Errorf("negative coordinates rejected: %v,%v ok=%v", lat, lon, ok)
	}
}

func TestAgreeCredibility(t *testing.T) {
	cases := []struct {
		agreeing, total int
		want            byte
	}{
		{3, 3, '1'}, {1, 1, '1'},
		{2, 3, '2'}, {3, 4, '2'},
		{1, 3, '3'}, {2, 5, '3'},
		{0, 3, '3'}, {0, 0, '3'},
	}
	for _, c := range cases {
		if got := agreeCredibility(c.agreeing, c.total); got != c.want {
			t.Errorf("agreeCredibility(%d,%d) = %q, want %q",
				c.agreeing, c.total, string(got), string(c.want))
		}
	}
}

func TestHaversine(t *testing.T) {
	// San Jose to Mountain View is about 77 km straight line. The familiar "50 km"
	// figure for that pair is the road distance, and my first expectation used it,
	// which would have flagged a correct function as broken.
	d := haversineKm(37.3394, -121.8950, 38.0088, -122.1175)
	if d < 70 || d > 85 {
		t.Errorf("haversineKm = %v km, want roughly 77", d)
	}
	if d := haversineKm(10, 20, 10, 20); d != 0 {
		t.Errorf("haversineKm of identical points = %v, want 0", d)
	}
	// A degree of latitude is about 111 km, and a degree of longitude at the equator
	// is very nearly the same.
	if d := haversineKm(0, 0, 1, 0); d < 110 || d > 112 {
		t.Errorf("one degree of latitude = %v km, want about 111", d)
	}
	if d := haversineKm(0, 0, 0, 1); d < 110 || d > 112 {
		t.Errorf("one degree of longitude at the equator = %v km, want about 111", d)
	}
	// At 60 degrees north a degree of longitude is half as long, which is the whole
	// reason longitude distance is cosine-weighted.
	if d := haversineKm(60, 0, 60, 1); d < 54 || d > 57 {
		t.Errorf("one degree of longitude at 60N = %v km, want about 55.7", d)
	}
	// Antipodes are half the circumference.
	if d := haversineKm(0, 0, 0, 180); d < 20000 || d > 20020 {
		t.Errorf("antipodal distance = %v km, want about 20015", d)
	}
}

func TestEvidenceIsRetainedPerProvider(t *testing.T) {
	// Every provider's answer is kept, because the disagreement is only auditable if
	// each side of it can be read back.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))
	if got := h.Blobs.Count(); got < 3 {
		t.Errorf("retained %d artifacts, want one per provider", got)
	}
}

func TestNoHTTPClientFailsInit(t *testing.T) {
	if err := New().Init(context.Background(), sdk.Deps{}); err == nil {
		t.Error("Init without an HTTP client must fail rather than run and produce nothing")
	}
}

func TestNonAddressTargetIsSkipped(t *testing.T) {
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if len(h.HTTP.Calls()) != 0 {
		t.Errorf("a domain target caused lookups: %v", h.HTTP.Calls())
	}
}

func TestCIDRTargetUsesItsAddress(t *testing.T) {
	m := New()
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("ipwho.is", http.StatusOK, ipwhoisBody, "application/json")
	h.HTTP.Respond("ipinfo.io", http.StatusOK, ipinfoBody, "application/json")
	h.HTTP.Respond("free.freeipapi.com", http.StatusOK, freeipapiBody, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeCIDR, "8.8.8.0/24"))

	if len(h.HTTP.Calls()) == 0 {
		t.Fatal("no lookups for a prefix target")
	}
	for _, c := range h.HTTP.Calls() {
		if strings.Contains(c.URL, "/24") {
			t.Errorf("the prefix itself was queried: %s", c.URL)
		}
		if !strings.Contains(c.URL, "8.8.8.0") {
			t.Errorf("expected the address from the prefix, got %s", c.URL)
		}
	}
}

func containsStr(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf

func TestFreeipapiUsesItsCanonicalHost(t *testing.T) {
	// api.freeipapi.com redirects to free.freeipapi.com. Following that redirect
	// means reaching a host the manifest does not declare, so the canonical endpoint
	// is requested directly instead.
	a := freeipapi{}
	if got := a.host(); got != "free.freeipapi.com" {
		t.Errorf("host = %q", got)
	}
	url := a.buildURL("8.8.8.8")
	if !strings.HasPrefix(url, "https://free.freeipapi.com/") {
		t.Errorf("URL = %q, want the canonical host", url)
	}
}

func TestObservationReportsItsRealAgreement(t *testing.T) {
	// An observation that claims more support than it has is worse than no
	// observation: it looks checkable and is not.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	for _, f := range h.Out.Findings {
		switch f.Observation.Predicate {
		case "country", "region", "origin_asn", "operated_by":
			// All three providers agree on these.
			if n, _ := f.Observation.Attrs["providers_agreeing"].(int); n != 3 {
				t.Errorf("%s claims %v providers agreed; all three did",
					f.Observation.Predicate, f.Observation.Attrs["providers_agreeing"])
			}
			if n, _ := f.Observation.Attrs["providers_total"].(int); n != 3 {
				t.Errorf("%s total = %v, want 3", f.Observation.Predicate, f.Observation.Attrs["providers_total"])
			}
		case "city":
			// Two of three: ipwho.is says San Jose, the others Mountain View.
			if n, _ := f.Observation.Attrs["providers_agreeing"].(int); n != 2 {
				t.Errorf("city claims %v providers agreed; two of three did",
					f.Observation.Attrs["providers_agreeing"])
			}
			if f.Observation.Object != "Mountain View" {
				t.Errorf("city = %v, want the majority value", f.Observation.Object)
			}
		}
	}
}
