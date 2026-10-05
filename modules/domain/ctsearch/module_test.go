package ctsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// stubAdapter returns a fixed set of entries or an error, so the module's own logic
// can be tested without a network or a provider.
type stubAdapter struct {
	id      string
	hosts_  []string
	entries []entry
	err     error
	url     string
	calls   int
}

func (s *stubAdapter) name() string      { return s.id }
func (s *stubAdapter) hosts() []string   { return s.hosts_ }
func (s *stubAdapter) requiresKey() bool { return false }
func (s *stubAdapter) buildURL(string) string {
	if s.url != "" {
		return s.url
	}
	return "https://" + s.id + ".example/index"
}

func (s *stubAdapter) fetch(_ context.Context, d sdk.Deps, e sdk.Emitter, _, method, url string) ([]entry, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	// Exercise the same retention path the real adapters use.
	if d.Blobs != nil && e != nil {
		_, _ = e.PutEvidence(context.Background(), sdk.EvidenceMeta{
			Source: url, Method: method, MediaType: "application/json",
		}, []byte(`[{"stub":true}]`))
	}
	return s.entries, nil
}

const crtShFixture = `[
  {"issuer_ca_id": 1234, "issuer_name": "C3, Inc. Authoritative CA1", "issuer_org": "Let's Encrypt",
   "common_name": "example.com", "name_value": "example.com\n*.example.com\nwww.example.com",
   "id": 456789012, "cert_id": 987654321, "serial_number": "04:A1:BC:DE",
   "entry_timestamp": "2026-09-01T10:00:00", "not_before": "2026-08-01T00:00:00",
   "not_after": "2026-11-01T00:00:00", "result_count": 3},
  {"issuer_ca_id": 1234, "issuer_name": "C3, Inc. Authoritative CA1", "issuer_org": "Let's Encrypt",
   "common_name": "api.example.com", "name_value": "api.example.com",
   "id": 456789013, "cert_id": 987654322, "serial_number": "04:A1:BC:DF",
   "entry_timestamp": "2026-09-02T10:00:00", "not_before": "2026-08-02T00:00:00",
   "not_after": "2026-11-02T00:00:00", "result_count": 1}
]`

// Byte-faithful to what api.certspotter.com actually serves: dns_names is a JSON
// array, the issuer exposes friendly_name alongside a full DN, and revoked is
// present. An earlier fixture used a newline-separated string and fields the API does
// not publish, which hid a parse failure that would have made the module report zero
// names on every real lookup.
const certspotterFixture = `[
  {"id": "12809115180",
   "cert_sha256": "4973b48cf244e4981d43ff0485c347d50a22f0b827f9d0c96f9233a9e7646bf5",
   "tbs_sha256": "a7781bc044f9e19ba8009c0299b404f3816642d5185ed73bae6c05e8f7fa9d35",
   "dns_names": ["example.com", "www.example.com", "api.example.com", "mail.example.com", "unrelated.org"],
   "issuer": {
     "friendly_name": "Example CA",
     "name": "C=GB, O=Example CA Ltd, CN=Example CA R3",
     "pubkey_sha256": "2aa918617e4b60060fed719e9aacdbb4f3c803cc7b052fc16ce21c0177f78f69"
   },
   "not_before": "2025-11-20T00:00:00Z",
   "not_after": "2026-11-20T23:59:59Z",
   "revoked": true},
  {"id": "12809115181",
   "cert_sha256": "0a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccddeef",
   "dns_names": ["live.example.com"],
   "issuer": {"friendly_name": "Example CA", "name": "C=GB, O=Example CA Ltd, CN=Example CA R3"},
   "not_before": "2026-01-01T00:00:00Z",
   "not_after": "2026-04-01T00:00:00Z",
   "revoked": false}
]`

func newModuleHarness(t *testing.T) *sdktest.Harness {
	t.Helper()
	m := New(WithAdapters(newCrtSh(), newCertspotter("")))
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("crt.sh", http.StatusOK, crtShFixture, "application/json")
	h.HTTP.Respond("api.certspotter.com", http.StatusOK, certspotterFixture, "application/json")
	return h
}

func TestManifestIsPassive(t *testing.T) {
	man := New().Manifest()
	// A transparency log is read through a third-party index; the target is never
	// contacted. Declaring semi-active would imply otherwise.
	if man.Mode != sdk.ModePassive {
		t.Errorf("mode = %v, want passive", man.Mode)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
	// Hosts must match the configured adapters, not a hardcoded list that could
	// drift from them.
	if !containsStr(man.EgressHosts, "crt.sh") || !containsStr(man.EgressHosts, "api.certspotter.com") {
		t.Errorf("EgressHosts = %v, want the adapter hosts", man.EgressHosts)
	}
}

func TestFindsSubdomains(t *testing.T) {
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.AssertEntities(sdk.TypeSubdomain, "www.example.com", "api.example.com", "mail.example.com")
	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()
}

func TestWildcardIsNotASubdomain(t *testing.T) {
	// The classic CT false positive. A wildcard certificate proves the holder could
	// cover names below it; it proves nothing about any specific host existing.
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.RefuteEntities(sdk.TypeSubdomain, "*.example.com")
	for _, f := range h.Out.Findings {
		if strings.Contains(f.Entity.Value, "*") {
			t.Errorf("a wildcard name was emitted as an entity: %q", f.Entity.Value)
		}
	}
}

func TestNamesOutsideTheDomainAreDropped(t *testing.T) {
	// A certificate log is global. It contains a stranger's certificate for
	// example.com, and that stranger's other hosts too. Emitting those would turn
	// every scan into a scan of the whole log.
	const mixed = `[
	  {"issuer_name": "Some CA", "common_name": "example.com",
	   "name_value": "example.com\nevil.com\nattacker.other-domain.test\ncdn.example.com",
	   "id": 1, "serial_number": "AA", "entry_timestamp": "2026-01-01T00:00:00"}
	]`
	m := New(WithAdapters(&stubAdapter{
		id: "mixed", hosts_: []string{"mixed.example"}, url: "https://mixed.example/i",
		entries: func() []entry {
			var raw []entry
			names := splitNames("example.com\nevil.com\nattacker.other-domain.test\ncdn.example.com")
			raw = append(raw, entry{names: names, provider: "mixed"})
			return raw
		}(),
	}))
	h := sdktest.NewHarness(t, m)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.AssertEntities(sdk.TypeSubdomain, "cdn.example.com")
	h.RefuteEntities(sdk.TypeSubdomain, "evil.com")
	h.RefuteEntities(sdk.TypeSubdomain, "attacker.other-domain.test")
}

func TestLookalikeSuffixIsNotInDomain(t *testing.T) {
	// A label-boundary mistake here would attribute a stranger's hosts to the target.
	for _, raw := range []string{
		"evil-example.com",
		"notexample.com",
		"example.com.evil.com",
		"xexample.com",
	} {
		_, _, ok := normalizeName(raw, "example.com")
		if ok {
			t.Errorf("normalizeName(%q) accepted a name outside the domain", raw)
		}
	}
}

func TestPartialWildcardIsRejected(t *testing.T) {
	// "dev-*.example.com" proves nothing about dev-foo.example.com.
	if _, kind, ok := normalizeName("dev-*.example.com", "example.com"); ok || kind != nameWildcard {
		t.Errorf("a partial wildcard was accepted: kind=%v ok=%v", kind, ok)
	}
}

func TestIDNAndUnicodeNamesCollapse(t *testing.T) {
	// A log may carry either spelling of the same name. They must become one entity
	// or the graph forks on a script boundary.
	a, _, ok := normalizeName("xn--mnchen-3ya.example.com", "example.com")
	if !ok {
		t.Fatal("punycode form rejected")
	}
	b, _, ok := normalizeName("münchen.example.com", "example.com")
	if !ok {
		t.Fatal("unicode form rejected")
	}
	if a != b {
		t.Errorf("the two spellings produced different entities: %q vs %q", a, b)
	}
}

func TestRegistrableDomainIsNotEmittedAsItsOwnSubdomain(t *testing.T) {
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	// example.com appears in every SAN list; re-emitting it as a subdomain of itself
	// would be a self-loop.
	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeSubdomain && f.Entity.Value == "example.com" {
			t.Error("the registrable domain was emitted as its own subdomain")
		}
	}
}

func TestTwoProvidersBecomeOneName(t *testing.T) {
	// api.example.com is in both fixtures. It must be emitted once, attributed to
	// both providers, so the scorer can treat them as independent corroboration
	// rather than as two separate hosts.
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	count := 0
	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeSubdomain && f.Entity.Value == "api.example.com" {
			count++
			if f.Observation.Predicate != "observed_in_ct_log" {
				continue
			}
			providers, _ := f.Observation.Attrs["ct_providers"].([]string)
			if len(providers) != 2 {
				t.Errorf("ct_providers = %v, want both sources attributed", providers)
			}
		}
	}
	if count != 1 {
		t.Errorf("api.example.com emitted %d times, want exactly 1", count)
	}
}

func TestCertificateEntityOnlyFromRealDigest(t *testing.T) {
	// crt.sh publishes a serial number, which is not a fingerprint. Presenting one as
	// a certificate hash would create an entity that looks verifiable and is not.
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	certs := 0
	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeCert {
			certs++
			if !strings.HasPrefix(f.Entity.Value, "sha256:") {
				t.Errorf("certificate entity value = %q, want a sha256-prefixed digest", f.Entity.Value)
			}
		}
	}
	// Two certificates in the Certspotter fixture, and none from crt.sh. A first
	// version of this fixture carried a 66-character digest that the SDK rejected,
	// so the count matched by accident while one certificate was being silently
	// dropped.
	if certs != 2 {
		t.Errorf("emitted %d certificate entities, want 2 (both Certspotter digests; crt.sh publishes none)", certs)
	}
	// The serial must not appear masquerading as a certificate.
	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeCert && strings.Contains(f.Entity.Value, "04A1BCDE") {
			t.Error("a certificate serial was emitted as a certificate digest")
		}
	}
}

func TestRevokedCertificateIsFlagged(t *testing.T) {
	// A revoked certificate stays in the transparency log forever. Reporting it as a
	// live credential would tell an analyst to trust something the CA withdrew.
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	var revoked, live int
	for _, f := range h.Out.Findings {
		if f.Entity.Type != sdk.TypeCert {
			continue
		}
		if flag, _ := f.Observation.Attrs["revoked"].(bool); flag {
			revoked++
			if f.Severity == "" || f.Severity == sdk.SevInfo {
				t.Errorf("a revoked certificate carries severity %q; it should not read as routine", f.Severity)
			}
		} else {
			live++
		}
	}
	if revoked != 1 || live != 1 {
		t.Errorf("revoked=%d live=%d, want one of each", revoked, live)
	}
}

func TestCertspotterExpandIsRepeatedNotCommaJoined(t *testing.T) {
	// Certspotter's expand parameter must be repeated. The comma form is silently
	// accepted and ignored, returning the default response with no dns_names at all:
	// a discovery module that asks this way reports zero names and no error, which
	// reads as a clean result while having looked at nothing.
	url := newCertspotter("").buildURL("example.com")
	if strings.Contains(url, "expand=dns_names,issuer") {
		t.Errorf("URL uses the comma form: %q", url)
	}
	if strings.Count(url, "expand=") != 2 {
		t.Errorf("URL = %q; each expand value must be its own parameter", url)
	}
	if !strings.Contains(url, "expand=dns_names") || !strings.Contains(url, "expand=issuer") {
		t.Errorf("URL = %q; both dns_names and issuer must be requested", url)
	}
}

func TestDNSNamesDecodeFromBothPublishedShapes(t *testing.T) {
	// Certspotter returns an array; crt.sh returns one newline-separated string.
	// Accepting both means a provider changing its encoding does not become a parse
	// failure that reads as "no names found".
	for _, doc := range []string{
		`{"dns_names": ["a.example.com", "b.example.com"]}`,
		`{"dns_names": "a.example.com\nb.example.com"}`,
		`{"dns_names": null}`,
		`{}`,
	} {
		var got certspotterIssuance
		if err := json.Unmarshal([]byte(doc), &got); err != nil {
			t.Errorf("%s: %v", doc, err)
			continue
		}
		names := splitNames(got.DNSNames.join())
		if doc[0] == '{' && strings.Contains(doc, "null") {
			if len(names) != 0 {
				t.Errorf("%s decoded to %v", doc, names)
			}
			continue
		}
		if len(names) == 0 && !strings.Contains(doc, "{}") {
			t.Errorf("%s decoded to no names", doc)
		}
	}
	if names := splitNames(nameList{"x.example.com", "y.example.com"}.join()); len(names) != 2 {
		t.Errorf("array form lost names: %v", names)
	}
}

func TestIssuerNameFallsBackToTheOrganizationComponent(t *testing.T) {
	// Without a friendly_name, the DN is the only source. Emitting the whole DN as an
	// organization would put "C=GB, O=Example CA Ltd, CN=Example CA R3" into the
	// graph as a company name.
	cases := map[string]string{
		"C=GB, O=Example CA Ltd, CN=Example CA R3": "Example CA Ltd",
		"CN=Example CA R3":                         "Example CA R3",
		"CN=A, O=Only Org":                         "Only Org",
		// A comma inside an escaped value must not split the component.
		`CN=A, O=Smith\, Jones and Co, C=GB`: "Smith, Jones and Co",
		"":                                   "",
	}
	for dn, want := range cases {
		if got := issuerLabel("", dn); got != want {
			t.Errorf("issuerLabel(%q) = %q, want %q", dn, got, want)
		}
	}
	// The friendly name wins when present.
	if got := issuerLabel("Nice Name", "C=GB, O=Ignored"); got != "Nice Name" {
		t.Errorf("issuerLabel = %q, want the friendly name", got)
	}
}

func TestIssuerIsHeuristic(t *testing.T) {
	// A log records that some certificate was issued; it does not record who the
	// operator or registrant is. Attributing the domain to the CA as owner would be
	// an inference presented as fact.
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	var sawIssuer bool
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != sdk.RelOwnedBy {
				continue
			}
			sawIssuer = true
			if !r.Heuristic {
				t.Error("the issuer relation is not flagged heuristic")
			}
		}
	}
	if !sawIssuer {
		t.Error("no issuer relation emitted")
	}
}

func TestSummaryObservationIsEmitted(t *testing.T) {
	// Silence is indistinguishable from "nothing exists". A summary lets a report
	// state coverage even when nothing new was found.
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	var summary map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "ct_search_summary" {
			summary = f.Observation.Attrs
		}
	}
	if summary == nil {
		t.Fatal("no summary observation emitted")
	}
	if summary["truncated"] != false {
		t.Errorf("truncated = %v", summary["truncated"])
	}
	if n, _ := summary["distinct_names"].(int); n == 0 {
		t.Error("summary reports zero distinct names despite findings")
	}
}

func TestProviderFailureIsIsolated(t *testing.T) {
	// These sources are volunteer-run and go down. One failing must not discard
	// what the other found.
	good := &stubAdapter{id: "good", hosts_: []string{"good.example"},
		entries: []entry{{names: []string{"a.example.com"}, provider: "good"}}}
	bad := &stubAdapter{id: "bad", hosts_: []string{"bad.example"}, err: fmt.Errorf("HTTP 502")}
	m := New(WithAdapters(bad, good))
	h := sdktest.NewHarness(t, m)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.AssertEntities(sdk.TypeSubdomain, "a.example.com")
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "CT source failed") {
			found = true
		}
	}
	if !found {
		t.Error("the provider failure was not reported; a silent partial result reads as complete")
	}
}

func TestAllProvidersFailingIsAnError(t *testing.T) {
	a := &stubAdapter{id: "a", hosts_: []string{"a.example"}, err: fmt.Errorf("down")}
	b := &stubAdapter{id: "b", hosts_: []string{"b.example"}, err: fmt.Errorf("down")}
	h := sdktest.NewHarness(t, New(WithAdapters(a, b)))

	if err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "example.com")); err == nil {
		t.Error("when every source fails the task must fail, not report zero names")
	}
}

func TestNameSetIsBounded(t *testing.T) {
	// A large organization has tens of thousands of logged names. Materializing all
	// of them stalls the pipeline and drowns the useful signal.
	var many []string
	for i := 0; i < 500; i++ {
		many = append(many, fmt.Sprintf("host%d.example.com", i))
	}
	ad := &stubAdapter{id: "big", hosts_: []string{"big.example"},
		entries: []entry{{names: many, provider: "big"}}}
	h := sdktest.NewHarness(t, New(WithAdapters(ad), WithMaxNames(25)))

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	if got := h.CountEntities(sdk.TypeSubdomain); got > 25 {
		t.Errorf("emitted %d names, want at most 25", got)
	}
	// Truncation must be visible.
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "truncated") {
			found = true
		}
	}
	if !found {
		t.Error("truncation was silent; a capped result must not read as complete")
	}
}

func TestSubdomainOfEdgePointsAtTheQueriedDomain(t *testing.T) {
	h := newModuleHarness(t)
	target := sdk.NewEntity(sdk.TypeDomain, "example.com")
	h.Run(target)

	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != sdk.RelSubdomainOf {
				continue
			}
			if r.From != f.Entity.ID || r.To != target.ID {
				t.Errorf("subdomain_of should run discovered host -> queried domain, got %s -> %s", r.From, r.To)
			}
		}
	}
}

func TestEvidenceIsRetained(t *testing.T) {
	h := newModuleHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if h.Blobs.Count() == 0 {
		t.Fatal("no evidence retained; the raw index is the artifact behind every name reported")
	}
}

func TestSearchesTheRegistrableDomainNotTheSubdomain(t *testing.T) {
	// Certificates are issued against the registrable domain. Searching a
	// subdomain's own name finds nothing, and the Public Suffix List is required to
	// get the right one: a last-label split would query "co.uk".
	cases := map[string]string{
		"example.com":          "example.com",
		"www.example.com":      "example.com",
		"a.b.c.example.com":    "example.com",
		"shop.example.co.uk":   "example.co.uk",
		"deep.sub.example.org": "example.org",
	}
	for in, want := range cases {
		if got := registrableOf(in); got != want {
			t.Errorf("registrableOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNamesUnderTheRegistrableDomainAreKept(t *testing.T) {
	// The scope for matching is the registrable domain, not the name that arrived in
	// the task. A scan seeded with a subdomain must still surface the siblings and
	// the apex that CT recorded.
	ad := &stubAdapter{id: "one", hosts_: []string{"one.example"},
		entries: []entry{{names: []string{
			"api.example.co.uk", "www.example.co.uk", "other.co.uk",
		}, provider: "one"}}}
	h := sdktest.NewHarness(t, New(WithAdapters(ad)))

	h.Run(sdk.NewEntity(sdk.TypeSubdomain, "shop.example.co.uk"))

	h.AssertEntities(sdk.TypeSubdomain, "api.example.co.uk", "www.example.co.uk")
	h.RefuteEntities(sdk.TypeSubdomain, "other.co.uk")
}

func TestNoHTTPClientFailsInit(t *testing.T) {
	m := New()
	if err := m.Init(context.Background(), sdk.Deps{}); err == nil {
		t.Error("Init without an HTTP client must fail rather than run and produce nothing")
	}
}

func TestCrtShQueryUsesWildcardSyntax(t *testing.T) {
	// crt.sh needs the leading %. to match certificates for subdomains. Without it
	// the query matches only the exact name, which is the most common reason a CT
	// collector silently returns almost nothing.
	url := newCrtSh().buildURL("example.com")
	if !strings.Contains(url, "q=%25.example.com") {
		t.Errorf("crt.sh URL = %q; the wildcard form must be percent-encoded", url)
	}
	if !strings.Contains(url, "output=json") {
		t.Errorf("crt.sh URL = %q; JSON output was not requested", url)
	}
}

func TestCrtShAdapterParsesFixture(t *testing.T) {
	h := sdktest.NewHarness(t, New(WithAdapters(newCrtSh())))
	h.HTTP.Respond("crt.sh", http.StatusOK, crtShFixture, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.AssertEntities(sdk.TypeSubdomain, "www.example.com", "api.example.com")
	h.RefuteEntities(sdk.TypeSubdomain, "*.example.com")
}

func TestCertspotterAdapterParsesFixture(t *testing.T) {
	h := sdktest.NewHarness(t, New(WithAdapters(newCertspotter(""))))
	h.HTTP.Respond("api.certspotter.com", http.StatusOK, certspotterFixture, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.AssertEntities(sdk.TypeSubdomain, "mail.example.com", "api.example.com", "live.example.com")
	if got := h.CountEntities(sdk.TypeCert); got != 2 {
		t.Errorf("certificate entities = %d, want 2", got)
	}
}

func TestSerialIsNormalized(t *testing.T) {
	// Serial formats vary between registries; the same certificate must not appear
	// twice because one wrote "04:A1" and another wrote "04a1".
	for in, want := range map[string]string{
		"04:A1:BC:DE": "04A1BCDE",
		"04a1bcde":    "04A1BCDE",
		" 04:A1 ":     "04A1",
		"":            "",
	} {
		if got := normalizeSerial(in); got != want {
			t.Errorf("normalizeSerial(%q) = %q, want %q", in, got, want)
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
