package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// bootstrapFixture is a minimal IANA domain registry naming one service, which is
// all the module needs to resolve an endpoint for the keys under test.
// The real shape published by IANA, which is nested: [ [keys...], [urls...] ].
// An earlier flat fixture hid a parser bug, so this fixture stays byte-faithful to
// what data.iana.org actually serves.
const bootstrapFixture = `{
  "description": "RDAP bootstrap file for Domain Name System registrations",
  "publication": "2026-01-15T00:00:00Z",
  "version": "1.0",
  "services": [
    [ ["com"], ["https://rdap.example-registry.test/com/v1/"] ],
    [ ["net"], ["https://rdap.example-net.test/"] ],
    [ ["test"], ["https://rdap.example-tld.test/"] ]
  ]
}`

const asnBootstrapFixture = `{
  "publication": "2026-01-15T00:00:00Z",
  "version": "1.0",
  "services": [
    [ ["64500-64510", "64511-64520"], ["https://rdap.example-rir.test/rdap/"] ]
  ]
}`

const ipv4BootstrapFixture = `{
  "publication": "2026-01-15T00:00:00Z",
  "version": "1.0",
  "services": [
    [ ["203.0.113.0/24", "198.51.100.0/24"], ["https://rdap.example-rir.test/"] ]
  ]
}`

func newHarness(t *testing.T, m *Module) *sdktest.Harness {
	t.Helper()
	m.bootstrapURLs = map[string][]string{
		"domain": {"https://bootstrap.test/dns.json"},
		"ipv4":   {"https://bootstrap.test/ipv4.json"},
		"ipv6":   {"https://bootstrap.test/ipv6.json"},
		"asn":    {"https://bootstrap.test/asn.json"},
	}
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("dns.json", http.StatusOK, bootstrapFixture, "application/json")
	h.HTTP.Respond("ipv4.json", http.StatusOK, ipv4BootstrapFixture, "application/json")
	h.HTTP.Respond("asn.json", http.StatusOK, asnBootstrapFixture, "application/json")
	return h
}

const comResponse = `{
  "objectClassName": "domain",
  "handle": "2138514_DOMAIN_COM-VRSN",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited", "client transfer prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:31Z"}
  ],
  "nameservers": [
    {"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"},
    {"objectClassName": "nameserver", "ldhName": "B.IANA-SERVERS.NET"}
  ],
  "secureDNS": {"delegationSigned": true},
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "376",
      "roles": ["registrar"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Example Registrar Inc."],
        ["email", {}, "text", "registrar@example-registrar.test"]
      ]],
      "entities": [
        {
          "objectClassName": "entity",
          "roles": ["abuse"],
          "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Example Registrar Abuse"],
            ["email", {}, "text", "abuse@example-registrar.test"],
            ["tel", {"type": ["voice"]}, "uri", "tel:+1.5555550100"]
          ]]
        }
      ]
    }
  ]
}`

func TestManifestIsPassiveAndHonest(t *testing.T) {
	m := New()
	man := m.Manifest()
	// RDAP reads the authoritative registry and never touches the target, so it is
	// passive. Declaring it semi-active would wrongly imply it probes the target.
	if man.Mode != sdk.ModePassive {
		t.Errorf("mode = %v, want passive: RDAP reads a registry and never contacts the target", man.Mode)
	}
	if man.Sensitivity != sdk.SensLow {
		t.Errorf("sensitivity = %v", man.Sensitivity)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
}

func TestReadsRegistrationData(t *testing.T) {
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-registry.test", http.StatusOK, comResponse, "application/rdap+json")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	// Registrar, nameservers, and abuse contact.
	h.AssertEntities(sdk.TypeOrg, "Example Registrar Inc.")
	h.AssertEntities(sdk.TypeSubdomain, "a.iana-servers.net", "b.iana-servers.net")
	h.AssertEntities(sdk.TypeEmail, "abuse@example-registrar.test")
	h.AssertManifestIsValid()
	h.AssertNoConfidenceSet()
	h.AssertObservationsGraded()
}

func TestAttachesRegistrationFacts(t *testing.T) {
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-registry.test", http.StatusOK, comResponse, "application/rdap+json")

	target := sdk.NewEntity(sdk.TypeDomain, "example.com")
	h.Run(target)

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "registered" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no registration observation was emitted")
	}
	for _, want := range []string{"handle", "status", "registered_at", "expires_at", "dnssec"} {
		if _, ok := attrs[want]; !ok {
			t.Errorf("registration observation is missing %q; got keys %v", want, keysOf(attrs))
		}
	}
	if attrs["dnssec"] != "signed" {
		t.Errorf("dnssec = %v, want signed", attrs["dnssec"])
	}
	if got, _ := attrs["registered_at"].(string); !strings.HasPrefix(got, "1995-08-14") {
		t.Errorf("registered_at = %v", got)
	}
}

func TestNameserverEdgesPointAtTheDomain(t *testing.T) {
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-registry.test", http.StatusOK, comResponse, "application/rdap+json")

	target := sdk.NewEntity(sdk.TypeDomain, "example.com")
	h.Run(target)

	// ns_for must run nameserver -> domain, matching dns-records. An inverted edge
	// would make the graph claim the domain is authoritative for the nameserver.
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != sdk.RelNSFor {
				continue
			}
			if r.From == target.ID {
				t.Errorf("ns_for runs from the domain; it must run nameserver -> domain")
			}
		}
	}
}

func TestRedactedFieldsAreReportedNotGuessed(t *testing.T) {
	// A registrar that withholds the registrant has stated the data exists and is
	// withheld under a privacy regime. The module must record that statement. It
	// must not report an absent registrant, and must never invent a value.
	const redacted = `{
	  "objectClassName": "domain",
	  "handle": "REDACTED",
	  "ldhName": "PRIVATE.NET",
	  "status": ["client delete prohibited"],
	  "events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}],
	  "redacted": [
	    {"name": {"type": "registrant"}, "prePath": "$.entities[0]", "postPath": "",
	     "method": "removal", "reason": {"type": "privacy"}},
	    {"name": {"type": "registrar"}, "method": "removal", "reason": {"type": "privacy"}}
	  ],
	  "entities": [
	    {"roles": ["registrar"],
	     "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]}
	  ]
	}`

	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-net.test", http.StatusOK, redacted, "application/rdap+json")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "private.net"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "registered" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no registration observation")
	}
	fields, _ := attrs["redacted_fields"].([]string)
	if len(fields) != 2 {
		t.Fatalf("redacted_fields = %v, want registrant and registrar", fields)
	}
	methods, _ := attrs["redaction_methods"].([]string)
	if len(methods) != 1 || methods[0] != "removal" {
		t.Errorf("redaction_methods = %v, want [removal]", methods)
	}

	// A redacted org name must not become an entity: it is not an organization.
	h.RefuteEntities(sdk.TypeOrg, "REDACTED FOR PRIVACY")
	h.AssertEntities(sdk.TypeSubdomain) // nothing required, just ensure no panic
}

func TestNotRegisteredIsAFindingNotAnError(t *testing.T) {
	// A 404 from a registry is an authoritative statement that the object does not
	// exist. It must be recorded as a finding and must not abort or be silently
	// swallowed as a transport error.
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-registry.test", http.StatusNotFound, `{"errorCode":404}`, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "doesnotexist.com"))

	if len(h.Out.Findings) == 0 {
		t.Fatal("an authoritative negative produced no finding")
	}
	var kind string
	for _, f := range h.Out.Findings {
		kind = f.Kind
		if f.Observation.Reliability != 'A' {
			t.Errorf("reliability = %q; a registry is authoritative about its own data", string(f.Observation.Reliability))
		}
	}
	if kind != "rdap-not-registered" {
		t.Errorf("kind = %q, want rdap-not-registered", kind)
	}
}

func TestNoBootstrapServiceIsNotAnError(t *testing.T) {
	// Not every TLD has an RDAP service. That is an ordinary fact about the
	// registry ecosystem, not a failure worth reporting as one.
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.pirate"))

	if len(h.Out.Findings) != 0 {
		t.Errorf("expected no findings for an unserved key, got %d", len(h.Out.Findings))
	}
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "no RDAP service") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning naming the missing service; got %v", h.Out.Warnings)
	}
}

func TestEndpointFailureFallsBackToTheNext(t *testing.T) {
	// Registries publish redundant servers and any may be down. One failing
	// endpoint must not end the lookup.
	resetCaches()
	m := New()
	m.bootstrapURLs = map[string][]string{
		"domain": {"https://bootstrap.test/dns.json"},
		"ipv4":   {"https://bootstrap.test/ipv4.json"},
		"ipv6":   {"https://bootstrap.test/ipv6.json"},
		"asn":    {"https://bootstrap.test/asn.json"},
	}
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("dns.json", http.StatusOK, `{
	  "services": [ [ ["com"], ["https://a.example.test", "https://b.example.test"] ] ]
	}`, "application/json")
	h.HTTP.Respond("a.example.test", http.StatusInternalServerError, `{"error":1}`, "application/json")
	h.HTTP.Respond("b.example.test", http.StatusOK, comResponse, "application/rdap+json")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.AssertEntities(sdk.TypeOrg, "Example Registrar Inc.")
}

func TestAllEndpointsFailingIsReported(t *testing.T) {
	resetCaches()
	m := New()
	m.bootstrapURLs = map[string][]string{
		"domain": {"https://bootstrap.test/dns.json"},
		"ipv4":   {"https://bootstrap.test/ipv4.json"},
		"ipv6":   {"https://bootstrap.test/ipv6.json"},
		"asn":    {"https://bootstrap.test/asn.json"},
	}
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("dns.json", http.StatusOK,
		`{"services": [ [ ["com"], ["https://a.example.test"] ] ]}`, "application/json")
	h.HTTP.Respond("a.example.test", http.StatusInternalServerError, `{"error":1}`, "application/json")

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if err == nil {
		t.Fatal("a lookup where every endpoint failed must surface an error, not return empty")
	}
	if !strings.Contains(err.Error(), "every endpoint failed") {
		t.Errorf("error should name the failure mode: %v", err)
	}
}

func TestTruncatedResponseIsRefused(t *testing.T) {
	// A partial registry object would parse into missing fields and produce
	// confident-looking but wrong conclusions. Refusing is the only safe answer.
	resetCaches()
	m := New()
	m.maxBodyBytes = 64
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-registry.test", http.StatusOK, comResponse, "application/rdap+json")

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if err == nil {
		t.Fatal("a truncated response must be refused")
	}
	if !strings.Contains(err.Error(), "refusing to parse a partial object") {
		t.Errorf("error should explain the refusal: %v", err)
	}
}

func TestBootstrapIsFetchedOnce(t *testing.T) {
	// The registries are large and change rarely; refetching per lookup would be
	// both slow and rude to IANA.
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-registry.test", http.StatusOK, comResponse, "application/rdap+json")

	target := sdk.NewEntity(sdk.TypeDomain, "example.com")
	h.Run(target, target, target)

	bootstrapCalls := 0
	for _, c := range h.HTTP.Calls() {
		if strings.Contains(c.URL, "bootstrap.test") {
			bootstrapCalls++
		}
	}
	if bootstrapCalls != 1 {
		t.Errorf("bootstrap fetched %d times for 3 lookups, want 1", bootstrapCalls)
	}
}

func TestEvidenceIsRetained(t *testing.T) {
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-registry.test", http.StatusOK, comResponse, "application/rdap+json")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	if h.Blobs.Count() == 0 {
		t.Fatal("no evidence retained; a registration record is the primary artifact for every conclusion drawn from it")
	}
	body := string(h.Blobs.Bytes())
	if !strings.Contains(body, "EXAMPLE.COM") {
		t.Errorf("retained artifact does not look like the registry response: %.120s", body)
	}
}

func TestIPAndASNTargets(t *testing.T) {
	resetCaches()
	m := New()
	h := newHarness(t, m)
	h.HTTP.Respond("rdap.example-rir.test", http.StatusOK, `{
	  "objectClassName": "autnum",
	  "handle": "AS64500",
	  "startAutnum": 64500,
	  "endAutnum": 64501,
	  "name": "EXAMPLE-AS",
	  "country": "ZZ",
	  "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@as64500.test"]]]}]
	}`, "application/rdap+json")

	h.Run(sdk.NewEntity(sdk.TypeASN, "AS64500"))

	h.AssertEntities(sdk.TypeEmail, "abuse@as64500.test")

	// The autnum endpoint must be used for ASNs, not the domain or ip path.
	sawAutnum := false
	for _, c := range h.HTTP.Calls() {
		if strings.Contains(c.URL, "/autnum/64500") {
			sawAutnum = true
		}
	}
	if !sawAutnum {
		t.Errorf("expected an /autnum/ lookup; calls: %v", h.HTTP.Calls())
	}
}

func TestNonRegistrableTargetIsSkipped(t *testing.T) {
	resetCaches()
	m := New()
	h := newHarness(t, m)

	// An account handle has no registration data. Reporting that would be noise.
	h.Run(sdk.NewEntity(sdk.TypeAccount, "github:octocat"))
	if len(h.Out.Findings) != 0 {
		t.Errorf("expected no findings for a non-registrable target, got %d", len(h.Out.Findings))
	}
	if len(h.HTTP.Calls()) != 0 {
		t.Errorf("no request should be made for a non-registrable target; got %v", h.HTTP.Calls())
	}
}

func TestNoHTTPClientFailsInit(t *testing.T) {
	m := New()
	if err := m.Init(context.Background(), sdk.Deps{}); err == nil {
		t.Error("Init without an HTTP client must fail rather than run and produce nothing")
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestErrNotRegisteredIsDistinguishable(t *testing.T) {
	// The distinction matters: the caller must be able to tell "no such object"
	// from "the lookup failed", because only one of them is a finding.
	wrapped := fmt.Errorf("lookup example.com: %w", errNotRegistered)
	if !errors.Is(wrapped, errNotRegistered) {
		t.Error("errNotRegistered must survive wrapping; the caller distinguishes a negative answer by errors.Is")
	}
	if errors.Is(wrapped, context.DeadlineExceeded) {
		t.Error("errNotRegistered must not match unrelated sentinels")
	}
	if !strings.Contains(wrapped.Error(), "example.com") {
		t.Errorf("wrapping must keep the context: %v", wrapped)
	}
}
