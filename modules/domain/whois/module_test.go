package whois

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// A thin .com registry answer. This is the shape RFC 3912 documents for a registry
// that keeps no registration data of its own and points at the registrar.
const thinCom = `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.iana.test:43
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Updated Date: 2026-08-14T07:01:43Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2027-08-13T04:00:00Z
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Domain Status: clientDeleteProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
`

// A registrar's own answer, with the registrant withheld and an expiry inside a month.
const registrarThick = `Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example-registrar.test
Registrar URL: http://www.example-registrar.test
Updated Date: 2026-09-01T12:00:00+01:00
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-10-01T04:00:00Z
Registrar Registration Expiration Date: 2026-10-01T04:00:00Z
Registrar: Example Registrar Inc.
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: REDACTED FOR PRIVACY
Registrant Street: REDACTED FOR PRIVACY
Registrant Country: US
Registrant Email: REDACTED FOR PRIVACY
Registrar Abuse Contact Email: abuse@example-registrar.test
Registrar Abuse Contact Phone: +1.5555550100
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE-REGISTRAR.TEST
Name Server: NS2.EXAMPLE-REGISTRAR.TEST
DNSSEC: unsigned
`

// A volume refusal, which is prose rather than a record.
const rateLimited = `WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS
`

// An authoritative negative.
const noRecord = `No match for "NOTHING-HERE.TEST".
`

func newHarness(t *testing.T, opts ...Option) (*sdktest.Harness, *Module) {
	t.Helper()
	m := New(append([]Option{
		WithRegistryHosts(map[string]string{
			"com":  "whois.verisign-grs.test:43",
			"test": "whois.iana.test:43",
		}),
		WithIANAHost("whois.iana.test:43"),
	}, opts...)...)
	h := sdktest.NewHarness(t, m)
	return h, m
}

func TestManifestIsPassive(t *testing.T) {
	man := New().Manifest()
	// WHOIS reads a public registry and never contacts the domain being looked up.
	// Declaring it semi-active would wrongly imply it probes the target.
	if man.Mode != sdk.ModePassive {
		t.Errorf("mode = %v, want passive", man.Mode)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
}

func TestManifestDeclaresEveryServerItMayReach(t *testing.T) {
	man := New().Manifest()
	// The manifest is the only thing standing between a collector and the whole
	// internet, so a server it will dial but did not declare is a live hole.
	for _, addr := range New().registryHosts {
		host := hostOfAddress(addr)
		if !man.AllowsHost(host) {
			t.Errorf("server %s is not in EgressHosts %v", host, man.EgressHosts)
		}
	}
	if !man.AllowsHost("whois.iana.org") {
		t.Error("the referral server is not declared")
	}
}

func TestRateLimitIsConservative(t *testing.T) {
	// This rate is about being a good citizen, not staying under a quota. WHOIS
	// servers block outright, and a blocked operator loses the registry for the day.
	r, ok := New().Manifest().RateHints["*"]
	if !ok {
		t.Fatal("no rate hint; the broker applies the manifest hint for each host")
	}
	if r.Requests != 1 || r.Per < 2*time.Second || r.Burst != 1 {
		t.Errorf("rate hint = %v, want one request every few seconds with no burst", r)
	}
}

func TestReadsRegistryRecord(t *testing.T) {
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", thinCom)

	target := sdk.NewEntity(sdk.TypeDomain, "example.com")
	h.Run(target)

	h.AssertEntities(sdk.TypeSubdomain, "a.iana-servers.net", "b.iana-servers.net")
	h.AssertEntities(sdk.TypeOrg, "RESERVED-Internet Assigned Numbers Authority")
	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()

	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "whois_record" {
			continue
		}
		// A registry record is authoritative about its own data.
		if f.Observation.Reliability != registryReliability {
			t.Errorf("registry record graded %q, want %q",
				string(f.Observation.Reliability), string(registryReliability))
		}
		if attrs := f.Observation.Attrs; attrs["created_at"] == nil || attrs["expires_at"] == nil {
			t.Errorf("dates missing from the record: %v", attrs)
		}
	}
}

func TestThinRecordFollowsTheReferral(t *testing.T) {
	// A thin registry answer is only a pointer. Following it is what makes this a
	// registration source rather than a directory of referral addresses.
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", thinCom)
	h.Dial.Reply("whois.iana.test:43", registrarThick)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	h.AssertEntities(sdk.TypeOrg, "Example Registrar Inc.")
	h.AssertEntities(sdk.TypeSubdomain, "ns1.example-registrar.test")
	h.AssertEntities(sdk.TypeEmail, "abuse@example-registrar.test")

	saw := false
	for _, c := range h.Dial.Calls() {
		if strings.HasPrefix(c, "whois.iana.test:43") {
			saw = true
		}
	}
	if !saw {
		t.Errorf("the referral was not followed; calls: %v", h.Dial.Calls())
	}
}

func TestRegistrarRecordIsGradedBelowTheRegistry(t *testing.T) {
	// A registrar is not bound by what a registry must publish, so its answer is
	// graded lower than the registry's.
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", thinCom)
	h.Dial.Reply("whois.iana.test:43", registrarThick)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	var registrarGrade string
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "whois_record" {
			continue
		}
		if f.Observation.Attrs["resolved_via"] == "registrar referral" {
			registrarGrade = string(f.Observation.Reliability) + string(f.Observation.Credibility)
		}
	}
	if registrarGrade == "" {
		t.Fatal("no observation attributed to the registrar referral")
	}
	if registrarGrade != string(registrarReliability)+string(registrarCredibility) {
		t.Errorf("registrar record graded %q", registrarGrade)
	}
}

func TestRedactedFieldsAreReportedNotGuessed(t *testing.T) {
	// The registry has said the data exists and is withheld. Recording it as absent
	// would misrepresent the registry, and guessing would fabricate personal data.
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", thinCom)
	h.Dial.Reply("whois.iana.test:43", registrarThick)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "whois_record" {
			continue
		}
		if f.Observation.Attrs["redacted_fields"] != nil {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no observation records the withheld fields")
	}
	fields, _ := attrs["redacted_fields"].([]string)
	if len(fields) == 0 {
		t.Error("redacted_fields is empty")
	}
	if note, _ := attrs["note"].(string); !strings.Contains(note, "not of absence") {
		t.Errorf("note = %q", note)
	}
	// No placeholder may become an entity.
	h.RefuteEntities(sdk.TypeOrg, "REDACTED FOR PRIVACY")
	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeEmail && strings.Contains(strings.ToLower(f.Entity.Value), "redacted") {
			t.Errorf("a redaction placeholder became an email entity: %q", f.Entity.Value)
		}
	}
}

func TestRateLimitIsNotAnEmptyResult(t *testing.T) {
	// Registries enforce volume by returning prose. Parsing that as a record yields a
	// domain with no nameservers and no dates, which looks exactly like a sparsely
	// populated entry and tells an analyst a name is unregistered when the truth is
	// that this operator was throttled.
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", rateLimited)

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if err == nil {
		t.Fatal("a volume refusal must surface as an error")
	}
	if !strings.Contains(err.Error(), "volume") && !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("error should name the refusal: %v", err)
	}
}

func TestNoRecordIsAFindingNotAnError(t *testing.T) {
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", noRecord)

	// Run returns the recorded findings; an authoritative negative must not be an error.
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "no_whois_record" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no finding emitted for an authoritative negative")
	}
	if note, _ := attrs["note"].(string); !strings.Contains(note, "ever registered") {
		t.Errorf("note = %q; it must distinguish this from a name that was deleted", note)
	}
}

func TestUnknownTLDUsesTheReferralServer(t *testing.T) {
	// RFC 3912 designates the IANA server for exactly the case of a TLD with no
	// configured entry, so an unlisted TLD is answerable rather than a dead end.
	h, _ := newHarness(t)
	h.Dial.Reply("whois.iana.test:43", thinCom)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.pirate"))

	if len(h.Dial.Calls()) == 0 {
		t.Fatal("no query was made for a TLD with no registry entry")
	}
	if !strings.HasPrefix(h.Dial.Calls()[0], "whois.iana.test:43") {
		t.Errorf("first query = %q, want the referral server", h.Dial.Calls()[0])
	}
}

func TestQueryBudgetBoundsLookups(t *testing.T) {
	// WHOIS servers block the caller, so a scan must not be the reason an operator
	// loses access to a registry for the rest of the day.
	m := New(WithRegistryHosts(map[string]string{"com": "whois.verisign-grs.test:43"}),
		WithIANAHost("whois.iana.test:43"))
	m.maxQueries = 1
	h := sdktest.NewHarness(t, m)
	h.Dial.Reply("whois.verisign-grs.test:43", thinCom)
	h.Dial.Reply("whois.iana.test:43", registrarThick)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	if got := len(h.Dial.Calls()); got > 1 {
		t.Errorf("made %d queries, want at most the budget of 1", got)
	}
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "budget") {
			found = true
		}
	}
	if !found {
		t.Errorf("the unreached referral was not reported; warnings: %v", h.Out.Warnings)
	}
}

func TestConnectionFailureIsNotSilentlyEmpty(t *testing.T) {
	h, _ := newHarness(t)
	h.Dial.ReplyErr("whois.verisign-grs.test:43", context.DeadlineExceeded)

	if err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "example.com")); err == nil {
		t.Fatal("an unreachable registry must surface")
	}
}

func TestNSForEdgePointsAtTheDomain(t *testing.T) {
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", thinCom)
	target := sdk.NewEntity(sdk.TypeDomain, "example.com")
	h.Run(target)

	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != sdk.RelNSFor {
				continue
			}
			if r.To != target.ID {
				t.Errorf("ns_for must point at the domain; got %s -> %s", r.From, r.To)
			}
		}
	}
}

func TestEvidenceIsRetained(t *testing.T) {
	h, _ := newHarness(t)
	h.Dial.Reply("whois.verisign-grs.test:43", thinCom)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))

	if h.Blobs.Count() == 0 {
		t.Fatal("no evidence retained; the raw record is the only artifact behind every field")
	}
	if !strings.Contains(string(h.Blobs.Bytes()), "EXAMPLE.COM") {
		t.Error("the retained artifact does not look like a WHOIS record")
	}
}

func TestNoDialerFailsInit(t *testing.T) {
	// A module needing port 43 without the brokered dialer would have to hold a raw
	// socket, which is the one thing the egress layer exists to prevent.
	if err := New().Init(context.Background(), sdk.Deps{}); err == nil {
		t.Error("Init without a dialer must fail rather than run and produce nothing")
	}
}

func TestNonDomainTargetIsSkipped(t *testing.T) {
	h, _ := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))
	if len(h.Dial.Calls()) != 0 {
		t.Errorf("an address target caused WHOIS lookups: %v", h.Dial.Calls())
	}
}
