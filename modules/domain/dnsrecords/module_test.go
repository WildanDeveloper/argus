package dnsrecords

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

func TestManifestIsHonest(t *testing.T) {
	m := New()
	man := m.Manifest()

	if man.Mode != sdk.ModeSemiActive {
		t.Errorf("mode = %v; resolving records contacts the target's authoritative infrastructure, so semi-active is the honest declaration", man.Mode)
	}
	if man.Sensitivity != sdk.SensLow {
		t.Errorf("sensitivity = %v; DNS records about a domain are not personal data", man.Sensitivity)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
	// The manifest must not claim to consume anything it cannot act on.
	for _, c := range man.Consumes {
		if c != sdk.TypeDomain && c != sdk.TypeSubdomain {
			t.Errorf("Consumes includes %q; this module only resolves names", c)
		}
	}
}

func TestResolvesARecords(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("acme.example", "A",
		sdk.DNSRecord{Name: "acme.example", Type: "A", TTL: 300, Data: "203.0.113.10"},
		sdk.DNSRecord{Name: "acme.example", Type: "A", TTL: 300, Data: "203.0.113.11"},
	)

	target := sdk.NewEntity(sdk.TypeDomain, "acme.example")
	h.Run(target)

	h.AssertEntities(sdk.TypeIP, "203.0.113.10", "203.0.113.11")
	if h.CountEntities(sdk.TypeIP) != 2 {
		t.Errorf("expected 2 IP entities, got %d", h.CountEntities(sdk.TypeIP))
	}

	// The edge must run domain -> ip, i.e. the target points at the addresses. An
	// inverted edge would make "who resolves to whom" unreadable.
	assertEdge(t, h, sdk.RelResolvesTo, target.ID, "203.0.113.10")
	assertEdge(t, h, sdk.RelResolvesTo, target.ID, "203.0.113.11")
}

// assertEdge checks that a relation of type typ runs from -> toValue.
func assertEdge(t *testing.T, h *sdktest.Harness, typ sdk.RelationType, from sdk.EntityID, toValue string) {
	t.Helper()
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != typ || r.From != from {
				continue
			}
			if f.Entity.ID == r.To && f.Entity.Value == toValue {
				return
			}
		}
	}
	t.Errorf("missing %s edge from %s to %s", typ, from, toValue)
}

func TestResolvesEveryDeclaredType(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("acme.example", "A", sdk.DNSRecord{Type: "A", TTL: 300, Data: "203.0.113.10"})
	h.DNS.Set("acme.example", "AAAA", sdk.DNSRecord{Type: "AAAA", TTL: 300, Data: "2001:db8::10"})
	h.DNS.Set("acme.example", "CNAME", sdk.DNSRecord{Type: "CNAME", TTL: 300, Data: "cdn.vendor.example."})
	h.DNS.Set("acme.example", "MX", sdk.DNSRecord{Type: "MX", TTL: 300, Data: "mail.acme.example.", Pref: 10})
	h.DNS.Set("acme.example", "NS", sdk.DNSRecord{Type: "NS", TTL: 3600, Data: "ns1.acme.example."})
	h.DNS.Set("acme.example", "TXT", sdk.DNSRecord{Type: "TXT", TTL: 300, Data: "v=spf1 -all"})
	h.DNS.Set("acme.example", "CAA", sdk.DNSRecord{Type: "CAA", TTL: 300, Data: "issue letsencrypt.org"})
	h.DNS.Set("acme.example", "SOA", sdk.DNSRecord{Type: "SOA", TTL: 900, Data: "ns1.acme.example. hostmaster.acme.example. 1 3600 600 86400 60"})

	h.Run(sdk.NewEntity(sdk.TypeDomain, "acme.example"))

	h.AssertEntities(sdk.TypeIP, "203.0.113.10", "2001:db8::10")
	h.AssertEntities(sdk.TypeSubdomain, "cdn.vendor.example", "mail.acme.example", "ns1.acme.example")
	h.AssertEntities(sdk.TypeText, "v=spf1 -all")
	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()
}

func TestRelationDirections(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("acme.example", "MX", sdk.DNSRecord{Type: "MX", TTL: 300, Data: "mail.acme.example.", Pref: 10})
	h.DNS.Set("acme.example", "NS", sdk.DNSRecord{Type: "NS", TTL: 300, Data: "ns1.acme.example."})

	target := sdk.NewEntity(sdk.TypeDomain, "acme.example")
	h.Run(target)

	// MX and NS point inward: the mail/nameserver server serves the domain. An
	// inverted edge would make the graph lie about which host is authoritative.
	byID := map[sdk.EntityID]string{target.ID: target.Value}
	for _, f := range h.Out.Findings {
		byID[f.Entity.ID] = f.Entity.Value
	}
	var sawMX, sawNS bool
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			switch r.Type {
			case sdk.RelMXFor:
				sawMX = true
				if byID[r.From] != "mail.acme.example" || byID[r.To] != "acme.example" {
					t.Errorf("mx_for should run mail -> domain, got %s -> %s", byID[r.From], byID[r.To])
				}
			case sdk.RelNSFor:
				sawNS = true
				if byID[r.From] != "ns1.acme.example" || byID[r.To] != "acme.example" {
					t.Errorf("ns_for should run nameserver -> domain, got %s -> %s", byID[r.From], byID[r.To])
				}
			}
		}
	}
	if !sawMX {
		t.Error("no mx_for relation emitted")
	}
	if !sawNS {
		t.Error("no ns_for relation emitted")
	}
}

func TestOneFailingTypeDoesNotAbort(t *testing.T) {
	// The critical resilience property: a domain with no MX but a valid A is
	// normal, and losing the A because the MX lookup failed would be a silent
	// under-report that the analyst would never see.
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("acme.example", "A", sdk.DNSRecord{Type: "A", TTL: 300, Data: "203.0.113.10"})
	h.DNS.SetErr("acme.example", "MX", errors.New("SERVFAIL"))

	h.Run(sdk.NewEntity(sdk.TypeDomain, "acme.example"))

	h.AssertEntities(sdk.TypeIP, "203.0.113.10")
	if len(h.Out.Warnings) == 0 {
		t.Error("the failing lookup should have produced a warning, not silence")
	}
}

func TestSkipsUnparsableAddress(t *testing.T) {
	// A resolver answering with a garbage address is a data quality problem. Storing
	// it would create a fake IP entity that later modules might try to probe.
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("acme.example", "A",
		sdk.DNSRecord{Type: "A", TTL: 300, Data: "not-an-ip"},
		sdk.DNSRecord{Type: "A", TTL: 300, Data: "203.0.113.10"},
	)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "acme.example"))

	h.AssertEntities(sdk.TypeIP, "203.0.113.10")
	h.RefuteEntities(sdk.TypeIP, "not-an-ip")
}

func TestAnswerSetIsBounded(t *testing.T) {
	// An unconstrained answer set can be enormous; a collector that materializes
	// all of it stalls the pipeline.
	var many []sdk.DNSRecord
	for i := 0; i < 50; i++ {
		many = append(many, sdk.DNSRecord{Type: "TXT", TTL: 60, Data: "ver=" + string(rune('a'+i%26)) + strings.Repeat("x", 3)})
	}
	h := sdktest.NewHarness(t, New(WithMaxRecords(10)))
	h.DNS.Set("acme.example", "TXT", many...)

	h.Run(sdk.NewEntity(sdk.TypeDomain, "acme.example"))

	if got := h.CountEntities(sdk.TypeText); got > 10 {
		t.Errorf("emitted %d TXT entities, want at most 10", got)
	}
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "truncated") {
			found = true
		}
	}
	if !found {
		t.Error("truncation must be reported, not silent")
	}
}

func TestTypesCanBeOverridden(t *testing.T) {
	h := sdktest.NewHarness(t, New(WithRecordTypes("A", "aaaa")))
	h.DNS.Set("acme.example", "A", sdk.DNSRecord{Type: "A", TTL: 300, Data: "203.0.113.10"})
	h.DNS.Set("acme.example", "TXT", sdk.DNSRecord{Type: "TXT", TTL: 300, Data: "should-not-be-queried"})

	h.Run(sdk.NewEntity(sdk.TypeDomain, "acme.example"))

	h.RefuteEntities(sdk.TypeText, "should-not-be-queried")
	for _, call := range h.DNS.Calls() {
		if strings.HasSuffix(call, "/TXT") {
			t.Errorf("TXT should not have been queried with the override: %v", h.DNS.Calls())
		}
	}
	// "aaaa" must be normalised to upper case, not passed through as typed.
	sawAAAA := false
	for _, call := range h.DNS.Calls() {
		if strings.HasSuffix(call, "/AAAA") {
			sawAAAA = true
		}
	}
	if !sawAAAA {
		t.Errorf("expected an AAAA lookup, got %v", h.DNS.Calls())
	}
}

func TestNoResolverMeansInitFails(t *testing.T) {
	// A module that initializes without a resolver would run and silently produce
	// nothing, which looks exactly like "the target has no DNS records".
	m := New()
	err := m.Init(context.Background(), sdk.Deps{})
	if err == nil {
		t.Error("Init without a resolver should fail loudly")
	}
}

func TestEgressAllowListMatchesResolverHosts(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	man := h.Module.Manifest()
	for _, host := range man.EgressHosts {
		if !man.AllowsHost(host) {
			t.Errorf("declared host %q is not accepted by its own allow-list", host)
		}
	}
	// A module must never be permitted to reach an arbitrary host.
	for _, bad := range []string{"evil.example", "10.0.0.1", "192.168.1.1"} {
		if man.AllowsHost(bad) {
			t.Errorf("allow-list must not include %q", bad)
		}
	}
}

func TestTrailingDotIsNormalized(t *testing.T) {
	// Resolvers report FQDNs with a trailing dot; the module must not create a
	// second entity for "acme.example." versus "acme.example".
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("acme.example", "A", sdk.DNSRecord{Type: "A", TTL: 300, Data: "203.0.113.10"})

	h.Run(sdk.NewEntity(sdk.TypeSubdomain, "dev.acme.example."))

	for _, call := range h.DNS.Calls() {
		if strings.HasPrefix(call, "dev.acme.example./") {
			t.Errorf("the trailing dot reached the resolver: %q", call)
		}
	}
}

func TestCancelledTaskStopsPromptly(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("acme.example", "A", sdk.DNSRecord{Type: "A", TTL: 300, Data: "203.0.113.10"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := h.Module.Run(ctx, sdk.Task{
		Target:   sdk.NewEntity(sdk.TypeDomain, "acme.example"),
		Params:   map[string]string{},
		Deadline: time.Now().Add(time.Minute),
	}, h.Out)
	if err == nil {
		t.Error("a cancelled context should stop the module")
	}
}
