package reverse

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// What the resolvers actually returned when this was written.
const ptrGoogle = "dns.google."
const ptrCloudflare = "one.one.one.one."

func newHarness(t *testing.T) *sdktest.Harness {
	t.Helper()
	m := New()
	h := sdktest.NewHarness(t, m)
	h.DNS.Set("8.8.8.8.in-addr.arpa", "PTR", sdk.DNSRecord{Type: "PTR", Data: ptrGoogle})
	h.DNS.Set("dns.google", "A", sdk.DNSRecord{Type: "A", Data: "8.8.8.8"})
	h.DNS.Set("dns.google", "AAAA")
	return h
}

func TestManifestIsSemiActive(t *testing.T) {
	man := New().Manifest()
	// DNS lookups reach the subject's own resolvers, so this touches infrastructure
	// they operate. Declaring it passive would understate what was done.
	if man.Mode != sdk.ModeSemiActive {
		t.Errorf("mode = %v, want semi-active", man.Mode)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
}

func TestReverseOfEdgePointsFromTheAddress(t *testing.T) {
	h := newHarness(t)
	addr := sdk.NewEntity(sdk.TypeIP, "8.8.8.8")
	h.Run(addr)

	h.AssertEntities(sdk.TypeSubdomain, "dns.google")

	saw := false
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != sdk.RelReverseOf {
				continue
			}
			saw = true
			if r.From != addr.ID {
				t.Errorf("reverse_of ran from %s; it must run address -> name", r.From)
			}
		}
	}
	if !saw {
		t.Fatal("no reverse_of edge emitted")
	}
}

func TestForwardConfirmation(t *testing.T) {
	// The pointer resolves back to the same address, so the claim is corroborated.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "reverse_of" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no pointer observation emitted")
	}
	if attrs["forward_confirmed"] != true {
		t.Errorf("forward_confirmed = %v, want true", attrs["forward_confirmed"])
	}
	// A confirmed pointer is a routine record, not a mismatch.
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "reverse_of" && f.Kind == "reverse-dns-fcrdns-mismatch" {
			t.Error("a forward-confirmed pointer was reported as a mismatch")
		}
	}
}

func TestMismatchIsRaisedAndNotHidden(t *testing.T) {
	// A pointer that does not resolve back is either stale or deliberately
	// misdirected. Reporting it as a routine pointer would launder the difference.
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("10.2.0.192.in-addr.arpa", "PTR", sdk.DNSRecord{Type: "PTR", Data: "stale.example.com."})
	h.DNS.Set("stale.example.com", "A", sdk.DNSRecord{Type: "A", Data: "198.51.100.7"})

	h.Run(sdk.NewEntity(sdk.TypeIP, "192.0.2.10"))

	var kind, severity string
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "reverse_of" {
			kind, severity = f.Kind, f.Severity
			if flag, _ := f.Observation.Attrs["forward_confirmed"].(bool); flag {
				t.Error("forward_confirmed is true for a name that resolves elsewhere")
			}
			if note, _ := f.Observation.Attrs["fcrdns_note"].(string); note == "" {
				t.Error("a mismatch carries no explanation")
			}
		}
	}
	if kind != "reverse-dns-fcrdns-mismatch" {
		t.Errorf("kind = %q, want reverse-dns-fcrdns-mismatch", kind)
	}
	if severity == "" || severity == sdk.SevInfo {
		t.Errorf("severity = %q; a mismatch is more than routine", severity)
	}
}

func TestWhereThePointerActuallyLeadsIsReported(t *testing.T) {
	// The name resolves to a different address. That address is real information even
	// though the pointer does not point back, so it is emitted with the mismatch
	// stated rather than dropped.
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("10.2.0.192.in-addr.arpa", "PTR", sdk.DNSRecord{Type: "PTR", Data: "stale.example.com."})
	h.DNS.Set("stale.example.com", "A", sdk.DNSRecord{Type: "A", Data: "198.51.100.7"})

	h.Run(sdk.NewEntity(sdk.TypeIP, "192.0.2.10"))

	h.AssertEntities(sdk.TypeIP, "198.51.100.7")

	var flagged bool
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "resolves_to" && f.Observation.Attrs["via_ptr"] == "stale.example.com" {
			flagged = true
			if f.Observation.Attrs["reverse_confirmed"] != false {
				t.Error("the forward answer is not marked as not confirming the reverse")
			}
		}
	}
	if !flagged {
		t.Error("the address the pointer leads to was not reported")
	}
}

func TestNoPointerIsAFinding(t *testing.T) {
	// An empty answer is not a statement about the host, and silence would be read as
	// one.
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("1.2.0.192.in-addr.arpa", "PTR")

	h.Run(sdk.NewEntity(sdk.TypeIP, "192.0.2.1"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "no_ptr_record" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no finding for an address with no pointer")
	}
	if note, _ := attrs["note"].(string); !strings.Contains(note, "does not indicate whether the host exists") {
		t.Errorf("note = %q", note)
	}
	if h.CountEntities(sdk.TypeSubdomain) != 0 {
		t.Error("an address with no pointer produced a name entity")
	}
}

func TestResolverFailureIsNotSilentlyNoPointer(t *testing.T) {
	// A transport failure and an absent record are different facts. Treating the
	// first as the second turns an outage into a clean negative.
	m := New()
	h := sdktest.NewHarness(t, m)
	h.DNS.SetErr("1.2.0.192.in-addr.arpa", "PTR", fmt.Errorf("resolver unreachable"))

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeIP, "192.0.2.1"))
	if err == nil {
		t.Fatal("a resolver failure must surface, not be reported as no pointer")
	}
	if strings.Contains(err.Error(), "no_ptr") {
		t.Error("the error was phrased as an absent record")
	}
}

func TestSharedInfrastructureIsFlagged(t *testing.T) {
	// A pointer into a hosting platform's namespace identifies where the address is
	// served, not who operates it. Without the note a reader concludes the target owns
	// the machine.
	for name, provider := range map[string]string{
		"ec2-203-0-113-1.compute-1.amazonaws.com": "Amazon Web Services",
		"host.docker.internal.gcp":                "Google Cloud",
		"myapp.azurewebsites.net":                 "Microsoft Azure",
		"vm.corp.fastly.net":                      "Fastly",
	} {
		h := sdktest.NewHarness(t, New())
		h.DNS.Set("10.2.0.192.in-addr.arpa", "PTR", sdk.DNSRecord{Type: "PTR", Data: name + "."})
		h.DNS.Set(name, "A", sdk.DNSRecord{Type: "A", Data: "192.0.2.10"})

		h.Run(sdk.NewEntity(sdk.TypeIP, "192.0.2.10"))

		found := false
		for _, f := range h.Out.Findings {
			if f.Observation.Predicate != "reverse_of" {
				continue
			}
			if f.Observation.Attrs["shared_infrastructure"] == true {
				found = true
				if got := f.Observation.Attrs["shared_provider"]; got != provider {
					t.Errorf("%s: provider = %v, want %q", name, got, provider)
				}
				if note, _ := f.Observation.Attrs["shared_note"].(string); note == "" {
					t.Errorf("%s: no explanation of what the namespace means", name)
				}
			}
		}
		if !found {
			t.Errorf("%s was not flagged as shared infrastructure", name)
		}
	}
}

func TestOrdinaryNamesAreNotFlaggedShared(t *testing.T) {
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "reverse_of" && f.Observation.Attrs["shared_infrastructure"] != nil {
			t.Errorf("dns.google was flagged as shared infrastructure")
		}
	}
}

func TestSharedNamespaceIsSuffixAnchored(t *testing.T) {
	// A host merely containing the words, or holding them as a leading label, is not
	// in the namespace.
	for _, name := range []string{
		"amazonaws.com.attacker.test",
		"notamazonaws.com",
		"fastly.net.evil.test",
	} {
		if shared, _ := sharedInfrastructure(name); shared {
			t.Errorf("%q was treated as a shared namespace", name)
		}
	}
}

func TestFixtureUsesRealReverseNames(t *testing.T) {
	// A test that scripts the PTR answer under the address itself rather than under
	// its reverse name passes for any address whose octets are symmetric, which is
	// exactly 8.8.8.8 and 1.1.1.1, and then fails for everything else. This pins the
	// name so the trap cannot come back.
	got, err := ptrName("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.2.0.192.in-addr.arpa" {
		t.Errorf("ptrName(192.0.2.10) = %q, want 10.2.0.192.in-addr.arpa", got)
	}
}

func TestPtrNameConstruction(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":     "8.8.8.8.in-addr.arpa",
		"1.1.1.1":     "1.1.1.1.in-addr.arpa",
		"203.0.113.9": "9.113.0.203.in-addr.arpa",
		"192.0.2.1":   "1.2.0.192.in-addr.arpa",
	}
	for in, want := range cases {
		got, err := ptrName(in)
		if err != nil {
			t.Errorf("ptrName(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ptrName(%q) = %q, want %q", in, got, want)
		}
	}

	// IPv6 reverse names are 32 nibbles in reverse order. Getting the order or the
	// length wrong yields a name that never resolves.
	got, err := ptrName("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, ".ip6.arpa") {
		t.Errorf("ptrName(v6) = %q", got)
	}
	// 32 nibbles, each followed by a dot, then "ip6.arpa" which contributes one more.
	nibbles := strings.TrimSuffix(got, ".ip6.arpa")
	if n := strings.Count(nibbles, ".") + 1; n != 32 {
		t.Errorf("ptrName(v6) has %d nibble labels, want 32: %q", n, nibbles)
	}
	// The first nibble must be the low half of the last byte, which is 1.
	if !strings.HasPrefix(got, "1.0.0.0.") {
		t.Errorf("ptrName(v6) = %q; the nibbles are not reversed correctly", got)
	}

	if _, err := ptrName("not-an-address"); err == nil {
		t.Error("ptrName accepted a non-address")
	}
}

func TestNonAddressTargetIsSkipped(t *testing.T) {
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if len(h.DNS.Calls()) != 0 {
		t.Errorf("a domain target caused lookups: %v", h.DNS.Calls())
	}
}

func TestForwardLookupCoversBothFamilies(t *testing.T) {
	// A dual-stack pointer is common, and confirming only the A answer would let a
	// mismatched AAAA record pass.
	h := sdktest.NewHarness(t, New())
	h.DNS.Set("10.2.0.192.in-addr.arpa", "PTR", sdk.DNSRecord{Type: "PTR", Data: "dual.example.com."})
	h.DNS.Set("dual.example.com", "A", sdk.DNSRecord{Type: "A", Data: "192.0.2.10"})
	h.DNS.Set("dual.example.com", "AAAA", sdk.DNSRecord{Type: "AAAA", Data: "2001:db8::99"})

	h.Run(sdk.NewEntity(sdk.TypeIP, "192.0.2.10"))

	var sawV6 bool
	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeIP && strings.HasPrefix(f.Entity.Value, "2001:db8") {
			sawV6 = true
		}
	}
	if !sawV6 {
		t.Error("the AAAA answer was not considered")
	}
}

func TestNoResolverFailsInit(t *testing.T) {
	if err := New().Init(context.Background(), sdk.Deps{}); err == nil {
		t.Error("Init without a DNS resolver must fail rather than run and produce nothing")
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
