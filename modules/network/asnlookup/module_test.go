package asnlookup

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// Byte-faithful to what Team Cymru's DNS interface actually returns, including the
// five pipe-separated fields and the allocation date in the last one.
const cymruRecord = "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
const cymruRecordCloudflare = "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"

// Real RIPEstat as-overview payload.
const ripeOverview = `{
  "status": "success",
  "data": {
    "type": "as",
    "resource": "15169",
    "block": {
      "resource": "13312-15359",
      "desc": "Assigned by ARIN",
      "name": "IANA 16-bit Autonomous System (AS) Numbers Registry"
    },
    "holder": "GOOGLE - Google LLC",
    "announced": true,
    "query_starttime": "2026-10-05T00:00:00",
    "query_endtime": "2026-10-05T00:00:00"
  }
}`

func newHarness(t *testing.T, txt string, ripe string) *sdktest.Harness {
	t.Helper()
	m := New(WithBases("origin.asn.cymru.test", "https://ripe.test/data"))
	h := sdktest.NewHarness(t, m)
	if txt != "" {
		h.DNS.Set(reversedIP("8.8.8.8")+"."+m.cymruBase, "TXT", sdk.DNSRecord{Data: txt})
	}
	if ripe != "" {
		h.HTTP.Respond("ripe.test", http.StatusOK, ripe, "application/json")
	}
	return h
}

func TestManifestIsPassive(t *testing.T) {
	man := New().Manifest()
	if man.Mode != sdk.ModePassive {
		t.Errorf("mode = %v, want passive: route data is read, the target is never contacted", man.Mode)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
	// The DNS service is reached through the resolver, not through an HTTP allow-list.
	if !containsStr(man.EgressHosts, "stat.ripe.net") {
		t.Errorf("EgressHosts = %v, want stat.ripe.net", man.EgressHosts)
	}
}

func TestResolvesAddressToOriginAndHolder(t *testing.T) {
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	h.AssertEntities(sdk.TypeASN, "AS15169")
	h.AssertEntities(sdk.TypeCIDR, "8.8.8.0/24")
	h.AssertEntities(sdk.TypeOrg, "GOOGLE - Google LLC")
	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()
}

func TestCymruNameIsTheReversedAddress(t *testing.T) {
	// Team Cymru indexes IPv4 by reversed octets. A wrong order returns nothing and
	// looks like an address with no route.
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	found := false
	for _, q := range h.DNS.Calls() {
		if strings.Contains(q, "8.8.8.8.origin.asn.cymru.test") {
			found = true
		}
	}
	if !found {
		t.Errorf("no query to the reversed-octet name; queries: %v", h.DNS.Calls())
	}
}

func TestReversedIP(t *testing.T) {
	// 8.8.8.8 reverses to itself, which is exactly why the function needs a
	// non-symmetric case to be testable at all.
	if got := reversedIP("8.8.8.8"); got != "8.8.8.8" {
		t.Errorf("reversedIP(8.8.8.8) = %q", got)
	}
	if got := reversedIP("1.2.3.4"); got != "4.3.2.1" {
		t.Errorf("reversedIP(1.2.3.4) = %q, want 4.3.2.1", got)
	}
	// An IPv6 address has no reversed-octet form, so the lookup is skipped rather
	// than issued with nonsense.
	if got := reversedIP("2001:db8::1"); got != "" {
		t.Errorf("reversedIP(v6) = %q, want empty", got)
	}
	if got := reversedIP("not-an-ip"); got != "" {
		t.Errorf("reversedIP(garbage) = %q, want empty", got)
	}
}

func TestAllocationDateIsNotPresentedAsFirstSeen(t *testing.T) {
	// The trailing field is the block's allocation date. Calling it a first-seen date
	// would claim the network was operating then.
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "originated_by" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no origin observation")
	}
	if _, bad := attrs["first_seen"]; bad {
		t.Error("the allocation date was published as a first_seen date")
	}
	if attrs["block_allocated_at"] != "2023-12-28" {
		t.Errorf("block_allocated_at = %v", attrs["block_allocated_at"])
	}
}

func TestParseCymru(t *testing.T) {
	o, ok := parseCymru(cymruRecord)
	if !ok {
		t.Fatal("a well-formed record was rejected")
	}
	if o.asn != "15169" || o.prefix != "8.8.8.0/24" || o.country != "US" || o.registry != "arin" {
		t.Errorf("parsed = %+v", o)
	}

	// Long TXT values arrive quoted and space-padded when concatenated.
	q := `13335 | " 1.1.1.0/24 " | " AU " | apnic | 2011-08-11`
	o, ok = parseCymru(q)
	if !ok {
		t.Fatal("a quoted record was rejected")
	}
	if o.asn != "13335" || o.prefix != "1.1.1.0/24" || o.country != "AU" {
		t.Errorf("quoting not stripped: %+v", o)
	}

	// Anything without a numeric autonomous system is not a route record.
	for _, bad := range []string{"", "   ", "not a record", "abc | 8.8.8.0/24 | US | arin", "15169"} {
		if _, ok := parseCymru(bad); ok {
			t.Errorf("parseCymru(%q) accepted a malformed record", bad)
		}
	}
}

func TestRoutingIsMarkedAsASnapshot(t *testing.T) {
	// BGP origin can and does move. An observation without a sense of when it was
	// taken reads as a standing fact.
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "originated_by" {
			attrs = f.Observation.Attrs
		}
	}
	if snap, _ := attrs["routing_snapshot"].(bool); !snap {
		t.Error("the origin observation does not mark itself as a point-in-time snapshot")
	}
}

func TestHolderScopeIsStated(t *testing.T) {
	// The holder is who holds the number. For a shared network it is frequently not
	// who operates anything on it, and a graph reader cannot see that from the edge
	// alone.
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "held_by" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no holder observation")
	}
	scope, _ := attrs["holder_scope"].(string)
	if !strings.Contains(scope, "not operation of services") {
		t.Errorf("holder_scope = %q; it must distinguish number registration from service operation", scope)
	}
}

func TestHolderEdgeIsNotHeuristicBecauseItIsARegistry(t *testing.T) {
	// The specification treats owned_by as heuristic unless backed by a registry,
	// and this edge comes from a RIR allocation record.
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))

	saw := false
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if r.Type != sdk.RelOwnedBy {
				continue
			}
			saw = true
			if r.Heuristic {
				t.Error("the holder edge is heuristic despite coming from a registry record")
			}
		}
	}
	if !saw {
		t.Fatal("no holder edge emitted")
	}
}

func TestEdgeDirectionsMatchTheTaxonomy(t *testing.T) {
	// announced_by runs cidr -> asn. An inverted edge would claim the autonomous
	// system is announced by the prefix it announces.
	h := newHarness(t, cymruRecord, ripeOverview)
	target := sdk.NewEntity(sdk.TypeIP, "8.8.8.8")
	h.Run(target)

	var asnID, cidrID sdk.EntityID
	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeASN {
			asnID = f.Entity.ID
		}
		if f.Entity.Type == sdk.TypeCIDR {
			cidrID = f.Entity.ID
		}
	}
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			switch r.Type {
			case sdk.RelAnnouncedBy:
				if r.From != cidrID || r.To != asnID {
					t.Errorf("announced_by ran %s -> %s, want cidr -> asn", r.From, r.To)
				}
			case sdk.RelPartOfNetwork:
				if r.From != target.ID || r.To != asnID {
					t.Errorf("part_of_network ran %s -> %s, want ip -> asn", r.From, r.To)
				}
			}
		}
	}
}

func TestNoOriginRecordIsAFindingNotAnError(t *testing.T) {
	// Absent from a route collector's tables is not the same as unrouted. The gap
	// must be stated rather than left as silence.
	h := newHarness(t, "", "")
	h.Run(sdk.NewEntity(sdk.TypeIP, "192.0.2.99"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "no_origin_recorded" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no finding for an address with no route record")
	}
	note, _ := attrs["note"].(string)
	if !strings.Contains(note, "not a claim that the address is unrouted") {
		t.Errorf("note = %q", note)
	}
	if h.CountEntities(sdk.TypeASN) != 0 {
		t.Error("an address with no route record produced an autonomous system")
	}
}

func TestASNTargetResolvesHolderWithoutRouteData(t *testing.T) {
	// Asking about an AS number does not need the IP-to-ASN lookup at all.
	h := newHarness(t, "", ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeASN, "AS15169"))

	h.AssertEntities(sdk.TypeOrg, "GOOGLE - Google LLC")
	if len(h.DNS.Calls()) != 0 {
		t.Errorf("an ASN target issued DNS queries: %v", h.DNS.Calls())
	}
}

func TestRipeFailureIsReported(t *testing.T) {
	m := New(WithBases("origin.asn.cymru.test", "https://ripe.test/data"))
	h := sdktest.NewHarness(t, m)
	h.DNS.Set("8.8.8.8.origin.asn.cymru.test", "TXT", sdk.DNSRecord{Data: cymruRecord})
	h.HTTP.Respond("ripe.test", http.StatusInternalServerError, `{"error":1}`, "application/json")

	if err := h.RunExpectingError(sdk.NewEntity(sdk.TypeIP, "8.8.8.8")); err == nil {
		t.Error("a holder lookup that failed must surface rather than silently omitting the holder")
	}
}

func TestRipeNonSuccessStatusIsNotSilentlyAccepted(t *testing.T) {
	// RIPEstat answers 200 with a non-success status for some failures. Parsing that
	// as data would produce an empty holder and a confident-looking finding.
	m := New(WithBases("origin.asn.cymru.test", "https://ripe.test/data"))
	h := sdktest.NewHarness(t, m)
	h.DNS.Set("8.8.8.8.origin.asn.cymru.test", "TXT", sdk.DNSRecord{Data: cymruRecord})
	h.HTTP.Respond("ripe.test", http.StatusOK, `{"status":"not_found","data":{}}`, "application/json")

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))
	if err == nil {
		t.Fatal("a non-success status must not be parsed as a holder record")
	}
	if !strings.Contains(err.Error(), "not_found") {
		t.Errorf("error should name the status: %v", err)
	}
}

func TestEmptyHolderIsAWarningNotAnOrganization(t *testing.T) {
	// RIPEstat answers successfully for a reserved or unallocated block with no
	// holder. Emitting an empty-named organization would be nonsense.
	m := New(WithBases("origin.asn.cymru.test", "https://ripe.test/data"))
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("ripe.test", http.StatusOK,
		`{"status":"success","data":{"resource":"64496","holder":"","announced":false}}`, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeASN, "AS64496"))

	if h.CountEntities(sdk.TypeOrg) != 0 {
		t.Error("an empty holder became an organization entity")
	}
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "no holder published") {
			found = true
		}
	}
	if !found {
		t.Errorf("the missing holder was not reported; got %v", h.Out.Warnings)
	}
}

func TestCIDRTargetIsReducedToAnAddress(t *testing.T) {
	// A prefix has no single origin; the address that was queried does.
	m := New(WithBases("origin.asn.cymru.test", "https://ripe.test/data"))
	h := sdktest.NewHarness(t, m)
	h.DNS.Set("8.8.8.8.origin.asn.cymru.test", "TXT", sdk.DNSRecord{Data: cymruRecord})
	h.HTTP.Respond("ripe.test", http.StatusOK, ripeOverview, "application/json")

	h.Run(sdk.NewEntity(sdk.TypeCIDR, "8.8.8.0/24"))

	found := false
	for _, q := range h.DNS.Calls() {
		if strings.Contains(q, "/24") {
			t.Errorf("the prefix itself was queried: %q", q)
		}
		if strings.Contains(q, "0.8.8.8.origin.asn.cymru.test") {
			found = true
		}
	}
	if !found {
		t.Errorf("no query derived from the prefix; got %v", h.DNS.Calls())
	}
}

func TestTrimAS(t *testing.T) {
	for in, want := range map[string]string{
		"AS15169": "15169", "as15169": "15169", "15169": "15169", " AS15169 ": "15169",
		"": "", "ASxyz": "", "AS": "",
	} {
		if got := trimAS(in); got != want {
			t.Errorf("trimAS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNonRegistrableTargetIsSkipped(t *testing.T) {
	// A domain or a username has no routing record to look up.
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if len(h.DNS.Calls()) != 0 || len(h.HTTP.Calls()) != 0 {
		t.Errorf("a domain target caused lookups: dns=%v http=%v", h.DNS.Calls(), h.HTTP.Calls())
	}
}

func TestNoResolverFailsInit(t *testing.T) {
	m := New()
	if err := m.Init(context.Background(), sdk.Deps{HTTP: http.DefaultClient}); err == nil {
		t.Error("Init without a DNS resolver must fail rather than run and produce nothing")
	}
}

func TestEvidenceIsRetained(t *testing.T) {
	h := newHarness(t, cymruRecord, ripeOverview)
	h.Run(sdk.NewEntity(sdk.TypeIP, "8.8.8.8"))
	if h.Blobs.Count() == 0 {
		t.Fatal("no evidence retained; the RIR record is the artifact behind the holder claim")
	}
	if !strings.Contains(string(h.Blobs.Bytes()), "GOOGLE") {
		t.Error("retained artifact does not look like the RIPEstat response")
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
