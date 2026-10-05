package wayback

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// Real CDX shape, trimmed. The first row is a header naming the requested fields,
// the Archive emits rows with explicit default ports, and it records the 404s it hit
// while crawling alongside the pages it actually stored. A fixture that omits those
// hides both the header trap and the phantom-subdomain trap.
const cdxFixture = `[
  ["original","timestamp","statuscode"],
  ["http://www.kernel.org:80/","20180101000000","200"],
  ["http://www.kernel.org:80/!INDEX.html","20010609235502","404"],
  ["http://git.kernel.org:80/","20190102030405","200"],
  ["https://docs.kernel.org/doc/html/latest/","20240101000000","200"],
  ["http://www.kernel.org:80/docs/","20200401000000","301"],
  ["http://kernel.org:80/gone.html","20150101000000","410"],
  ["http://attacker.other-domain.test/","20200101000000","200"],
  ["http://kernel.org:80/","20180101000000","200"]
]`

// emptyFixture is what the Archive actually returns for a domain it holds nothing
// for: HTTP 200 with an empty array, not a 404.
const emptyFixture = `[]`

func newHarness(t *testing.T, body string, opts ...Option) *sdktest.Harness {
	t.Helper()
	m := New(opts...)
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("web.archive.org", http.StatusOK, body, "application/json")
	return h
}

func TestManifestIsPassive(t *testing.T) {
	man := New().Manifest()
	if man.Mode != sdk.ModePassive {
		t.Errorf("mode = %v, want passive: the Archive is a third party and the target is never contacted", man.Mode)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
	if !containsStr(man.EgressHosts, "web.archive.org") {
		t.Errorf("EgressHosts = %v", man.EgressHosts)
	}
	// The Archive throttles sustained callers. The hint exists to be a good
	// citizen, so a generous rate would be wrong.
	r, ok := man.RateHints["web.archive.org"]
	if !ok {
		t.Fatal("no rate hint for web.archive.org")
	}
	if r.Requests <= 0 || r.Per < time.Second {
		t.Errorf("rate hint = %v; the Archive asks for well under one request per second", r)
	}
}

func TestFindsHistoricalHosts(t *testing.T) {
	h := newHarness(t, cdxFixture)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "kernel.org"))

	h.AssertEntities(sdk.TypeSubdomain, "www.kernel.org", "git.kernel.org", "docs.kernel.org")
	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()
}

func TestNotFoundCapturesDoNotBecomeHosts(t *testing.T) {
	// The Archive records the 404s it encountered while crawling. A 404 row means it
	// probed a URL and found nothing, which is evidence of a probe and not of a
	// host. Counting these is the single largest source of phantom subdomains in a
	// capture index.
	h := newHarness(t, cdxFixture)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "kernel.org"))

	for _, f := range h.Out.Findings {
		if strings.Contains(f.Entity.Value, "gone.html") || strings.Contains(f.Entity.Value, "!index") {
			t.Errorf("a non-successful capture became a host: %q", f.Entity.Value)
		}
	}
}

func TestSuccessfulStatusCoversOnlyWhatServed(t *testing.T) {
	cases := map[int]bool{
		200: true, 201: true, 301: true, 302: true, 399: true, 403: true,
		400: false, 401: false, 404: false, 410: false, 500: false, 503: false,
		// A row with no status column is unknown, not a success. Treating unknown as
		// success would let a malformed row become a phantom host.
		0: false,
	}
	for code, want := range cases {
		if got := successfulStatus(code); got != want {
			t.Errorf("successfulStatus(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestApexIsNotEmittedAsItsOwnSubdomain(t *testing.T) {
	// kernel.org appears in the capture list. Emitting it as a subdomain of itself
	// would be a self-loop.
	h := newHarness(t, cdxFixture)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "kernel.org"))

	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeSubdomain && f.Entity.Value == "kernel.org" {
			t.Error("the apex was emitted as its own subdomain")
		}
	}
}

func TestDefaultPortsDoNotForkTheHost(t *testing.T) {
	// The Archive's rows carry explicit default ports such as http://www.kernel.org:80/.
	// Without stripping them the same host becomes two entities.
	if got := hostOf("http://www.kernel.org:80/"); got != "www.kernel.org" {
		t.Errorf("hostOf = %q, want www.kernel.org", got)
	}
	if got := hostOf("https://www.kernel.org:443/x"); got != "www.kernel.org" {
		t.Errorf("hostOf = %q, want www.kernel.org", got)
	}
	if got := hostOf("https://www.kernel.org/x"); got != "www.kernel.org" {
		t.Errorf("hostOf = %q, want www.kernel.org", got)
	}
	if got := hostOf("not a url"); got != "" {
		t.Errorf("hostOf(%q) = %q, want empty", "not a url", got)
	}
}

func TestFindingsAreMarkedHistorical(t *testing.T) {
	// This module's evidence is about the past. Reporting an archived name as a live
	// subdomain would put a dead host into the graph as a pivot target.
	h := newHarness(t, cdxFixture)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "kernel.org"))

	found := 0
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "archived_in_wayback" {
			continue
		}
		found++
		if flag, _ := f.Observation.Attrs["historical"].(bool); !flag {
			t.Errorf("%s is not marked historical", f.Entity.Value)
		}
		for _, k := range []string{"first_seen", "last_seen"} {
			v, ok := f.Observation.Attrs[k].(string)
			if !ok || v == "" {
				t.Errorf("%s missing %s", f.Entity.Value, k)
				continue
			}
			if !strings.HasPrefix(v, "20") {
				t.Errorf("%s %s = %q, want an RFC 3339 date rather than a raw CDX stamp",
					f.Entity.Value, k, v)
			}
		}
	}
	if found == 0 {
		t.Fatal("no archived host observations emitted")
	}
}

func TestFirstSeenIsTheEarliestCapture(t *testing.T) {
	// A later capture must not overwrite the earliest date. Getting this backwards
	// makes a host look newer than it is and hides long-dormant infrastructure.
	rows := []capture{
		{original: "https://a.example.org/x", stamp: "20200101000000", status: 200},
		{original: "https://a.example.org/y", stamp: "20150101000000", status: 200},
		{original: "https://a.example.org/z", stamp: "20230405060708", status: 200},
	}
	hosts := aggregate(rows, "example.org")
	rec := hosts["a.example.org"]
	if rec == nil {
		t.Fatal("host not aggregated")
	}
	if rec.firstSeen != "20150101000000" {
		t.Errorf("firstSeen = %s", rec.firstSeen)
	}
	if rec.lastSeen != "20230405060708" {
		t.Errorf("lastSeen = %s", rec.lastSeen)
	}
	if rec.captures != 3 {
		t.Errorf("captures = %d, want 3", rec.captures)
	}
}

func TestHostsOutsideTheDomainAreDropped(t *testing.T) {
	// A wildcard domain query still returns stray rows. Attributing another
	// organization's hosts to the target is what this prevents.
	hosts := aggregate([]capture{
		{original: "http://attacker.other-domain.test/", stamp: "20200101000000", status: 200},
		{original: "http://evil-kernel.org/", stamp: "20200101000000", status: 200},
		{original: "http://kernel.org.evil.test/", stamp: "20200101000000", status: 200},
	}, "kernel.org")
	if len(hosts) != 0 {
		for h := range hosts {
			t.Errorf("host %q is outside the target and should have been dropped", h)
		}
	}
}

func TestNoCapturesIsAFindingNotAnError(t *testing.T) {
	// The Archive answers HTTP 200 with an empty array when it holds nothing. That
	// is a statement about the Archive, not proof the hosts never existed, so it is
	// reported rather than returned as an error or left as silence.
	h := newHarness(t, emptyFixture)
	// An empty index is not a failure; Run returning nil is the point.
	h.Run(sdk.NewEntity(sdk.TypeDomain, "nothing-here.test"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "no_archived_captures" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no finding emitted for an empty index; silence reads as a claim")
	}
	note, _ := attrs["note"].(string)
	if !strings.Contains(note, "not a claim that the hosts never existed") {
		t.Errorf("note = %q; it must state what the empty result does not mean", note)
	}
}

func TestThrottlingIsAFailureNotAnEmptyResult(t *testing.T) {
	// 429 and 403 are what the Archive returns to sustained callers. Reporting those
	// as "no captures" would turn a rate limit into a clean result.
	m := New()
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("web.archive.org", http.StatusTooManyRequests, "slow down", "text/plain")

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "kernel.org"))
	if err == nil {
		t.Fatal("HTTP 429 must surface as an error")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should name the status: %v", err)
	}
}

func TestQueryAsksForTheWholeDomain(t *testing.T) {
	// matchType=domain with the bare registrable domain is the whole-domain query.
	//
	// Combining the wildcard with matchType=domain is a live trap: the Archive
	// answers HTTP 200 with an empty array instead of an error, so the module would
	// report that nothing was ever archived while having asked a question the index
	// silently ignores. Both forms work individually; they are alternatives, not
	// synonyms.
	q := New().buildURL("kernel.org")
	if strings.Contains(q, "%2A") || strings.Contains(q, "*") {
		t.Errorf("query = %q; the wildcard must not be combined with matchType=domain", q)
	}
	if !strings.Contains(q, "url=kernel.org") {
		t.Errorf("query = %q; the bare domain is required", q)
	}
	if !strings.Contains(q, "matchType=domain") {
		t.Errorf("query = %q; matchType=domain is required", q)
	}
	// collapse=urlkey stops the limit being spent on repeat captures of one page.
	if !strings.Contains(q, "collapse=urlkey") {
		t.Errorf("query = %q; without collapse the limit is wasted on duplicates", q)
	}
	if !strings.Contains(q, "limit=") {
		t.Errorf("query = %q; a bounded read needs a limit", q)
	}
	// The index stores the 404s it hit while crawling, several hundred to one for a
	// real domain. Without a server-side filter the whole row limit is spent on rows
	// that are then thrown away, so a bounded read returns almost nothing.
	if !strings.Contains(q, "filter=statuscode") {
		t.Errorf("query = %q; the 404 rows must be filtered server-side", q)
	}
}

func TestHostSetIsBounded(t *testing.T) {
	var rows []capture
	for i := 0; i < 200; i++ {
		rows = append(rows, capture{
			original: "https://h" + itoa(i) + ".example.org/", stamp: "20200101000000", status: 200,
		})
	}
	body := `[["original","timestamp","statuscode"],`
	for i, r := range rows {
		if i > 0 {
			body += ","
		}
		body += `["` + r.original + `","` + r.stamp + `","200"]`
	}
	body += `]`

	h := newHarness(t, body, WithMaxHosts(20))
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.org"))

	if got := h.CountEntities(sdk.TypeSubdomain); got > 20 {
		t.Errorf("emitted %d hosts, want at most 20", got)
	}
	// A capped result must not read as complete.
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "truncated") {
			found = true
		}
	}
	if !found {
		t.Error("truncation was silent")
	}
}

func TestSummaryStatesItIsASample(t *testing.T) {
	// The Archive holds hundreds of millions of rows for a popular domain. The span
	// that was read is not the domain's lifetime, and the summary must not imply
	// otherwise.
	h := newHarness(t, cdxFixture)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "kernel.org"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "wayback_summary" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no summary emitted")
	}
	if sampled, _ := attrs["sampled"].(bool); !sampled {
		t.Error("summary does not state that the result is a bounded sample")
	}
	if n, _ := attrs["query_limit"].(int); n == 0 {
		t.Error("summary omits the limit that was applied")
	}
}

func TestHeaderRowIsNotParsedAsData(t *testing.T) {
	// The first row names the requested fields. Treating it as a capture would
	// produce one phantom host literally named "original".
	rows, err := parseCDX([]byte(cdxFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.EqualFold(r.original, "original") {
			t.Fatal("the header row was parsed as a capture")
		}
	}
	if len(rows) != 8 {
		t.Errorf("parsed %d rows, want 8", len(rows))
	}
}

func TestParseRejectsAResponseWithNoOriginalColumn(t *testing.T) {
	// An index without the column this module depends on is an error, not an empty
	// result. Silently returning nothing would read as "nothing was ever archived".
	if _, err := parseCDX([]byte(`[["timestamp"],["20200101000000"]]`)); err == nil {
		t.Error("expected an error for a response with no 'original' column")
	}
	if _, err := parseCDX([]byte(`not json`)); err == nil {
		t.Error("expected an error for a non-JSON response")
	}
	rows, err := parseCDX([]byte(emptyFixture))
	if err != nil {
		t.Errorf("an empty index is valid JSON and must not error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %d, want 0", len(rows))
	}
}

func TestCDTimestamp(t *testing.T) {
	if got := cdTimestamp("19980130085039"); got != "1998-01-30T08:50:39Z" {
		t.Errorf("cdTimestamp = %q", got)
	}
	// A malformed stamp is passed through rather than dropped, so the value stays
	// visible instead of silently becoming zero.
	if got := cdTimestamp("garbage"); got != "garbage" {
		t.Errorf("cdTimestamp = %q, want the input preserved", got)
	}
}

func TestAtoi(t *testing.T) {
	for in, want := range map[string]int{
		"200": 200, "301": 301, " 404 ": 404, "": 0, "20x": 0, "404 Moved": 0,
	} {
		if got := atoi(in); got != want {
			t.Errorf("atoi(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestNoHTTPClientFailsInit(t *testing.T) {
	m := New()
	if err := m.Init(context.Background(), sdk.Deps{}); err == nil {
		t.Error("Init without an HTTP client must fail rather than run and produce nothing")
	}
}

func TestEvidenceIsRetained(t *testing.T) {
	h := newHarness(t, cdxFixture)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "kernel.org"))
	if h.Blobs.Count() == 0 {
		t.Fatal("no evidence retained; the CDX index is the artifact behind every date reported")
	}
	if !strings.Contains(string(h.Blobs.Bytes()), "kernel.org") {
		t.Error("retained artifact does not look like a CDX response")
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
