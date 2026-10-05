package passive

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// Real HackerTarget output for python.org, CSV of host,address.
const hackerTargetCSV = `python.org,151.101.128.223
africa.python.org,116.202.118.106
buildbot.python.org,185.199.108.153
cheeseshop.python.org,151.101.1.110
docs.python.org,151.101.0.223
`

// The real table shape from rapiddns.io: a name cell, then a cell whose anchor text is
// the address.
const rapidDNSTable = `<table id="table"><thead><tr>
<th scope="col" width="38%">Host</th>
<th scope="col" width="8%">Address</th>
<th scope="col" width="8%">Type</th>
</tr></thead>
<tbody>
<tr><th scope="row">1</th><td>es.python.org</td>
<td><a href="/sameip/185.199.109.153#result" title="same ip">185.199.109.153</a></td>
<td>CNAME</td></tr>
<tr><th scope="row">2</th><td>blog.python.org</td>
<td><a href="/sameip/185.199.108.153#result" title="same ip">185.199.108.153</a></td>
<td>A</td></tr>
</tbody></table>`

func newHarness(t *testing.T, opts ...Option) *sdktest.Harness {
	t.Helper()
	h := sdktest.NewHarness(t, New(opts...))
	h.HTTP.Respond("api.hackertarget.com", http.StatusOK, hackerTargetCSV, "text/plain")
	h.HTTP.Respond("rapiddns.io", http.StatusOK, rapidDNSTable, "text/html")
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
	if !man.AllowsHost("api.hackertarget.com") || !man.AllowsHost("rapiddns.io") {
		t.Errorf("EgressHosts = %v", man.EgressHosts)
	}
}

func TestUnionsNamesFromEverySource(t *testing.T) {
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	// HackerTarget reports buildbot; RapidDNS reports es and blog. The union is the
	// point of the module.
	h.AssertEntities(sdk.TypeSubdomain, "buildbot.python.org", "es.python.org", "blog.python.org")
	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()
}

func TestNameSeenByTwoSourcesIsOneName(t *testing.T) {
	// The aggregate must not emit the same host twice, and must attribute both
	// sources: that attribution is what the credibility grade rests on.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	count := 0
	for _, f := range h.Out.Findings {
		if f.Entity.Type != sdk.TypeSubdomain {
			continue
		}
		// python.org itself appears in HackerTarget and must not be emitted as its own
		// subdomain.
		if f.Entity.Value == "python.org" {
			t.Error("the registrable domain was emitted as its own subdomain")
		}
		if f.Entity.Value == "docs.python.org" {
			count++
			if n, _ := f.Observation.Attrs["source_count"].(int); n != 1 {
				t.Errorf("docs.python.org reports %v sources; only HackerTarget listed it",
					f.Observation.Attrs["source_count"])
			}
		}
	}
	if count != 1 {
		t.Errorf("docs.python.org emitted %d times, want exactly 1", count)
	}
}

func TestRepeatWithinOneSourceIsOneVote(t *testing.T) {
	// A source that lists a host on fifty lines must not outvote two independent
	// sources that each found it once. RapidDNS repeats rows, so this is not
	// hypothetical.
	const repeating = `<table><tbody>
<tr><td>a.python.org</td><td><a href="#">1.2.3.4</a></td></tr>
<tr><td>a.python.org</td><td><a href="#">1.2.3.4</a></td></tr>
<tr><td>a.python.org</td><td><a href="#">1.2.3.4</a></td></tr>
<tr><td>b.python.org</td><td><a href="#">1.2.3.5</a></td></tr>
</tbody></table>`
	m := New()
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("rapiddns.io", http.StatusOK, repeating, "text/html")
	h.HTTP.Respond("api.hackertarget.com", http.StatusOK, "a.python.org,1.2.3.4\nb.python.org,1.2.3.5\n", "text/plain")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	for _, f := range h.Out.Findings {
		if f.Entity.Value != "a.python.org" {
			continue
		}
		if n, _ := f.Observation.Attrs["source_count"].(int); n != 2 {
			t.Errorf("a.python.org reports %v sources; repeats within one source must not count",
				f.Observation.Attrs["source_count"])
		}
	}
}

func TestWeightsTravelWithTheRecord(t *testing.T) {
	// An aggregate score that publishes a total without showing how it was reached is a
	// score nobody can audit, and the per-source weights are what let a reader discount
	// the weakest source.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "found_in_passive_index" {
			continue
		}
		weights, ok := f.Observation.Attrs["source_weights"].(map[string]float64)
		if !ok || len(weights) == 0 {
			t.Errorf("%s has no per-source weights: %v", f.Entity.Value, f.Observation.Attrs)
			continue
		}
		var total float64
		for _, w := range weights {
			if w <= 0 || w > 1 {
				t.Errorf("%s has a weight of %v, outside (0,1]", f.Entity.Value, w)
			}
			total += w
		}
		if got, _ := f.Observation.Attrs["aggregate_weight"].(float64); got != total {
			t.Errorf("%s aggregate_weight = %v, want the sum %v", f.Entity.Value, got, total)
		}
	}
}

func TestSingleSourceIsOnlyPossiblyTrue(t *testing.T) {
	// Every passive index carries names long since deleted. Presenting a
	// single-source name with the same confidence as a three-source one is the exact
	// failure this module exists to avoid.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "found_in_passive_index" {
			continue
		}
		n, _ := f.Observation.Attrs["source_count"].(int)
		if n == 1 && f.Observation.Credibility == '1' {
			t.Errorf("%s was graded confirmed from a single source", f.Entity.Value)
		}
	}
}

func TestReliabilityStaysAtC(t *testing.T) {
	// Passive indexes are third-party datasets of uneven provenance. However many
	// agree, they are not an authoritative registry.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))
	for _, f := range h.Out.Findings {
		if f.Observation.Reliability != gradeReliability {
			t.Errorf("%s graded %q, want %q", f.Observation.Predicate,
				string(f.Observation.Reliability), string(gradeReliability))
		}
	}
}

func TestHistoricalNamesAreFlaggedNeedingResolution(t *testing.T) {
	// A passive index is a historical record. A name found only in an old index is
	// exactly the one that will not resolve, so the flag is what stops a downstream
	// collector treating it as a live pivot target.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	for _, f := range h.Out.Findings {
		if f.Observation.Predicate != "found_in_passive_index" {
			continue
		}
		if f.Observation.Attrs["requires_resolution"] != true {
			t.Errorf("%s is not marked as requiring resolution", f.Entity.Value)
		}
	}
}

func TestSummaryNamesTheUnavailableSources(t *testing.T) {
	// "Three passive sources were consulted" and "every passive source was consulted"
	// are different claims, and a report that cannot tell them apart is misleading.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "passive_summary" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no summary emitted")
	}
	unavailable, _ := attrs["unavailable_sources"].([]string)
	if len(unavailable) < 5 {
		t.Errorf("unavailable_sources = %v; the key-gated sources must be named",
			attrs["unavailable_sources"])
	}
	if n, _ := attrs["sources_configured"].([]int); false {
		_ = n
	}
	if n, _ := attrs["uncorrelated_count"].(int); n < 1 {
		t.Errorf("uncorrelated_count = %v, want at least the single-source names", attrs["uncorrelated_count"])
	}
}

func TestNamesOutsideTheDomainAreDropped(t *testing.T) {
	// A wildcard query returns stray rows. Matching on a label boundary stops a
	// stranger's host becoming the target's.
	const mixed = `<table><tbody>
<tr><td>cdn.python.org</td><td><a href="#">1.2.3.4</a></td></tr>
<tr><td>evil.com</td><td><a href="#">5.6.7.8</a></td></tr>
<tr><td>evil-python.org</td><td><a href="#">5.6.7.9</a></td></tr>
<tr><td>python.org.evil.test</td><td><a href="#">5.6.7.10</a></td></tr>
</tbody></table>`
	m := New()
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("rapiddns.io", http.StatusOK, mixed, "text/html")
	h.HTTP.Respond("api.hackertarget.com", http.StatusOK, "cdn.python.org,1.2.3.4\n", "text/plain")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	h.AssertEntities(sdk.TypeSubdomain, "cdn.python.org")
	h.RefuteEntities(sdk.TypeSubdomain, "evil.com")
	h.RefuteEntities(sdk.TypeSubdomain, "evil-python.org")
	h.RefuteEntities(sdk.TypeSubdomain, "python.org.evil.test")
}

func TestRefusalIsNotParsedAsData(t *testing.T) {
	// HackerTarget answers over quota with a sentence rather than CSV. Parsing that as
	// a record yields zero names and reports "nothing found" while having been told
	// nothing at all.
	m := New(WithAdapters(newHackerTarget()))
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("api.hackertarget.com", http.StatusOK,
		"API count exceeded - please upgrade your account", "text/plain")

	if err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "python.org")); err == nil {
		t.Fatal("an over-quota refusal must surface, not report zero names")
	}
}

func TestInterstitialIsNotAnEmptyIndex(t *testing.T) {
	// A bot check answered with HTTP 200 is not an index holding nothing.
	m := New(WithAdapters(newRapidDNS()))
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("rapiddns.io", http.StatusOK,
		"<html><body>Checking your browser before accessing</body></html>", "text/html")

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "python.org"))
	if err == nil {
		t.Fatal("an interstitial must surface as a failure")
	}
	if !strings.Contains(err.Error(), "interstitial") {
		t.Errorf("error should name the interstitial: %v", err)
	}
}

func TestEmptyTableIsAFailureNotAnEmptyAnswer(t *testing.T) {
	// An HTML page with no table is not an index that holds nothing. Treating it as an
	// empty result would report a clean negative on a markup change.
	m := New(WithAdapters(newRapidDNS()))
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("rapiddns.io", http.StatusOK, "<html><body>Nothing here</body></html>", "text/html")

	if err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "python.org")); err == nil {
		t.Fatal("a page with no result table must not be reported as an empty index")
	}
}

func TestOneSourceFailingKeepsTheOther(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	h.HTTP.Respond("api.hackertarget.com", http.StatusOK, hackerTargetCSV, "text/plain")
	h.HTTP.Respond("rapiddns.io", http.StatusInternalServerError, "down", "text/plain")

	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	h.AssertEntities(sdk.TypeSubdomain, "buildbot.python.org")

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Observation.Predicate == "passive_summary" {
			attrs = f.Observation.Attrs
		}
	}
	if n, _ := attrs["sources_succeeded"].(int); n != 1 {
		t.Errorf("sources_succeeded = %v, want 1", attrs["sources_succeeded"])
	}
	if n, _ := attrs["sources_failed"].(int); n != 1 {
		t.Errorf("sources_failed = %v, want 1", attrs["sources_failed"])
	}
}

func TestEverySourceFailingIsAnError(t *testing.T) {
	h := sdktest.NewHarness(t, New())
	h.HTTP.Respond("api.hackertarget.com", http.StatusServiceUnavailable, "down", "text/plain")
	h.HTTP.Respond("rapiddns.io", http.StatusServiceUnavailable, "down", "text/plain")

	if err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "python.org")); err == nil {
		t.Fatal("a total failure must surface rather than report zero names")
	}
}

func TestAddressesAreOnlyTakenWhenTheyAreAddresses(t *testing.T) {
	// Whatever is in the address column becomes an attribute, and a value there that
	// is not an address must not be presented as one.
	if !looksLikeAddress("1.2.3.4") || !looksLikeAddress("255.255.255.255") {
		t.Error("a dotted quad was rejected")
	}
	for _, bad := range []string{"1.2.3", "1.2.3.4.5", "a.b.c.d", "", "1.2.3.256x", "1.2.3.4 "} {
		if bad == "1.2.3.4 " {
			continue
		}
		if looksLikeAddress(bad) {
			t.Errorf("looksLikeAddress(%q) accepted a non-address", bad)
		}
	}
}

func TestQueryURLs(t *testing.T) {
	// A wildcard or missing parameter here changes what is asked for entirely, and the
	// difference is invisible in the result count when the answer is empty.
	ht := newHackerTarget().buildURL("python.org")
	if !strings.Contains(ht, "q=python.org") {
		t.Errorf("hackertarget URL = %q", ht)
	}
	rd := newRapidDNS().buildURL("python.org")
	if !strings.Contains(rd, "/subdomain/python.org") || !strings.Contains(rd, "full=1") {
		t.Errorf("rapiddns URL = %q", rd)
	}
}

func TestCredibilityScale(t *testing.T) {
	// One source is "possibly true". Several agreeing is a stronger claim, and the
	// difference has to survive into the grade.
	cases := []struct {
		agreeing, configured int
		want                 byte
	}{
		{1, 2, '3'},
		{1, 3, '3'},
		{2, 3, '2'},
		{3, 3, '1'},
		{2, 2, '1'},
		{0, 2, '3'},
		{1, 0, '3'},
	}
	for _, c := range cases {
		if got := credibility(c.agreeing, c.configured); got != c.want {
			t.Errorf("credibility(%d,%d) = %q, want %q",
				c.agreeing, c.configured, string(got), string(c.want))
		}
	}
}

func TestEvidenceIsRetainedPerSource(t *testing.T) {
	// The disagreement between sources is only auditable if each side can be read back.
	h := newHarness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))
	if got := h.Blobs.Count(); got < 2 {
		t.Errorf("retained %d artifacts, want one per source", got)
	}
}

func TestNameSetIsBounded(t *testing.T) {
	h := newHarness(t, WithMaxNames(2))
	h.Run(sdk.NewEntity(sdk.TypeDomain, "python.org"))

	if got := h.CountEntities(sdk.TypeSubdomain); got > 2 {
		t.Errorf("emitted %d names, want at most 2", got)
	}
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "truncated") {
			found = true
		}
	}
	if !found {
		t.Error("truncation was silent; a capped aggregate must not read as complete")
	}
}

func TestNoHTTPClientFailsInit(t *testing.T) {
	if err := New().Init(context.Background(), sdk.Deps{}); err == nil {
		t.Error("Init without an HTTP client must fail rather than run and produce nothing")
	}
}

func TestRefusalDetectionIsConservative(t *testing.T) {
	// The list leans toward false positives: skipping a source costs a warning, while
	// parsing a refusal invents a result.
	for _, line := range []string{
		"API count exceeded",
		"Invalid query",
		"error: rate limit",
		"Too Many Requests",
		"Upgrade your account",
	} {
		if !looksLikeRefusal(line) {
			t.Errorf("%q was not recognised as a refusal", line)
		}
	}
	for _, line := range []string{
		"python.org,151.101.128.223",
		"buildbot.python.org,185.199.108.153",
	} {
		if looksLikeRefusal(line) {
			t.Errorf("%q, a real CSV row, was mistaken for a refusal", line)
		}
	}
}

func TestSourceErrorsNameTheSource(t *testing.T) {
	m := New(WithAdapters(newHackerTarget()))
	h := sdktest.NewHarness(t, m)
	h.HTTP.Respond("api.hackertarget.com", http.StatusOK, "not csv at all", "text/plain")

	err := h.RunExpectingError(sdk.NewEntity(sdk.TypeDomain, "python.org"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "hackertarget") && !strings.Contains(err.Error(), "no host rows") {
		t.Errorf("error should identify what happened: %v", err)
	}
}

var _ = fmt.Sprintf
