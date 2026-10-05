package pipeline

import (
	"math"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func TestConfidenceWorkedExampleFromSpec(t *testing.T) {
	// The specification's worked example: subdomain seen by ct-search (B,2) and
	// passive-dns (B,2), both fresh, in different independence groups.
	//
	//   w_ct   = 0.85 x 0.85 = 0.7225
	//   w_pdns = 0.85 x 0.85 = 0.7225
	//   confidence = 1 - (1 - 0.7225)^2 = 0.923
	cfg := DefaultScoreConfig()
	in := ConfidenceInput{
		HasArtifact: true,
		Evidence: []Evidence{
			{Source: "ct-search/crtsh", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
			{Source: "passive-dns/securitytrails", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
		},
	}
	got := Confidence(in, now, cfg)
	want := 1 - math.Pow(1-0.7225, 2)
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("confidence = %.6f, want %.6f", got, want)
	}
	// The spec rounds to 0.923.
	if math.Abs(got-0.923) > 0.0005 {
		t.Errorf("confidence %.4f does not match the documented 0.923", got)
	}
}

func TestIndependenceGroupingPreventsDoubleCounting(t *testing.T) {
	// The property the whole Noisy-OR depends on: three resellers of the same
	// passive-DNS dataset are one piece of evidence, not three.
	cfg := DefaultScoreConfig().WithGroups(map[string][]string{
		"passive_dns": {"passive-dns/securitytrails", "passive-dns/virustotal", "passive-dns/circl"},
	})

	in := ConfidenceInput{
		HasArtifact: true,
		Evidence: []Evidence{
			{Source: "passive-dns/securitytrails", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
			{Source: "passive-dns/virustotal", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
			{Source: "passive-dns/circl", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
		},
	}
	withGroups := Confidence(in, now, cfg)

	unguarded := DefaultScoreConfig()
	withoutGroups := Confidence(in, now, unguarded)

	if withGroups >= withoutGroups {
		t.Errorf("grouping must lower confidence: grouped %.4f vs ungrouped %.4f", withGroups, withoutGroups)
	}
	// All three in one group means the strongest single weight only: 0.7225.
	if math.Abs(withGroups-0.7225) > 1e-9 {
		t.Errorf("grouped confidence = %.6f, want 0.7225 (max of the group)", withGroups)
	}

	// A source in a NEW group must still raise it, and must raise it in a
	// predictable way.
	in.Evidence = append(in.Evidence, Evidence{
		Source: "ct-search/crtsh", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1,
	})
	withNewGroup := Confidence(in, now, cfg)
	if withNewGroup <= withGroups {
		t.Error("an independent group must raise confidence")
	}
	wantNew := 1 - math.Pow(1-0.7225, 2)
	if math.Abs(withNewGroup-wantNew) > 1e-9 {
		t.Errorf("new-group confidence = %.6f, want %.6f", withNewGroup, wantNew)
	}
}

func TestFreshnessDecay(t *testing.T) {
	cfg := DefaultScoreConfig() // 720h half-life
	mk := func(age time.Duration) float64 {
		return Confidence(ConfidenceInput{
			HasArtifact: true,
			Evidence:    []Evidence{{Source: "rdap", Reliability: 'B', Credibility: '2', ObservedAt: now.Add(-age), Method: 1}},
		}, now, cfg)
	}

	fresh := mk(0)
	oneHalf := mk(720 * time.Hour)
	twoHalf := mk(1440 * time.Hour)

	// One half-life halves the weight, so (1-w) grows and confidence falls.
	if oneHalf >= fresh {
		t.Errorf("aged evidence must score lower: fresh %.4f, half-life %.4f", fresh, oneHalf)
	}
	if oneHalf >= 1 {
		t.Errorf("confidence must stay below 1: %.4f", oneHalf)
	}
	// Half the weight => w = 0.7225/2 = 0.36125.
	wantHalf := 0.36125
	if math.Abs(oneHalf-wantHalf) > 1e-6 {
		t.Errorf("one half-life confidence = %.6f, want %.6f", oneHalf, wantHalf)
	}
	if twoHalf >= oneHalf {
		t.Error("two half-lives must score below one")
	}
	// Sanity: 0.85*0.85 = 0.7225; half of that is 0.36125.
	if math.Abs(fresh-0.7225) > 1e-9 {
		t.Errorf("fresh confidence = %.6f, want 0.7225", fresh)
	}
}

func TestFutureTimestampsDoNotInflateConfidence(t *testing.T) {
	// A provider whose clock runs ahead must not be able to make its evidence
	// fresher than fresh.
	cfg := DefaultScoreConfig()
	future := Confidence(ConfidenceInput{
		HasArtifact: true,
		Evidence:    []Evidence{{Source: "rdap", Reliability: 'B', Credibility: '2', ObservedAt: now.Add(72 * time.Hour), Method: 1}},
	}, now, cfg)
	fresh := Confidence(ConfidenceInput{
		HasArtifact: true,
		Evidence:    []Evidence{{Source: "rdap", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1}},
	}, now, cfg)
	if future > fresh+1e-12 {
		t.Errorf("future observation scored higher (%.6f > %.6f)", future, fresh)
	}
}

func TestConflictPenalty(t *testing.T) {
	cfg := DefaultScoreConfig()
	agree := Confidence(ConfidenceInput{
		HasArtifact: true,
		Evidence: []Evidence{
			{Source: "ip-geo/maxmind", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
			{Source: "ip-geo/ipinfo", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
		},
	}, now, cfg)

	// Two geolocation providers disagreeing by more than the configured
	// threshold: keep both values, reduce confidence.
	conflict := Confidence(ConfidenceInput{
		HasArtifact: true,
		Conflicts:   1,
		Evidence: []Evidence{
			{Source: "ip-geo/maxmind", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
			{Source: "ip-geo/ipinfo", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1, Conflict: true},
		},
	}, now, cfg)
	if conflict >= agree {
		t.Errorf("conflict must reduce confidence: %.4f vs %.4f", conflict, agree)
	}

	// A minor conflict among many corroborating observations costs little.
	many := make([]Evidence, 0, 10)
	for i := 0; i < 10; i++ {
		many = append(many, Evidence{Source: "src-" + string(rune('a'+i)), Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1})
	}
	oneConflict := Confidence(ConfidenceInput{HasArtifact: true, Conflicts: 1, Evidence: many}, now, cfg)
	if oneConflict < 0.9 {
		t.Errorf("one conflict among ten should barely dent confidence, got %.4f", oneConflict)
	}
}

func TestEvidenceFirstCap(t *testing.T) {
	// Evidence-first: a finding with no retrievable artifact is unverified and
	// must be capped, however many sources assert it.
	cfg := DefaultScoreConfig()
	var ev []Evidence
	for i := 0; i < 8; i++ {
		ev = append(ev, Evidence{Source: "src-" + string(rune('a'+i)), Reliability: 'A', Credibility: '1', ObservedAt: now, Method: 1})
	}
	withArtifact := Confidence(ConfidenceInput{HasArtifact: true, Evidence: ev}, now, cfg)
	without := Confidence(ConfidenceInput{HasArtifact: false, Evidence: ev}, now, cfg)

	if withArtifact <= 0.99 {
		t.Errorf("eight independent authoritative sources should exceed 0.99, got %.4f", withArtifact)
	}
	if without > maxUnverifiedCap+1e-9 {
		t.Errorf("unverified confidence %.4f must be capped at %.2f", without, maxUnverifiedCap)
	}
	if without >= withArtifact {
		t.Error("removing evidence must not raise confidence")
	}
}

func TestHeuristicPenalty(t *testing.T) {
	cfg := DefaultScoreConfig()
	direct := Confidence(ConfidenceInput{
		HasArtifact: true,
		Evidence:    []Evidence{{Source: "dns-records/dns", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1}},
	}, now, cfg)
	heuristic := Confidence(ConfidenceInput{
		HasArtifact: true,
		Evidence:    []Evidence{{Source: "correlator", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 0.6}},
	}, now, cfg)
	if heuristic >= direct {
		t.Errorf("a heuristic edge must score below a direct observation: %.4f vs %.4f", heuristic, direct)
	}
}

func TestUnknownGradeFallsBackConservative(t *testing.T) {
	// A module that declares an unrecognised grade must not have its observation
	// silently erased (weight 0) nor treated as authoritative.
	cfg := DefaultScoreConfig()
	got := Confidence(ConfidenceInput{
		HasArtifact: true,
		Evidence:    []Evidence{{Source: "newmod", Reliability: 'Z', Credibility: '9', ObservedAt: now, Method: 1}},
	}, now, cfg)
	if got <= 0 {
		t.Errorf("unknown grade produced zero confidence; the observation was erased")
	}
	if got >= 0.95 {
		t.Errorf("unknown grade %.4f was treated as authoritative", got)
	}
}

func TestEmptyEvidenceIsZero(t *testing.T) {
	if got := Confidence(ConfidenceInput{}, now, DefaultScoreConfig()); got != 0 {
		t.Errorf("empty evidence should score 0, got %.4f", got)
	}
}

func TestConfidenceIsBounded(t *testing.T) {
	cfg := DefaultScoreConfig()
	var ev []Evidence
	for i := 0; i < 200; i++ {
		ev = append(ev, Evidence{Source: "s" + string(rune(i%26)) + string(rune('a'+i/26)), Reliability: 'A', Credibility: '1', ObservedAt: now, Method: 1})
	}
	got := Confidence(ConfidenceInput{HasArtifact: true, Evidence: ev}, now, cfg)
	if got >= 1 {
		t.Errorf("confidence %.6f must stay strictly below 1", got)
	}
	if got < 0 || got > cfg.Cap {
		t.Errorf("confidence %.6f out of range", got)
	}
}

func TestExplainIsReadable(t *testing.T) {
	cfg := DefaultScoreConfig().WithGroups(map[string][]string{
		"passive_dns": {"passive-dns/securitytrails", "passive-dns/virustotal"},
	})
	in := ConfidenceInput{
		HasArtifact: true,
		Evidence: []Evidence{
			{Source: "ct-search/crtsh", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
			{Source: "passive-dns/securitytrails", Reliability: 'B', Credibility: '2', ObservedAt: now.Add(-48 * time.Hour), Method: 1},
			{Source: "passive-dns/virustotal", Reliability: 'B', Credibility: '2', ObservedAt: now, Method: 1},
		},
	}
	lines := Explain(in, now, cfg)
	if len(lines) < 3 {
		t.Fatalf("explanation too short: %v", lines)
	}
	joined := ""
	for _, l := range lines {
		joined += l + "\n"
	}
	// Explain must name the groups, the collapse, and the final number: that is
	// what makes a score auditable rather than a black box.
	for _, want := range []string{"group", "passive_dns", "collapsed", "noisy-OR", "final confidence"} {
		if !contains(joined, want) {
			t.Errorf("explanation missing %q:\n%s", want, joined)
		}
	}
	// The group that collapsed two sources must say so.
	if !contains(joined, "2 observation(s) collapsed") {
		t.Errorf("expected a collapsed-source note:\n%s", joined)
	}
}

func TestEntityConfidenceBridgesStoreToScorer(t *testing.T) {
	sub := sdk.NewEntity(sdk.TypeSubdomain, "dev.acme.example")
	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")

	src := sdk.Source{Module: "dns-records", Provider: "dns", Method: "lookup"}
	obs := []sdk.Observation{
		{
			Subject: ip.ID, Predicate: "resolves_to", Source: src,
			Reliability: 'B', Credibility: '2', ObservedAt: now,
			Evidence: []sdk.EvidenceRef{{ID: "01J", SHA256: "abc"}},
		},
		{
			Subject: ip.ID, Predicate: "resolves_to",
			Source:      sdk.Source{Module: "passive-dns", Provider: "securitytrails", Method: "api"},
			Reliability: 'B', Credibility: '2', ObservedAt: now,
		},
	}
	conf, lines := EntityConfidence(ip, obs, now, DefaultScoreConfig())
	if conf <= 0 || conf >= 1 {
		t.Errorf("confidence %.4f out of range", conf)
	}
	if len(lines) == 0 {
		t.Error("EntityConfidence should return an explanation")
	}
	_ = sub
}

func TestMethodFactorFromAttrs(t *testing.T) {
	if methodFactor(sdk.Observation{}) != 1.0 {
		t.Error("a plain observation should have method factor 1.0")
	}
	h := sdk.Observation{Attrs: map[string]any{"heuristic": true}}
	if methodFactor(h) >= 1.0 {
		t.Error("a heuristic observation must be penalized")
	}
	f := sdk.Observation{Attrs: map[string]any{"method_factor": 0.75}}
	if math.Abs(methodFactor(f)-0.75) > 1e-9 {
		t.Errorf("explicit method_factor ignored: %.3f", methodFactor(f))
	}
}

func TestGradeLabel(t *testing.T) {
	if GradeLabel('B', '2') != "B2" {
		t.Errorf("GradeLabel = %q", GradeLabel('B', '2'))
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
