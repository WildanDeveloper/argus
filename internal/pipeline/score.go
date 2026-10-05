// Package pipeline implements the streaming analysis stages: normalize, dedupe,
// resolve, correlate, score, enrich.
//
// The stages run sharded by hash(entity_id) so that all merges for one entity are
// serialized and the result is deterministic regardless of goroutine scheduling.
package pipeline

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// SourceGrade is one row of the Admiralty reliability table (§16.2).
type SourceGrade struct {
	Reliability byte
	Credibility byte
}

// DefaultAdmiralty returns the specification defaults for source reliability.
func DefaultAdmiralty() map[byte]float64 {
	return map[byte]float64{
		'A': 0.95, // completely reliable: authoritative registry, signed data
		'B': 0.85, // usually reliable: reputable API, CT logs
		'C': 0.70, // fairly reliable
		'D': 0.50, // not usually reliable
		'E': 0.25, // unreliable: heuristic, crowd-sourced, unverified
		'F': 0.40, // cannot be judged
	}
}

// DefaultCredibility returns the specification defaults for information
// credibility.
func DefaultCredibility() map[byte]float64 {
	return map[byte]float64{
		'1': 1.00, // confirmed by independent sources
		'2': 0.85, // probably true
		'3': 0.65, // possibly true
		'4': 0.40, // doubtful
		'5': 0.15, // improbable
		'6': 0.50, // cannot be judged
	}
}

// ScoreConfig configures the scorer.
type ScoreConfig struct {
	Reliability map[byte]float64
	Credibility map[byte]float64
	// GroupOf maps a source string to an independence group. Sources that resell
	// or mirror the same underlying data must land in the same group, or the
	// Noisy-OR double-counts one piece of evidence as several corroborating ones.
	GroupOf func(source string) string
	// HalfLife controls freshness decay.
	HalfLife time.Duration
	// ConflictPenalty is applied per unit of conflict ratio.
	ConflictPenalty float64
	// PerSourceWeights override the table for specific modules.
	PerSourceWeights map[string]float64
	// Cap is the maximum confidence any entity may reach.
	Cap float64
}

// DefaultScoreConfig returns the specification defaults.
func DefaultScoreConfig() ScoreConfig {
	return ScoreConfig{
		Reliability:      DefaultAdmiralty(),
		Credibility:      DefaultCredibility(),
		HalfLife:         720 * time.Hour, // 30 days
		ConflictPenalty:  0.25,
		PerSourceWeights: map[string]float64{},
		Cap:              0.999,
	}
}

// WithGroups returns a copy of the config using the supplied independence groups.
// The specification's example groups resellers of the same dataset together.
func (c ScoreConfig) WithGroups(groups map[string][]string) ScoreConfig {
	if len(groups) == 0 {
		if c.GroupOf == nil {
			c.GroupOf = func(s string) string { return s }
		}
		return c
	}
	member := map[string]string{}
	for group, sources := range groups {
		for _, s := range sources {
			member[s] = group
		}
	}
	c.GroupOf = func(source string) string {
		if g, ok := member[source]; ok {
			return g
		}
		return source
	}
	return c
}

// Evidence is one observation as the scorer sees it. The scorer never mutates it.
type Evidence struct {
	Source      string
	Reliability byte
	Credibility byte
	ObservedAt  time.Time
	// Method scales the weight: 1.0 for a direct observation, below that for a
	// heuristic.
	Method float64
	// Conflict marks an observation that contradicts another observation about
	// the same fact.
	Conflict bool
	// Verified marks evidence backed by a retrievable artifact. A finding with
	// no artifact is "unverified" and is capped, per the evidence-first
	// principle.
	Verified bool
}

// ConfidenceInput is the full set of evidence for one entity or relation.
type ConfidenceInput struct {
	Evidence []Evidence
	// Conflicts is the number of evidence items flagged as contradictory.
	Conflicts int
	// HasArtifact reports whether at least one observation is backed by a
	// retrievable artifact.
	HasArtifact bool
}

// maxUnverifiedCap is the ceiling applied when no observation carries evidence.
// The specification's evidence-first principle: a finding with no retrievable
// source artifact is flagged unverified and capped in confidence. A cap of 0.5
// keeps it above "unusable" while ensuring it never reaches the threshold that
// would drive an alert.
const maxUnverifiedCap = 0.5

// Confidence computes a confidence in [0, Cap] from a set of observations.
//
// The formula, from §16.3:
//
//	w_i    = R(source_i) x C(obs_i) x decay(age_i) x method_factor_i
//	w_g    = max(w_i for i in group g)
//	conf   = 1 - PRODUCT_g (1 - w_g)          Noisy-OR over independent groups
//	decay  = 0.5 ^ (age / half_life)
//	final  = conf x (1 - conflict_penalty x conflict_ratio)
//
// Independence grouping is the part that is easy to get wrong. Three passive-DNS
// resellers all showing the same historical A record is one piece of evidence,
// not three, and without grouping the Noisy-OR would push confidence toward 1 on
// the strength of a single upstream observation.
func Confidence(in ConfidenceInput, now time.Time, cfg ScoreConfig) float64 {
	if len(in.Evidence) == 0 {
		return 0
	}
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = 720 * time.Hour
	}
	if cfg.Cap <= 0 {
		cfg.Cap = 0.999
	}
	groupOf := cfg.GroupOf
	if groupOf == nil {
		groupOf = func(s string) string { return s }
	}

	best := make(map[string]float64, len(in.Evidence))
	for _, e := range in.Evidence {
		w := cfg.Reliability[e.Reliability] * cfg.Credibility[e.Credibility]
		if w == 0 {
			// Unknown grade. Fail to the conservative default rather than to
			// zero: an unrecognised grade means the module declared something new,
			// and zero would silently erase a real observation.
			w = 0.40 * 0.50
		}
		if ov, ok := cfg.PerSourceWeights[e.Source]; ok {
			w *= ov
		}
		method := e.Method
		if method <= 0 {
			method = 1.0
		}
		w *= method
		w *= decay(now.Sub(e.ObservedAt), cfg.HalfLife)
		w = math.Min(math.Max(w, 0), 0.999)

		g := groupOf(e.Source)
		if w > best[g] {
			best[g] = w
		}
	}

	miss := 1.0
	for _, w := range best {
		miss *= 1 - w
	}
	conf := 1 - miss

	// Conflict penalty. The ratio is conflicts/total so that a single
	// contradiction among many corroborating observations costs little, while a
	// dataset that is half contradiction loses half its confidence.
	if in.Conflicts > 0 && len(in.Evidence) > 0 {
		ratio := float64(in.Conflicts) / float64(len(in.Evidence))
		if ratio > 1 {
			ratio = 1
		}
		p := cfg.ConflictPenalty
		if p == 0 {
			p = 0.25
		}
		conf *= 1 - p*ratio
	}

	if !in.HasArtifact {
		if conf > maxUnverifiedCap {
			conf = maxUnverifiedCap
		}
	}
	if conf > cfg.Cap {
		conf = cfg.Cap
	}
	return conf
}

// decay is the freshness factor. A future timestamp (clock skew between us and a
// provider) must not exceed 1, so negative ages return 1.
func decay(age time.Duration, halfLife time.Duration) float64 {
	if age <= 0 {
		return 1
	}
	return math.Pow(0.5, float64(age)/float64(halfLife))
}

// Explain renders a human-readable breakdown of a confidence computation. Every
// merge, score, and pivot must carry a reason the analyst can read (§2).
func Explain(in ConfidenceInput, now time.Time, cfg ScoreConfig) []string {
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = 720 * time.Hour
	}
	groupOf := cfg.GroupOf
	if groupOf == nil {
		groupOf = func(s string) string { return s }
	}

	type groupInfo struct {
		weight  float64
		source  string
		age     time.Duration
		method  float64
		contrib int
	}
	groups := map[string]*groupInfo{}
	order := []string{}

	for _, e := range in.Evidence {
		w := cfg.Reliability[e.Reliability] * cfg.Credibility[e.Credibility]
		method := e.Method
		if method <= 0 {
			method = 1.0
		}
		w *= method
		w *= decay(now.Sub(e.ObservedAt), cfg.HalfLife)
		w = math.Min(math.Max(w, 0), 0.999)

		g := groupOf(e.Source)
		gi, ok := groups[g]
		if !ok {
			gi = &groupInfo{source: e.Source, method: method}
			groups[g] = gi
			order = append(order, g)
		}
		gi.contrib++
		if w > gi.weight {
			gi.weight, gi.source, gi.age, gi.method = w, e.Source, now.Sub(e.ObservedAt), method
		}
	}

	sort.Strings(order)
	out := make([]string, 0, len(order)+5)
	for _, g := range order {
		gi := groups[g]
		out = append(out, fmt.Sprintf(
			"group %-24s w=%.4f from %s (age %s, method %.2f, %d observation(s) collapsed)",
			g, gi.weight, gi.source, shortDur(gi.age), gi.method, gi.contrib))
	}
	conf := Confidence(in, now, cfg)
	out = append(out, fmt.Sprintf("noisy-OR over %d independent group(s) = %.4f", len(order), conf))
	if in.Conflicts > 0 {
		out = append(out, fmt.Sprintf("conflict penalty: %d of %d observations contradict -> factor %.4f",
			in.Conflicts, len(in.Evidence), conflictFactor(in.Conflicts, len(in.Evidence), cfg.ConflictPenalty)))
	}
	if !in.HasArtifact {
		out = append(out, fmt.Sprintf("no retrievable artifact -> capped at %.2f (unverified)", maxUnverifiedCap))
	}
	out = append(out, fmt.Sprintf("final confidence %.4f", conf))
	return out
}

func conflictFactor(conflicts, total int, penalty float64) float64 {
	if total == 0 || conflicts == 0 {
		return 1
	}
	if penalty == 0 {
		penalty = 0.25
	}
	ratio := float64(conflicts) / float64(total)
	if ratio > 1 {
		ratio = 1
	}
	return 1 - penalty*ratio
}

func shortDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
}

// GradeLabel renders an Admiralty pair, e.g. "B2".
func GradeLabel(rel, cred byte) string {
	return string(rel) + string(cred)
}

// EntityConfidence converts stored observations into evidence and scores them.
// This is the bridge between the store and the scorer.
func EntityConfidence(e sdk.Entity, obs []sdk.Observation, now time.Time, cfg ScoreConfig) (float64, []string) {
	in := ConfidenceInput{}
	for _, o := range obs {
		in.Evidence = append(in.Evidence, Evidence{
			Source:      o.Source.String(),
			Reliability: o.Reliability,
			Credibility: o.Credibility,
			ObservedAt:  o.ObservedAt,
			Method:      methodFactor(o),
			Conflict:    o.Attrs["conflict"] == true,
			Verified:    len(o.Evidence) > 0,
		})
		if len(o.Evidence) > 0 {
			in.HasArtifact = true
		}
		if o.Attrs["conflict"] == true {
			in.Conflicts++
		}
	}
	return Confidence(in, now, cfg), Explain(in, now, cfg)
}

// methodFactor derives the method multiplier from an observation. An
// observation whose attrs mark it heuristic gets a penalty, which keeps inferred
// facts below directly observed ones without needing a separate field.
func methodFactor(o sdk.Observation) float64 {
	if o.Attrs == nil {
		return 1.0
	}
	if v, ok := o.Attrs["heuristic"].(bool); ok && v {
		return 0.6
	}
	if v, ok := o.Attrs["method_factor"].(float64); ok && v > 0 && v <= 1 {
		return v
	}
	return 1.0
}
