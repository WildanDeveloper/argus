package pipeline

import (
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Config configures a pipeline.
type Config struct {
	Logger *slog.Logger
	Now    func() time.Time
	Score  ScoreConfig
	// Shards serializes merges per entity. Stages are sharded by
	// hash(entity_id) so all work for one entity happens in one goroutine, which is
	// what makes a concurrent scan produce the same graph as a sequential one.
	Shards int
}

// DefaultConfig returns the specification defaults.
func DefaultConfig() Config {
	return Config{
		Logger: slog.Default(),
		Now:    time.Now,
		Score:  DefaultScoreConfig().WithGroups(defaultIndependenceGroups),
		Shards: 4,
	}
}

// defaultIndependenceGroups are the specification's example groups: sources that
// resell the same underlying data must be counted once.
var defaultIndependenceGroups = map[string][]string{
	"passive_dns": {"securitytrails", "virustotal", "circl", "dnsdb", "otx"},
	"ct_logs":     {"crtsh", "certspotter", "censys-certs", "facebook-ct"},
	"scan_db":     {"shodan", "censys", "zoomeye", "fofa", "binaryedge", "netlas"},
	"whois":       {"whois-iana", "whois-arin", "whois-ripe", "whois-apnic", "whois-lacnic"},
	"geolocation": {"maxmind", "ipinfo", "ipapi", "dbip"},
	"blocklists":  {"abuseipdb", "greynoise", "spamhaus", "pulsedive"},
}

// ErrNoPipeline is returned when a nil pipeline is used.
var ErrNoPipeline = errors.New("pipeline: nil")

// Pipeline runs the analysis stages over an entity stream.
type Pipeline struct {
	cfg   Config
	stats StageStats
}

// StageStats counts what each stage did, for the metrics endpoint.
type StageStats struct {
	Normalized int
	Deduped    int
	Resolved   int
	Correlated int
	Scored     int
	Enriched   int
	Aliases    int
	Conflicts  int
}

// New builds a pipeline.
func New(cfg Config) (*Pipeline, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Shards <= 0 {
		cfg.Shards = 4
	}
	if cfg.Score.Reliability == nil {
		cfg.Score = DefaultScoreConfig().WithGroups(defaultIndependenceGroups)
	}
	return &Pipeline{cfg: cfg}, nil
}

// Config returns the pipeline configuration.
func (p *Pipeline) Config() Config { return p.cfg }

// Stats returns stage counters.
func (p *Pipeline) Stats() StageStats { return p.stats }

// ScoredBatch is the result of scoring.
type ScoredBatch struct {
	Entities  []sdk.Entity
	Relations []sdk.Relation
	// Explanations carries the human-readable score breakdown per entity, keyed by
	// entity ID, so `argus show entity --explain` and reports can show why a
	// number is what it is.
	Explanations map[sdk.EntityID][]string
}

// ScoreBatch computes confidence for a batch of entities from their observations.
//
// The scorer owns confidence. No module may set it, and no store write may carry
// a number that was not produced here, so that every confidence in the system has
// the same provenance and the same explanation.
func (p *Pipeline) ScoreBatch(entities []sdk.Entity, observations []sdk.Observation, relations []sdk.Relation) ScoredBatch {
	now := p.cfg.Now()
	bySubject := groupBySubject(observations)

	out := ScoredBatch{
		Entities:     make([]sdk.Entity, 0, len(entities)),
		Explanations: make(map[sdk.EntityID][]string, len(entities)),
	}
	index := make(map[sdk.EntityID]int, len(entities))
	for _, e := range entities {
		index[e.ID] = len(out.Entities)
		out.Entities = append(out.Entities, e)
	}

	for i := range out.Entities {
		e := &out.Entities[i]
		conf, lines := EntityConfidence(*e, bySubject[e.ID], now, p.cfg.Score)
		e.Confidence = conf
		out.Explanations[e.ID] = lines
	}
	p.stats.Scored += len(out.Entities)

	// A relation's confidence is derived from the entities it joins: an edge is
	// only as trustworthy as its weakest endpoint, since a fact about an
	// unverified entity cannot be a verified fact about what it connects to.
	confByID := make(map[sdk.EntityID]float64, len(out.Entities))
	for _, e := range out.Entities {
		confByID[e.ID] = e.Confidence
	}
	out.Relations = make([]sdk.Relation, 0, len(relations))
	for _, r := range relations {
		if r.Confidence > 0 {
			out.Relations = append(out.Relations, r)
			continue
		}
		from := confByID[r.From]
		to := confByID[r.To]
		missing := 0.0
		if _, ok := confByID[r.From]; !ok {
			missing = 0.5
		}
		if _, ok := confByID[r.To]; !ok {
			missing = 0.5
		}
		base := from
		if to < base {
			base = to
		}
		conf := base
		if missing > 0 {
			// An endpoint outside this batch is unknown, not disproven. Score it at
			// neutral rather than discarding the edge.
			conf = base*(1-missing) + 0.5*missing
		}
		if r.Heuristic && conf > 0.6 {
			// A heuristic edge is an inference; capping it keeps inference from
			// being read as verification.
			conf = 0.6
		}
		r.Confidence = conf
		out.Relations = append(out.Relations, r)
	}
	return out
}

func groupBySubject(obs []sdk.Observation) map[sdk.EntityID][]sdk.Observation {
	out := make(map[sdk.EntityID][]sdk.Observation, len(obs))
	for _, o := range obs {
		out[o.Subject] = append(out[o.Subject], o)
	}
	return out
}

// Normalize canonicalizes a batch and records aliases rather than merging them.
//
// Provider-aware email aliasing (googlemail.com and gmail.com, plus-addressing)
// is recorded as an alias relation, never silently merged: an analyst who cannot
// see why two addresses were joined cannot correct the join.
func (p *Pipeline) Normalize(entities []sdk.Entity, observations []sdk.Observation) ([]sdk.Entity, []sdk.Relation) {
	p.stats.Normalized += len(entities)

	byValue := make(map[string][]sdk.Entity, len(entities))
	for _, e := range entities {
		byValue[string(e.Type)+"\x00"+e.Value] = append(byValue[string(e.Type)+"\x00"+e.Value], e)
	}

	var relations []sdk.Relation
	seen := map[string]bool{}
	for _, e := range entities {
		for _, alias := range aliasCandidates(e) {
			matches, ok := byValue[string(e.Type)+"\x00"+alias]
			if !ok {
				continue
			}
			for _, m := range matches {
				if m.ID == e.ID {
					continue
				}
				key := string(m.ID) + ">" + string(e.ID)
				if seen[key] {
					continue
				}
				seen[key] = true
				relations = append(relations, sdk.Rel(m.ID, e.ID, sdk.RelAliasOf))
				p.stats.Aliases++
			}
		}
	}
	return entities, relations
}

// aliasCandidates returns values an entity might be an alias of. It is
// deliberately conservative: only equivalences that are actually true in the
// relevant platform's rules are proposed, and each is still only a proposal.
func aliasCandidates(e sdk.Entity) []string {
	switch e.Type {
	case sdk.TypeEmail:
		at := -1
		for i := len(e.Value) - 1; i >= 0; i-- {
			if e.Value[i] == '@' {
				at = i
				break
			}
		}
		if at < 0 {
			return nil
		}
		local, domain := e.Value[:at], e.Value[at+1:]
		var out []string
		// Plus-addressing: user+tag@example.com is the same mailbox at many
		// providers, but not all, so this is a proposal rather than an identity.
		if plus := indexByte(local, '+'); plus > 0 {
			out = append(out, local[:plus]+"@"+domain)
		}
		// Consumer-domain equivalence for the two well-known pairs.
		switch domain {
		case "gmail.com":
			out = append(out, local+"@googlemail.com")
		case "googlemail.com":
			out = append(out, local+"@gmail.com")
		}
		return out
	}
	return nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// Dedupe removes repeated observations. Redelivery is expected under
// at-least-once delivery, so this is a correctness requirement, not an
// optimization: without it a retried task doubles every row.
func (p *Pipeline) Dedupe(observations []sdk.Observation) []sdk.Observation {
	seen := make(map[string]struct{}, len(observations))
	out := make([]sdk.Observation, 0, len(observations))
	for _, o := range observations {
		if o.ID == "" {
			o.ID = sdk.ObservationID(o.Source.String(), string(o.Subject), o.Predicate, o.Object, o.ValidFrom)
		}
		if _, dup := seen[o.ID]; dup {
			p.stats.Deduped++
			continue
		}
		seen[o.ID] = struct{}{}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].ObservedAt.Before(out[j].ObservedAt)
	})
	return out
}

// DetectConflicts flags observations about the same predicate that assert
// different objects. The entity keeps both values with their provenance; only the
// confidence is reduced, and the disagreement stays visible.
func (p *Pipeline) DetectConflicts(observations []sdk.Observation) []sdk.Observation {
	type key struct {
		subject   sdk.EntityID
		predicate string
	}
	groups := map[key][]int{}
	for i, o := range observations {
		groups[key{o.Subject, o.Predicate}] = append(groups[key{o.Subject, o.Predicate}], i)
	}
	out := append([]sdk.Observation(nil), observations...)
	for _, idx := range groups {
		if len(idx) < 2 {
			continue
		}
		distinct := map[string]bool{}
		for _, i := range idx {
			distinct[sdk.ObservationID("obj", "", "", out[i].Object, nil)] = true
		}
		if len(distinct) < 2 {
			continue
		}
		for _, i := range idx {
			if out[i].Attrs == nil {
				out[i].Attrs = map[string]any{}
			}
			out[i].Attrs["conflict"] = true
		}
		p.stats.Conflicts += len(idx)
	}
	return out
}
