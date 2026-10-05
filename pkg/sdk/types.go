package sdk

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EntityID is the stable identity of a real-world thing. It is derived from the
// entity type plus the canonical value (ADR-009), so it is identical across
// scans, sources, machines, and workers.
type EntityID string

// NewEntityID hashes a type and an already-canonical value.
//
// The domain separator (a zero byte) prevents collisions between, say, the
// domain "ab" and any future concatenation of type and value that would produce
// the same byte stream.
func NewEntityID(t EntityType, canonical string) EntityID {
	h := sha256.New()
	h.Write([]byte(t))
	h.Write([]byte{0})
	h.Write([]byte(canonical))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))
	return EntityID(strings.ToLower(enc[:26]))
}

// Attr is one merged attribute together with the observations that support it.
// Argus never overwrites an attribute: a new value supersedes the old one and
// the change becomes a diff.
type Attr struct {
	Value any
	Obs   []string // observation IDs supporting this value
}

// ObservationID derives the identity of an observation. Two collectors that
// report the same fact about the same subject produce the same ID, which makes
// upserts idempotent under at-least-once delivery.
func ObservationID(source, subject, predicate string, object any, validFrom *time.Time) string {
	h := sha256.New()
	h.Write([]byte(source))
	h.Write([]byte{0})
	h.Write([]byte(subject))
	h.Write([]byte{0})
	h.Write([]byte(predicate))
	h.Write([]byte{0})
	h.Write([]byte(stableString(object)))
	h.Write([]byte{0})
	if validFrom != nil {
		h.Write([]byte(validFrom.UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// stableString renders any JSON-ish value deterministically. Map iteration in
// Go is randomized, so maps must be sorted by key before hashing.
func stableString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case []string:
		s := append([]string(nil), t...)
		sort.Strings(s)
		return strings.Join(s, "\x1f")
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = stableString(e)
		}
		return strings.Join(parts, "\x1e")
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(0x1d)
			}
			b.WriteString(k)
			b.WriteByte(0x1c)
			b.WriteString(stableString(t[k]))
		}
		return b.String()
	}
	return fmt.Sprint(v)
}

// Entity is the aggregate view of everything Argus has observed about a thing.
// It is a projection: the durable facts are the observations.
type Entity struct {
	ID          EntityID
	Type        EntityType
	Value       string // canonical form
	Display     string // original or pretty form
	Attrs       map[string]Attr
	Tags        []string
	Confidence  float64 // derived by the scorer; modules must never set it
	Sensitivity Sensitivity
	FirstSeen   time.Time
	LastSeen    time.Time
}

// NewEntity canonicalizes value and derives a stable ID. Prefer this over
// constructing an Entity literal: it guarantees Value is canonical and ID
// matches it.
func NewEntity(t EntityType, value string) Entity {
	c, err := Canonicalize(t, value)
	if err != nil {
		return Entity{}
	}
	return Entity{
		ID:    NewEntityID(t, c),
		Type:  t,
		Value: c,
		Attrs: map[string]Attr{},
		Tags:  []string{},
	}
}

// NewEntityOrErr is NewEntity with the canonicalization error surfaced.
func NewEntityOrErr(t EntityType, value string) (Entity, error) {
	c, err := Canonicalize(t, value)
	if err != nil {
		return Entity{}, err
	}
	return Entity{
		ID:    NewEntityID(t, c),
		Type:  t,
		Value: c,
		Attrs: map[string]Attr{},
		Tags:  []string{},
	}, nil
}

// NewFileEntity derives an identity from content, per Appendix A.
func NewFileEntity(b []byte) Entity {
	sum := contentID(b)
	return Entity{ID: NewEntityID(TypeFile, sum), Type: TypeFile, Value: sum, Attrs: map[string]Attr{}, Tags: []string{}}
}

// NewImageEntity derives an identity from image content.
func NewImageEntity(b []byte) Entity {
	sum := contentID(b)
	return Entity{ID: NewEntityID(TypeImage, sum), Type: TypeImage, Value: sum, Attrs: map[string]Attr{}, Tags: []string{}}
}

// NewTextEntity content-addresses free text so that identical text collected
// from two sources is one entity, not two.
func NewTextEntity(s string) Entity {
	c, err := Canonicalize(TypeText, s)
	if err != nil {
		return Entity{}
	}
	return Entity{ID: NewEntityID(TypeText, c), Type: TypeText, Value: c, Attrs: map[string]Attr{}, Tags: []string{}}
}

// NewFindingEntity hashes the kind, subject, and key attributes so the same
// finding discovered twice is one row.
func NewFindingEntity(kind string, subject EntityID, keyAttrs map[string]any) Entity {
	canon := kind + "\x00" + string(subject) + "\x00" + stableString(keyAttrs)
	sum := sha256.Sum256([]byte(canon))
	val := "sha256:" + hex.EncodeToString(sum[:])
	return Entity{ID: NewEntityID(TypeFinding, val), Type: TypeFinding, Value: val, Attrs: map[string]Attr{}, Tags: []string{}}
}

// SetAttr records an attribute value together with the observation supporting
// it. The value is stored alongside its provenance rather than overwriting a
// previous one.
func (e *Entity) SetAttr(key string, value any, obsID string) {
	if e.Attrs == nil {
		e.Attrs = map[string]Attr{}
	}
	a, ok := e.Attrs[key]
	if !ok {
		a = Attr{Value: value}
	}
	a.Value = value
	if obsID != "" {
		a.Obs = appendUnique(a.Obs, obsID)
	}
	e.Attrs[key] = a
}

// HasTag reports whether the entity carries tag.
func (e *Entity) HasTag(tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AddTag appends tag if absent and reports whether it was new.
func (e *Entity) AddTag(tag string) bool {
	if tag == "" || e.HasTag(tag) {
		return false
	}
	e.Tags = append(e.Tags, tag)
	sort.Strings(e.Tags)
	return true
}

// Source identifies who made a claim and how, at the granularity needed for
// independence-group scoring (resellers must be distinguishable from originators).
type Source struct {
	Module   string // "ct-search"
	Provider string // "crtsh"
	Method   string // "api.search"
}

// String renders a source as "module/provider:method" for display and hashing.
func (s Source) String() string {
	var b strings.Builder
	b.WriteString(s.Module)
	if s.Provider != "" {
		b.WriteByte('/')
		b.WriteString(s.Provider)
	}
	if s.Method != "" {
		b.WriteByte(':')
		b.WriteString(s.Method)
	}
	return b.String()
}

// Observation is a claim by one source at one time. Observations are append
// only; nothing is ever overwritten, only superseded.
type Observation struct {
	ID          string
	Subject     EntityID
	Predicate   string // "exists", "resolves_to", "attr:registrar", ...
	Object      any    // EntityID or scalar
	Source      Source
	Reliability byte // 'A'..'F'  source reliability (Admiralty)
	Credibility byte // '1'..'6'  information credibility
	ObservedAt  time.Time
	ValidFrom   *time.Time // optional bitemporal lower bound
	ValidTo     *time.Time // optional bitemporal upper bound
	Attrs       map[string]any
	Evidence    []EvidenceRef
}

// NewObservation fills in the deterministic identity of an observation and
// defaults the timestamp to now.
func NewObservation(now time.Time, subject EntityID, predicate string, object any, src Source, rel, cred byte) Observation {
	o := Observation{
		Subject:     subject,
		Predicate:   predicate,
		Object:      object,
		Source:      src,
		Reliability: rel,
		Credibility: cred,
		ObservedAt:  now.UTC(),
	}
	o.ID = ObservationID(src.String(), string(subject), predicate, object, nil)
	return o
}

// WithValidFrom recomputes the identity so the same fact at a different validity
// window is stored as a distinct observation rather than collapsed.
func (o Observation) WithValidFrom(from, to time.Time) Observation {
	if from.IsZero() {
		o.ValidFrom = nil
	} else {
		f := from.UTC()
		o.ValidFrom = &f
	}
	if to.IsZero() {
		o.ValidTo = nil
	} else {
		t := to.UTC()
		o.ValidTo = &t
	}
	o.ID = ObservationID(o.Source.String(), string(o.Subject), o.Predicate, o.Object, o.ValidFrom)
	return o
}

// EnsureID derives the observation's identity when it does not yet have one.
//
// Observation identity is content-derived, so it must not be the module's job to
// compute it: a module that forgets produces a row with an empty primary key,
// which the store then skips, and the finding silently loses its provenance. Every
// path that accepts an observation calls this, so a module cannot get it wrong.
func (o *Observation) EnsureID() {
	if o.ID == "" {
		o.ID = ObservationID(o.Source.String(), string(o.Subject), o.Predicate, o.Object, o.ValidFrom)
	}
}

// AddAttr attaches a provenance-carrying attribute to the observation.
func (o *Observation) AddAttr(key string, value any) {
	if o.Attrs == nil {
		o.Attrs = map[string]any{}
	}
	o.Attrs[key] = value
}

// EvidenceRef points at a content-addressed artifact.
type EvidenceRef struct {
	ID     string
	SHA256 string
}

// RelationType names a typed edge. The full taxonomy is in §13.2; the
// constants below cover the edges the 0.1/0.2 modules actually emit.
type RelationType string

const (
	RelResolvesTo    RelationType = "resolves_to"
	RelSubdomainOf   RelationType = "subdomain_of"
	RelCNAMETo       RelationType = "cname_to"
	RelNSFor         RelationType = "ns_for"
	RelMXFor         RelationType = "mx_for"
	RelAnnouncedBy   RelationType = "announced_by"
	RelHostedOn      RelationType = "hosted_on"
	RelRegisteredBy  RelationType = "registered_by"
	RelOwnedBy       RelationType = "owned_by"
	RelIssuedFor     RelationType = "issued_for"
	RelUsesEmail     RelationType = "uses_email"
	RelHasAccount    RelationType = "has_account"
	RelSameAs        RelationType = "same_as"
	RelAliasOf       RelationType = "alias_of"
	RelMentions      RelationType = "mentions"
	RelLocatedAt     RelationType = "located_at"
	RelLookalikeOf   RelationType = "lookalike_of"
	RelExposes       RelationType = "exposes"
	RelAffectedBy    RelationType = "affected_by"
	RelDerivedFrom   RelationType = "derived_from"
	RelObservedFrom  RelationType = "observed_from"
	RelReverseOf     RelationType = "reverse_of"
	RelAnnouncesIP   RelationType = "announces"
	RelRegistrarOf   RelationType = "registrar_of"
	RelPartOfNetwork RelationType = "part_of_network"
)

// Relation is a typed edge between entities. It is itself supported by
// observations, and heuristic edges are always flagged so a reviewer can tell an
// inference from a direct observation.
type Relation struct {
	ID         string
	From, To   EntityID
	Type       RelationType
	Confidence float64
	Heuristic  bool
	Obs        []string // supporting observation IDs
}

// Rel builds a direct (non-heuristic) relation with deterministic identity.
func Rel(from, to EntityID, t RelationType) Relation {
	canon := string(from) + "\x00" + string(to) + "\x00" + string(t)
	sum := sha256.Sum256([]byte(canon))
	return Relation{
		ID:        hex.EncodeToString(sum[:])[:32],
		From:      from,
		To:        to,
		Type:      t,
		Obs:       []string{},
		Heuristic: false,
	}
}

// HeuristicRel builds an inferred relation. Heuristic edges are rendered
// differently in reports and graph exports so an inference is never mistaken for
// a verified link.
func HeuristicRel(from, to EntityID, t RelationType) Relation {
	r := Rel(from, to, t)
	r.Heuristic = true
	return r
}

// Finding is a tagged observation of interest: an exposure, misconfiguration, or
// anomaly, optionally carrying a severity.
type Finding struct {
	Entity      Entity
	Relations   []Relation
	Observation Observation
	Kind        string // optional: "dangling-cname", "exposed-service", ...
	Severity    string // optional: info | low | medium | high | critical
}

// Severity constants, ordered so they can be compared numerically.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

var severityRank = map[string]int{SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4}

// SeverityRank maps a severity string to a comparable rank. Unknown values rank
// with "info" so a typo can never escalate a finding.
func SeverityRank(s string) int { return severityRank[s] }

// SeverityAtLeast reports whether s is at or above threshold.
func SeverityAtLeast(s, threshold string) bool { return severityRank[s] >= severityRank[threshold] }

// NewFinding assembles a finding and derives its entity identity.
func NewFinding(kind, severity string, subject Entity, obs Observation, rels ...Relation) Finding {
	key := map[string]any{"kind": kind}
	if obs.Attrs != nil {
		for k, v := range obs.Attrs {
			switch k {
			case "ttl", "rrtype", "days_to_expiry":
				key[k] = v
			}
		}
	}
	f := Finding{
		Entity:      subject,
		Observation: obs,
		Kind:        kind,
		Severity:    severity,
	}
	if kind != "" && severity != "" {
		f.Entity = NewFindingEntity(kind, subject.ID, key)
		f.Relations = append([]Relation{Rel(subject.ID, f.Entity.ID, RelExposes)}, rels...)
	}
	f.Relations = append(f.Relations, rels...)
	return f
}

func appendUnique(dst []string, v string) []string {
	for _, e := range dst {
		if e == v {
			return dst
		}
	}
	return append(dst, v)
}
