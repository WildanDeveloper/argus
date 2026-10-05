// Package audit implements the append-only, hash-chained record of every
// outbound request and every policy decision.
//
// The chain exists so that "we did not scan that target" is a verifiable claim
// rather than an assertion. Each record commits to the previous record's hash,
// so deleting, reordering, or editing any entry breaks verification.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Action names a class of auditable event. These strings are part of the
// on-disk format; add new ones, do not rename.
const (
	ActionEgressRequest  = "egress.request"
	ActionEgressDenied   = "egress.denied"
	ActionScopeDecision  = "scope.decision"
	ActionPolicyDecision = "policy.decision"
	ActionModuleRun      = "module.run"
	ActionSecretAccess   = "secret.access"
	ActionScanStart      = "scan.start"
	ActionScanFinish     = "scan.finish"
	ActionPurge          = "data.purge"
	ActionApproval       = "case.approval"
	ActionPluginInstall  = "plugin.install"
	ActionConfigChange   = "config.change"
	ActionEvidenceAnchor = "evidence.anchor"
)

// Entry is one link in the chain.
type Entry struct {
	Seq      uint64         `json:"seq"`
	At       time.Time      `json:"at"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Detail   map[string]any `json:"detail"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Sink persists entries. Implementations must be append-only: Append assigns
// and returns the sequence number, and no method may rewrite an existing entry.
type Sink interface {
	Append(ctx context.Context, e Entry) (uint64, error)
	Range(ctx context.Context, from, to uint64) ([]Entry, error)
	Head(ctx context.Context) (Entry, bool, error)
	Truncate(ctx context.Context, upto uint64) error // only for compaction, audited separately
}

// Log is a concurrent-safe hash-chained audit log.
type Log struct {
	mu    sync.Mutex
	sink  Sink
	actor string
	now   func() time.Time
	// lastHash is the chain head. It is cached so that Append does not need to
	// read the sink on the hot path; an empty store starts from a genesis value.
	lastHash string
	head     Entry
	hasHead  bool
}

// genesisHash seeds the chain so that the first record's PrevHash is a
// recognizable constant rather than an empty string.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// New builds a Log over the given sink.
func New(s Sink, actor string) (*Log, error) {
	if s == nil {
		return nil, errors.New("audit: nil sink")
	}
	l := &Log{
		sink:     s,
		actor:    actor,
		now:      time.Now,
		lastHash: genesisHash,
	}
	// Recover the chain head so a restart continues the chain rather than
	// silently restarting it, which would let an operator present a truncated
	// log as if it were complete.
	if head, ok, err := s.Head(context.Background()); err != nil {
		return nil, fmt.Errorf("audit: read head: %w", err)
	} else if ok {
		l.lastHash, l.head, l.hasHead = head.Hash, head, true
	}
	return l, nil
}

// WithClock overrides the clock for deterministic tests.
func (l *Log) WithClock(now func() time.Time) *Log {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
	return l
}

// WithActor overrides the recorded actor.
func (l *Log) WithActor(actor string) *Log {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.actor = actor
	return l
}

// Actor returns the current default actor.
func (l *Log) Actor() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.actor
}

// Record appends one entry to the chain and returns it.
func (l *Log) Record(ctx context.Context, action string, detail map[string]any) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	if detail == nil {
		detail = map[string]any{}
	}
	prev := l.lastHash
	e := Entry{
		At:       l.now().UTC().Truncate(time.Millisecond),
		Actor:    l.actor,
		Action:   action,
		Detail:   detail,
		PrevHash: prev,
	}
	e.Hash = chainHash(prev, e)
	seq, err := l.sink.Append(ctx, e)
	if err != nil {
		return Entry{}, err
	}
	e.Seq = seq
	l.lastHash, l.head, l.hasHead = e.Hash, e, true
	return e, nil
}

// Recordf is Record with a single formatted message detail.
func (l *Log) Recordf(ctx context.Context, action, format string, args ...any) error {
	_, err := l.Record(ctx, action, map[string]any{"message": fmt.Sprintf(format, args...)})
	return err
}

// Head returns the current chain head.
func (l *Log) Head() (Entry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head, l.hasHead
}

// LastHash returns the current chain head hash.
func (l *Log) LastHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastHash
}

// chainHash binds an entry to its predecessor. The hashed preimage is a
// length-prefixed encoding rather than a concatenation, so no combination of
// field values can be rearranged into a different entry with the same hash.
func chainHash(prev string, e Entry) string {
	h := sha256.New()
	writeField(h, prev)
	writeField(h, strconv.FormatInt(e.At.UnixNano(), 10))
	writeField(h, e.Actor)
	writeField(h, e.Action)
	writeField(h, canonicalJSON(e.Detail))
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(w io.Writer, s string) {
	fmt.Fprintf(w, "%d:", len(s))
	io.WriteString(w, s)
}

// canonicalJSON encodes a detail map deterministically. Go's encoding/json
// already sorts map keys, which is what makes the chain reproducible.
func canonicalJSON(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		// A detail value that cannot be marshaled must not be able to break the
		// chain. Fall back to its Go rendering; it is still deterministic for
		// any single value type.
		return fmt.Sprintf("%v", m)
	}
	return string(b)
}

// VerifyResult reports the outcome of a chain verification.
type VerifyResult struct {
	OK           bool
	Entries      int
	BrokenAtSeq  uint64 // 0 when intact
	BrokenReason string
	HeadHash     string
	First        Entry
}

// Verify walks the chain from the beginning and recomputes every hash. Any
// modification, deletion, or reordering is detected.
func (l *Log) Verify(ctx context.Context, limit int) (VerifyResult, error) {
	entries, err := l.sink.Range(ctx, 0, 0)
	if err != nil {
		return VerifyResult{}, err
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return VerifyEntries(entries), nil
}

// VerifyEntries verifies a materialized slice of the chain. It is exported so
// that `argus audit verify --bundle` can check a chain extracted from an
// archive without a live database.
func VerifyEntries(entries []Entry) VerifyResult {
	res := VerifyResult{OK: true, Entries: len(entries)}
	if len(entries) == 0 {
		res.HeadHash = genesisHash
		return res
	}
	prev := genesisHash
	for i, e := range entries {
		if e.PrevHash != prev {
			res.OK = false
			res.BrokenAtSeq = e.Seq
			res.BrokenReason = fmt.Sprintf("entry %d: prev_hash %s does not match previous head %s", i, short(e.PrevHash), short(prev))
			return res
		}
		want := chainHash(prev, Entry{At: e.At, Actor: e.Actor, Action: e.Action, Detail: e.Detail})
		if want != e.Hash {
			res.OK = false
			res.BrokenAtSeq = e.Seq
			res.BrokenReason = fmt.Sprintf("entry %d (%s): hash mismatch; content was modified after signing", i, e.Action)
			return res
		}
		if i == 0 {
			res.First = e
		}
		prev = e.Hash
	}
	res.HeadHash = prev
	return res
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:8] + ".." + h[len(h)-4:]
}

// Query filters the chain for inspection by the CLI and API.
type Query struct {
	Actor   string
	Action  string
	Since   time.Time
	Until   time.Time
	Limit   int
	FromSeq uint64
}

// Query returns matching entries newest first.
func (l *Log) Query(ctx context.Context, q Query) ([]Entry, error) {
	all, err := l.sink.Range(ctx, q.FromSeq, 0)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		if q.Actor != "" && e.Actor != q.Actor {
			continue
		}
		if q.Action != "" && e.Action != q.Action {
			continue
		}
		if !q.Since.IsZero() && e.At.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && e.At.After(q.Until) {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

// Actions returns the distinct action names present in the chain, sorted. The
// CLI uses this for tab completion and `argus audit` help.
func (l *Log) Actions(ctx context.Context) ([]string, error) {
	all, err := l.sink.Range(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range all {
		seen[e.Action] = true
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

// MemorySink keeps entries in memory. Used by tests and by the air-gapped
// single-shot mode where durability is provided by the case bundle instead.
type MemorySink struct {
	mu      sync.Mutex
	entries []Entry
}

// NewMemorySink returns an empty in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

func (s *MemorySink) Append(_ context.Context, e Entry) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Seq = uint64(len(s.entries)) + 1
	s.entries = append(s.entries, e)
	return e.Seq, nil
}

func (s *MemorySink) Range(_ context.Context, from, to uint64) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.Seq < from {
			continue
		}
		if to > 0 && e.Seq > to {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *MemorySink) Head(_ context.Context) (Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		return Entry{}, false, nil
	}
	return s.entries[len(s.entries)-1], true, nil
}

// Truncate discards entries up to and including seq. Used only by log
// compaction, which is itself an audited action: the truncated prefix is copied
// to a sealed file first, so the chain remains verifiable end to end.
func (s *MemorySink) Truncate(_ context.Context, upto uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []Entry
	for _, e := range s.entries {
		if e.Seq > upto {
			kept = append(kept, e)
		}
	}
	s.entries = kept
	return nil
}

// Nop is a sink that discards everything. Only for unit tests: a production
// binary must never run with a no-op audit log, because that is exactly the
// "we have no record" state the log exists to rule out.
type Nop struct{}

func (Nop) Append(context.Context, Entry) (uint64, error)          { return 0, nil }
func (Nop) Range(context.Context, uint64, uint64) ([]Entry, error) { return nil, nil }
func (Nop) Head(context.Context) (Entry, bool, error)              { return Entry{}, false, nil }
func (Nop) Truncate(context.Context, uint64) error                 { return nil }
