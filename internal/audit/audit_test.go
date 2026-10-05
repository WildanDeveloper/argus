package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestChainVerifies(t *testing.T) {
	l, err := New(NewMemorySink(), "analyst")
	if err != nil {
		t.Fatal(err)
	}
	l = l.WithClock(fixedClock(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)))

	for i := 0; i < 20; i++ {
		if _, err := l.Record(context.Background(), ActionEgressRequest, map[string]any{
			"host":   "example.com",
			"method": "GET",
			"n":      i,
		}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := l.Verify(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain should verify: %s", res.BrokenReason)
	}
	if res.Entries != 20 {
		t.Errorf("entries = %d, want 20", res.Entries)
	}
	if len(res.HeadHash) != 64 {
		t.Errorf("head hash length = %d, want 64", len(res.HeadHash))
	}
}

func TestTamperDetection(t *testing.T) {
	// The whole point of the chain: an edit to any historical record must be
	// detectable. Simulate an operator "fixing up" a scope denial after the fact.
	s := NewMemorySink()
	l, _ := New(s, "analyst")
	l = l.WithClock(fixedClock(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)))

	l.Record(context.Background(), ActionScopeDecision, map[string]any{"target": "evil.example", "decision": "deny"})
	l.Record(context.Background(), ActionScopeDecision, map[string]any{"target": "acme.example", "decision": "allow"})
	l.Record(context.Background(), ActionEgressRequest, map[string]any{"host": "acme.example"})

	if res, _ := l.Verify(context.Background(), 0); !res.OK {
		t.Fatalf("pre-tamper chain must verify: %s", res.BrokenReason)
	}

	// Mutate entry 1 in place: flip the decision to "allow".
	entries, _ := s.Range(context.Background(), 0, 0)
	entries[0].Detail["decision"] = "allow"
	s.mu.Lock()
	s.entries = entries
	s.mu.Unlock()

	res, _ := l.Verify(context.Background(), 0)
	if res.OK {
		t.Fatal("tampered chain verified as intact: tampering went undetected")
	}
	if res.BrokenAtSeq != 1 {
		t.Errorf("break reported at seq %d, want 1", res.BrokenAtSeq)
	}
	if !strings.Contains(res.BrokenReason, "modified") {
		t.Errorf("unexpected reason: %s", res.BrokenReason)
	}
}

func TestDeletionDetection(t *testing.T) {
	s := NewMemorySink()
	l, _ := New(s, "analyst")
	l = l.WithClock(fixedClock(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)))
	for i := 0; i < 5; i++ {
		l.Record(context.Background(), ActionModuleRun, map[string]any{"n": i})
	}
	// Remove a middle entry. Every hash still matches its own content, so a
	// content-only check would pass; only the prev_hash linkage catches this.
	entries, _ := s.Range(context.Background(), 0, 0)
	s.mu.Lock()
	s.entries = append(entries[:2], entries[3:]...)
	s.mu.Unlock()

	res, _ := l.Verify(context.Background(), 0)
	if res.OK {
		t.Fatal("deleted entry went undetected")
	}
	if !strings.Contains(res.BrokenReason, "prev_hash") {
		t.Errorf("expected prev_hash break, got: %s", res.BrokenReason)
	}
}

func TestReorderDetection(t *testing.T) {
	s := NewMemorySink()
	l, _ := New(s, "analyst")
	l = l.WithClock(fixedClock(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)))
	for i := 0; i < 4; i++ {
		l.Record(context.Background(), ActionModuleRun, map[string]any{"n": i})
	}
	entries, _ := s.Range(context.Background(), 0, 0)
	entries[1], entries[2] = entries[2], entries[1]
	s.mu.Lock()
	s.entries = entries
	s.mu.Unlock()

	if res, _ := l.Verify(context.Background(), 0); res.OK {
		t.Fatal("reordered chain verified as intact")
	}
}

func TestChainContinuesAcrossReopen(t *testing.T) {
	// Restarting the binary must extend the chain, not begin a new one. A fresh
	// chain would let an operator discard inconvenient history by restarting.
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.jsonl")

	l1, err := OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	l1 = l1.WithClock(fixedClock(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)))
	e1, err := l1.Record(context.Background(), ActionScanStart, map[string]any{"scan": "01"})
	if err != nil {
		t.Fatal(err)
	}

	l2, err := OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	l2 = l2.WithClock(fixedClock(time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)))
	if l2.LastHash() != e1.Hash {
		t.Fatal("reopened log did not recover the chain head")
	}
	if _, err := l2.Record(context.Background(), ActionScanFinish, map[string]any{"scan": "01"}); err != nil {
		t.Fatal(err)
	}

	res, err := l2.Verify(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain broken across restart: %s", res.BrokenReason)
	}
	if res.Entries != 2 {
		t.Errorf("entries = %d, want 2", res.Entries)
	}

	// The file must be readable without this program.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != '{' {
		t.Error("audit file is not plain JSONL")
	}
}

func TestQuery(t *testing.T) {
	l, _ := New(NewMemorySink(), "analyst")
	t0 := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	l = l.WithClock(func() time.Time { return t0 })

	l.Record(context.Background(), ActionEgressRequest, map[string]any{"host": "a.example"})
	l.Record(context.Background(), ActionScopeDecision, map[string]any{"target": "b.example"})
	l.Record(context.Background(), ActionEgressRequest, map[string]any{"host": "c.example"})

	got, err := l.Query(context.Background(), Query{Action: ActionEgressRequest})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("query returned %d, want 2", len(got))
	}
	// Newest first.
	if got[0].Detail["host"] != "c.example" {
		t.Errorf("expected newest first, got %v", got[0].Detail)
	}

	acts, err := l.Actions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 2 {
		t.Errorf("actions = %v", acts)
	}
}

func TestFileSinkRefusesTruncate(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenJSONL(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Record(context.Background(), ActionConfigChange, map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	// Truncating in place would rewrite history. The file sink must refuse.
	if err := truncateFileSink(t, l); err == nil {
		t.Error("expected the file sink to refuse truncation")
	}
}

func truncateFileSink(t *testing.T, l *Log) error {
	t.Helper()
	head, ok, err := l.sink.Head(context.Background())
	if err != nil || !ok || head.Seq == 0 {
		return nil
	}
	return l.sink.Truncate(context.Background(), head.Seq-1)
}

func TestConcurrentRecordIsChainSafe(t *testing.T) {
	// Many goroutines appending concurrently must still produce a single
	// well-formed chain. A lost update to lastHash would fork the chain.
	l, _ := New(NewMemorySink(), "analyst")
	l = l.WithClock(fixedClock(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)))

	const n = 200
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := l.Record(context.Background(), ActionEgressRequest, map[string]any{"n": i})
			done <- err
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	res, err := l.Verify(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("concurrent chain broken: %s", res.BrokenReason)
	}
	if res.Entries != n {
		t.Errorf("entries = %d, want %d", res.Entries, n)
	}
}
