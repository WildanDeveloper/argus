package engine

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

func newEvidenceStore(t *testing.T) (*EvidenceStore, store.Store) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dir := t.TempDir()
	es, err := NewEvidenceStore(st, dir, slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatal(err)
	}
	return es, st
}

func meta(source string) sdk.EvidenceMeta {
	return sdk.EvidenceMeta{Source: source, Method: "test", MediaType: "application/json"}
}

func TestEvidenceIsContentAddressedAndChained(t *testing.T) {
	es, _ := newEvidenceStore(t)
	ctx := context.Background()

	r1, err := es.Store(ctx, "scan1", "CASE-1", meta("a"), []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := es.Store(ctx, "scan1", "CASE-1", meta("b"), []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if r1.ID == r2.ID {
		t.Error("distinct artifacts must get distinct record IDs")
	}

	recs, err := es.store.EvidenceForCase(ctx, "CASE-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	// The second record must commit to the first.
	if recs[0].PrevHash != genesisHash {
		t.Errorf("first record prev_hash = %q, want the genesis value", recs[0].PrevHash)
	}
	if recs[1].PrevHash != recs[0].RecordHash {
		t.Error("the second record does not commit to the first; the chain is broken")
	}

	// The blob must be readable and hash to its digest.
	data, err := es.Read(r1.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"a":1}` {
		t.Errorf("artifact content = %q", data)
	}
}

func TestEvidenceVerifyPasses(t *testing.T) {
	es, _ := newEvidenceStore(t)
	ctx := context.Background()
	for _, body := range []string{`{"n":1}`, `{"n":2}`, `{"n":3}`} {
		if _, err := es.Store(ctx, "scan1", "CASE-1", meta("x"), []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	res, err := es.Verify(ctx, "CASE-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain should verify: %s", res.Problem)
	}
	if res.Checked != 3 || res.BlobsPresent != 3 {
		t.Errorf("checked=%d present=%d, want 3 and 3", res.Checked, res.BlobsPresent)
	}
}

func TestEvidenceVerifyDetectsAlteredBlob(t *testing.T) {
	// Content addressing must catch an artifact edited on disk after capture.
	es, _ := newEvidenceStore(t)
	ctx := context.Background()
	ref, err := es.Store(ctx, "scan1", "CASE-1", meta("x"), []byte(`{"secret":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(es.dir, pathForDigest(ref.SHA256))
	if err := os.WriteFile(path, []byte(`{"secret":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := es.Verify(ctx, "CASE-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("an altered artifact verified as intact")
	}
	if res.Problem == "" {
		t.Error("verification must explain the failure")
	}
}

func TestEvidenceVerifyDetectsDeletedBlob(t *testing.T) {
	// Re-hashing alone would pass here, because the record still matches itself.
	// Only checking the filesystem notices that the artifact is gone.
	es, _ := newEvidenceStore(t)
	ctx := context.Background()
	ref, err := es.Store(ctx, "scan1", "CASE-1", meta("x"), []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(es.dir, pathForDigest(ref.SHA256))); err != nil {
		t.Fatal(err)
	}

	res, err := es.Verify(ctx, "CASE-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a missing artifact verified as intact")
	}
	if len(res.BlobsMissing) != 1 {
		t.Errorf("BlobsMissing = %v, want one entry", res.BlobsMissing)
	}
}

func TestEvidenceVerifyDetectsRemovedRecord(t *testing.T) {
	// Dropping a record from the middle breaks the prev_hash linkage even though
	// every surviving record still hashes correctly.
	es, st := newEvidenceStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := es.Store(ctx, "scan1", "CASE-1", meta("x"), []byte(`{"n":`+string(rune('0'+i))+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DeleteEvidence(ctx, "CASE-1", 1); err != nil {
		t.Fatal(err)
	}
	res, err := es.Verify(ctx, "CASE-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a removed record verified as intact")
	}
}

func TestEvidenceChainsAreSeparatePerCase(t *testing.T) {
	// Two engagements must not be able to splice records into each other's chain.
	es, _ := newEvidenceStore(t)
	ctx := context.Background()
	es.Store(ctx, "s1", "CASE-1", meta("a"), []byte(`{"a":1}`))
	es.Store(ctx, "s2", "CASE-2", meta("b"), []byte(`{"b":2}`))

	if h1, h2 := es.ChainHead("CASE-1"), es.ChainHead("CASE-2"); h1 == h2 {
		t.Error("two cases produced the same chain head")
	}
	if es.ChainHead("unknown-case") != genesisHash {
		t.Error("an unknown case must report the genesis head, not another case's")
	}
}

func TestEvidenceChainContinuesAcrossProcessRestart(t *testing.T) {
	// A restarted process must recover the chain head from the store. Starting from
	// genesis again would fork a second chain, and every later verification would
	// report the fork as tampering.
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dir := t.TempDir()
	newStore := func() *EvidenceStore {
		es, err := NewEvidenceStore(st, dir, slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError})))
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	ctx := context.Background()

	first := newStore()
	for _, body := range []string{`{"n":1}`, `{"n":2}`} {
		if _, err := first.Store(ctx, "scan1", "CASE-R", meta("x"), []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	headBefore := first.ChainHead("CASE-R")

	// A brand new store over the same database, as after a restart.
	second := newStore()
	if h := second.ChainHead("CASE-R"); h != genesisHash {
		t.Errorf("a fresh store reports head %q before writing; it only learns the head on demand", shortHex(h))
	}
	if _, err := second.Store(ctx, "scan2", "CASE-R", meta("y"), []byte(`{"n":3}`)); err != nil {
		t.Fatal(err)
	}

	res, err := second.Verify(ctx, "CASE-R", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("the chain forked across a restart: %s", res.Problem)
	}
	if second.ChainHead("CASE-R") == headBefore {
		t.Error("the head did not advance past the records written before the restart")
	}
}

func shortHex(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
