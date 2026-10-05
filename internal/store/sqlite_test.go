package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "argus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seed(t *testing.T, s *SQLite, scanID string) {
	t.Helper()
	dom := sdk.NewEntity(sdk.TypeDomain, "acme.example")
	sub := sdk.NewEntity(sdk.TypeSubdomain, "dev.acme.example")
	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")

	now := time.Now().UTC()
	dom.FirstSeen, dom.LastSeen = now, now
	dom.Tags = []string{"registered"}
	sub.FirstSeen, sub.LastSeen = now, now
	ip.FirstSeen, ip.LastSeen = now, now
	ip.Confidence = 0.87
	sub.Confidence = 0.9

	src := sdk.Source{Module: "dns-records", Provider: "dns", Method: "lookup"}
	obs := sdk.NewObservation(now, ip.ID, "resolves_to", sub.ID, src, 'B', '2')
	obs.Evidence = []sdk.EvidenceRef{{ID: "01J1", SHA256: "deadbeef"}}

	if err := s.UpsertBatch(context.Background(), scanID, Batch{
		Entities:     []sdk.Entity{dom, sub, ip},
		Observations: []sdk.Observation{obs},
		Relations: []sdk.Relation{
			sdk.Rel(sub.ID, ip.ID, sdk.RelResolvesTo),
			sdk.Rel(sub.ID, dom.ID, sdk.RelSubdomainOf),
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSaveAndGetScan(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	target := sdk.NewEntity(sdk.TypeDomain, "acme.example")

	sc := Scan{CaseID: "CASE-1", Workflow: "domain-recon", Target: target, Purpose: "Authorized assessment",
		Mode: sdk.ModeSemiActive, CreatedBy: "analyst", Modules: []string{"rdap", "dns-records"}, StartedAt: time.Now()}
	if err := s.SaveScan(ctx, &sc); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Workflow != "domain-recon" || got.Purpose != "Authorized assessment" {
		t.Errorf("scan round-trip lost fields: %+v", got)
	}
	if got.Modules == nil || len(got.Modules) != 2 || got.Modules[0] != "rdap" {
		t.Errorf("modules round-trip failed: %v", got.Modules)
	}
	if got.Mode != sdk.ModeSemiActive {
		t.Errorf("mode = %v, want semi-active", got.Mode)
	}
}

func TestUpsertIsIdempotent(t *testing.T) {
	// This is the property that makes at-least-once delivery safe: a redelivered
	// task must not duplicate rows.
	s := newTestStore(t)
	ctx := context.Background()
	scanID := NewScanID()

	seed(t, s, scanID)
	before, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Replay the identical batch three more times, as a crashed worker would.
	seed(t, s, scanID)
	seed(t, s, scanID)
	after, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if after.Entities != before.Entities {
		t.Errorf("entities grew on replay: %d -> %d", before.Entities, after.Entities)
	}
	if after.Observations != before.Observations {
		t.Errorf("observations grew on replay: %d -> %d", before.Observations, after.Observations)
	}
	if after.Relations != before.Relations {
		t.Errorf("relations grew on replay: %d -> %d", before.Relations, after.Relations)
	}
}

func TestFirstSeenNeverMovesForward(t *testing.T) {
	// A later scan must not rewrite history: first_seen is the earliest sighting
	// and last_seen the latest, regardless of the order rows arrive in.
	s := newTestStore(t)
	ctx := context.Background()
	e := sdk.NewEntity(sdk.TypeDomain, "acme.example")

	early := time.Now().UTC().Add(-48 * time.Hour)
	late := time.Now().UTC()
	e.FirstSeen, e.LastSeen = late, late
	s.UpsertBatch(ctx, "", Batch{Entities: []sdk.Entity{e}})

	e2 := e
	e2.FirstSeen, e2.LastSeen = early, early
	s.UpsertBatch(ctx, "", Batch{Entities: []sdk.Entity{e2}})

	got, err := s.GetEntity(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.FirstSeen.Equal(early) {
		t.Errorf("first_seen = %v, want the earlier %v", got.FirstSeen, early)
	}
	if !got.LastSeen.Equal(late) {
		t.Errorf("last_seen = %v, want the later %v", got.LastSeen, late)
	}
}

func TestConfidenceIsMonotonicPerEntity(t *testing.T) {
	// Confidence only ever improves as evidence accumulates; a weaker observation
	// must not lower a well-corroborated entity.
	s := newTestStore(t)
	ctx := context.Background()
	e := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")

	e.Confidence = 0.9
	s.UpsertBatch(ctx, "", Batch{Entities: []sdk.Entity{e}})
	e2 := e
	e2.Confidence = 0.1
	s.UpsertBatch(ctx, "", Batch{Entities: []sdk.Entity{e2}})

	got, _ := s.GetEntity(ctx, e.ID)
	if got.Confidence < 0.9 {
		t.Errorf("confidence regressed to %v", got.Confidence)
	}
}

func TestTagsArePersisted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	e := sdk.NewEntity(sdk.TypeSubdomain, "dev.acme.example")
	e.Tags = []string{"cloud", "aws"}
	s.UpsertBatch(ctx, "", Batch{Entities: []sdk.Entity{e}})

	got, err := s.GetEntity(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "aws" {
		t.Errorf("tags = %v, want [aws cloud]", got.Tags)
	}

	list, total, err := s.ListEntities(ctx, EntityQuery{Tags: []string{"cloud"}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(list) != 1 {
		t.Errorf("tag filter returned %d (total %d), want 1", len(list), total)
	}
}

func TestObservationsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	scanID := NewScanID()
	seed(t, s, scanID)

	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")
	obs, err := s.Observations(ctx, ip.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	o := obs[0]
	if o.Predicate != "resolves_to" {
		t.Errorf("predicate = %q", o.Predicate)
	}
	if o.Source.Module != "dns-records" || o.Source.Provider != "dns" {
		t.Errorf("source lost attribution: %+v", o.Source)
	}
	if o.Reliability != 'B' || o.Credibility != '2' {
		t.Errorf("Admiralty grades lost: %q%q", o.Reliability, o.Credibility)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].SHA256 != "deadbeef" {
		t.Errorf("evidence link lost: %+v", o.Evidence)
	}
}

func TestRelationsAndNeighbors(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seed(t, s, NewScanID())

	sub := sdk.NewEntity(sdk.TypeSubdomain, "dev.acme.example")
	rels, err := s.Relations(ctx, sub.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 {
		t.Fatalf("expected 2 relations, got %d", len(rels))
	}

	neighbors, err := s.Neighbors(ctx, sub.ID, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(neighbors) != 2 {
		t.Errorf("expected 2 neighbors, got %d", len(neighbors))
	}

	// Two hops should also reach the parent domain via the IP.
	deep, err := s.Neighbors(ctx, sub.ID, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deep) < 2 {
		t.Errorf("2-hop neighborhood = %d entities, want at least 2", len(deep))
	}
}

func TestHeuristicEdgeIsNotPromotedToVerified(t *testing.T) {
	// An inference must never be laundered into a verified fact by a later
	// heuristic observation of the same edge.
	s := newTestStore(t)
	ctx := context.Background()
	from := sdk.NewEntity(sdk.TypeDomain, "acme.example")
	to := sdk.NewEntity(sdk.TypeOrg, "Example Holdings")

	s.UpsertBatch(ctx, "", Batch{
		Entities:  []sdk.Entity{from, to},
		Relations: []sdk.Relation{sdk.Rel(from.ID, to.ID, sdk.RelOwnedBy)},
	})
	h := sdk.HeuristicRel(from.ID, to.ID, sdk.RelOwnedBy)
	s.UpsertBatch(ctx, "", Batch{Relations: []sdk.Relation{h}})

	rels, err := s.Relations(ctx, from.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 {
		t.Fatalf("expected 1 relation, got %d", len(rels))
	}
	if rels[0].Heuristic {
		t.Error("a heuristic observation overwrote a verified edge")
	}
}

func TestGetEntityByValueAndNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seed(t, s, NewScanID())

	e, err := s.GetEntityByValue(ctx, sdk.TypeDomain, "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != sdk.TypeDomain {
		t.Errorf("type = %q", e.Type)
	}
	if _, err := s.GetEntityByValue(ctx, sdk.TypeDomain, "nope.example"); err == nil {
		t.Error("expected ErrNotFound")
	}
	if _, err := s.GetEntity(ctx, sdk.EntityID("does-not-exist")); err == nil {
		t.Error("expected ErrNotFound")
	}
}

func TestListEntitiesFiltersByTypeAndConfidence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seed(t, s, NewScanID())

	ips, total, err := s.ListEntities(ctx, EntityQuery{Types: []sdk.EntityType{sdk.TypeIP}, MinConfidence: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || ips[0].Type != sdk.TypeIP {
		t.Errorf("type+confidence filter returned %d (total %d)", len(ips), total)
	}

	all, total, err := s.ListEntities(ctx, EntityQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("total entities = %d, want 3", total)
	}
	if len(all) != 3 {
		t.Errorf("returned %d entities, want 3", len(all))
	}
}

func TestEvidenceRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ref, err := s.PutEvidence(ctx, Evidence{
		CaseID: "CASE-1", SHA256: "abc123", Size: 1024, MediaType: "application/json",
		Source: "https://rdap.org/domain/acme.example", Method: "http.get", Collector: "rdap@1.0.0",
		RecordHash: "hash", BlobPath: "ab/cd/abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID == "" || ref.SHA256 != "abc123" {
		t.Errorf("ref = %+v", ref)
	}

	got, err := s.Evidence(ctx, ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MediaType != "application/json" || got.Collector != "rdap@1.0.0" {
		t.Errorf("evidence round-trip lost fields: %+v", got)
	}
	if got.CapturedAt.IsZero() {
		t.Error("captured_at should be stamped automatically")
	}

	// Re-putting the same ID must not error.
	if _, err := s.PutEvidence(ctx, Evidence{ID: ref.ID, SHA256: "abc123", RecordHash: "hash"}); err != nil {
		t.Errorf("re-putting evidence failed: %v", err)
	}
}

func TestStats(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	scanID := NewScanID()
	seed(t, s, scanID)
	s.SaveScan(ctx, &Scan{Target: sdk.NewEntity(sdk.TypeDomain, "acme.example"), CreatedBy: "analyst"})

	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Entities != 3 || st.Observations != 1 || st.Relations != 2 {
		t.Errorf("stats = %+v", st)
	}
	if st.Scans != 1 {
		t.Errorf("scans = %d, want 1", st.Scans)
	}
	if st.ObservationsWithoutEvidence != 0 {
		t.Errorf("observations without evidence = %d, want 0", st.ObservationsWithoutEvidence)
	}
}

func TestDiffAcrossScans(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s1, s2 := NewScanID(), NewScanID()

	seed(t, s, s1)

	// The second scan re-observes the same assets and adds one, and records a
	// different registrar.
	now := time.Now().UTC()
	dom := sdk.NewEntity(sdk.TypeDomain, "acme.example")
	sub := sdk.NewEntity(sdk.TypeSubdomain, "dev.acme.example")
	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")
	newSub := sdk.NewEntity(sdk.TypeSubdomain, "api.acme.example")
	for _, e := range []*sdk.Entity{&dom, &sub, &ip, &newSub} {
		e.FirstSeen, e.LastSeen = now, now
	}
	newSub.Confidence = 0.4

	src := sdk.Source{Module: "rdap", Provider: "rdap.org", Method: "domain"}
	oldReg := sdk.NewObservation(now.Add(-24*time.Hour), dom.ID, "attr:registrar", "Old Registrar", src, 'A', '1')
	newReg := sdk.NewObservation(now, dom.ID, "attr:registrar", "New Registrar", src, 'A', '1')
	sameRes := sdk.NewObservation(now, ip.ID, "resolves_to", sub.ID,
		sdk.Source{Module: "dns-records", Provider: "dns", Method: "lookup"}, 'B', '2')

	if err := s.UpsertBatch(ctx, s1, Batch{
		Observations: []sdk.Observation{oldReg},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertBatch(ctx, s2, Batch{
		Entities:     []sdk.Entity{dom, sub, ip, newSub},
		Observations: []sdk.Observation{newReg, sameRes},
	}); err != nil {
		t.Fatal(err)
	}

	res, err := s.Diff(ctx, s1, s2)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Added) != 1 || res.Added[0].Value != "api.acme.example" {
		t.Errorf("added = %v, want [api.acme.example]", values(res.Added))
	}
	if len(res.Removed) != 0 {
		t.Errorf("removed = %v, want none; every shared entity was re-observed", values(res.Removed))
	}

	// The registrar moved and must be reported from the observation history,
	// even though the merged entity row already shows only the new value.
	var registrarChange *EntityChange
	for i := range res.Changed {
		if res.Changed[i].Field == "attr:registrar" {
			registrarChange = &res.Changed[i]
		}
	}
	if registrarChange == nil {
		t.Fatalf("registrar change not detected; changed = %+v", res.Changed)
	}
	if registrarChange.Before != "Old Registrar" || registrarChange.After != "New Registrar" {
		t.Errorf("registrar change = %v -> %v, want Old -> New", registrarChange.Before, registrarChange.After)
	}
	if !sdk.SeverityAtLeast(registrarChange.Severity, sdk.SevLow) {
		t.Errorf("registrar change severity = %q", registrarChange.Severity)
	}

	// An unchanged fact must not be reported: resolves_to was asserted identically
	// in both scans.
	for _, c := range res.Changed {
		if c.Field == "resolves_to" {
			t.Errorf("unchanged fact reported as changed: %+v", c)
		}
	}
}

func TestDiffReportsNotObservedLater(t *testing.T) {
	// An entity missing from the later scan is "not observed again", not proven
	// gone. Scans are partial, and a diff that claimed removal would be
	// misleading in an attack-surface report.
	s := newTestStore(t)
	ctx := context.Background()
	s1, s2 := NewScanID(), NewScanID()
	seed(t, s, s1)

	dom := sdk.NewEntity(sdk.TypeDomain, "acme.example")
	now := time.Now().UTC()
	dom.FirstSeen, dom.LastSeen = now, now
	s.UpsertBatch(ctx, s2, Batch{Entities: []sdk.Entity{dom}})

	res, err := s.Diff(ctx, s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 2 {
		t.Errorf("removed = %v, want the two entities the later scan did not observe", values(res.Removed))
	}
}

func TestPurgeBySubject(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seed(t, s, NewScanID())

	// Dry run first: it must report without deleting.
	rep, err := s.Purge(ctx, PurgeFilter{Subject: "acme.example", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.EntitiesErased == 0 {
		t.Error("dry run should report what it would erase")
	}
	st, _ := s.Stats(ctx)
	if st.Entities != 3 {
		t.Errorf("dry run deleted rows: entities = %d", st.Entities)
	}

	rep, err = s.Purge(ctx, PurgeFilter{Subject: "acme.example"})
	if err != nil {
		t.Fatal(err)
	}
	// 3 matches the seeded graph only because the cascade reaches every entity
	// through relations; without it the subdomain and IP would survive.
	if rep.EntitiesErased != 3 {
		t.Errorf("purged %d entities, want 3 (the cascade must reach the linked subdomain and IP)", rep.EntitiesErased)
	}
	st, _ = s.Stats(ctx)
	if st.Entities != 0 || st.Observations != 0 || st.Relations != 0 {
		t.Errorf("purge left residue: %+v", st)
	}
}

func TestPurgeNoFilterIsNoOp(t *testing.T) {
	s := newTestStore(t)
	seed(t, s, NewScanID())
	rep, err := s.Purge(context.Background(), PurgeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.EntitiesErased != 0 {
		t.Errorf("an unfiltered purge erased %d entities", rep.EntitiesErased)
	}
	st, _ := s.Stats(context.Background())
	if st.Entities != 3 {
		t.Errorf("entities = %d, want 3", st.Entities)
	}
}

func TestMigrationIsIdempotentAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "argus.db")

	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s1, NewScanID())
	s1.Close()

	// Reopening runs migrate again; it must not fail or duplicate data.
	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	st, err := s2.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Entities != 3 {
		t.Errorf("after reopen entities = %d, want 3", st.Entities)
	}
}

func TestConcurrentUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	scanID := NewScanID()

	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			e := sdk.NewEntity(sdk.TypeSubdomain, string(rune('a'+i))+".acme.example")
			now := time.Now().UTC()
			e.FirstSeen, e.LastSeen = now, now
			done <- s.UpsertBatch(ctx, scanID, Batch{Entities: []sdk.Entity{e}})
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent upsert failed: %v", err)
		}
	}
	st, _ := s.Stats(ctx)
	if st.Entities != 8 {
		t.Errorf("entities = %d, want 8", st.Entities)
	}
}

func TestEmptyBatchIsNoOp(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertBatch(context.Background(), "", Batch{}); err != nil {
		t.Errorf("empty batch should be a no-op, got %v", err)
	}
}

func TestRedactURLHidesCredentials(t *testing.T) {
	got := redactURL("postgres://argus:secret@db:5432/argus")
	if contains(got, "secret") {
		t.Errorf("redactURL leaked the password: %q", got)
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

func values(es []sdk.Entity) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Value
	}
	return out
}
