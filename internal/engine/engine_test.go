package engine

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/internal/audit"
	"github.com/WildanDeveloper/argus/internal/pipeline"
	"github.com/WildanDeveloper/argus/internal/policy"
	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// --- test doubles ---

type fakeScopeStore struct{ store.Store }

type recordingEmitter struct {
	emit   func(sdk.Finding) error
	events []Event
	store  store.Store
	scanID string
}

func (e *recordingEmitter) Emit(f sdk.Finding) error { return e.emit(f) }
func (e *recordingEmitter) PutEvidence(context.Context, sdk.EvidenceMeta, []byte) (sdk.EvidenceRef, error) {
	return sdk.EvidenceRef{}, nil
}
func (e *recordingEmitter) Progress(int, int) {}
func (e *recordingEmitter) Warn(msg string, _ ...any) {
	e.events = append(e.events, Event{Kind: "warning", Text: msg})
}

// testScope builds a scope covering example.com.
func testScope(t *testing.T) *policy.Scope {
	t.Helper()
	s := &policy.Scope{}
	s.Authorization = policy.Authorization{
		EngagementID: "TEST",
		AuthorizedBy: "test",
		ValidFrom:    time.Now().Add(-time.Hour),
		ValidUntil:   time.Now().Add(time.Hour),
		AllowedModes: []string{"passive", "semi-active", "active"},
	}
	s.Allow.Domains = []string{"example.com", "*.example.com"}
	return s
}

func newHarness(t *testing.T, mods ...sdk.Module) (*Orchestrator, store.Store, *audit.Log) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	guard, err := policy.NewGuard(testScope(t))
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.NewPolicy()
	pe, err := policy.NewEngine(pol, guard)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.New(audit.NewMemorySink(), "tester")
	if err != nil {
		t.Fatal(err)
	}

	opts := DefaultOptions()
	// Bind a case so the evidence chain and the case-scoped reads below have
	// something to bind to; an unbound case stores NULL and cannot be queried back.
	opts.CaseID = testCaseID
	opts.MaxDepth = 0
	opts.Workers = 4
	opts.TaskTimeout = 5 * time.Second
	opts.ScanTimeout = 30 * time.Second
	opts.Mode = sdk.ModeSemiActive

	// A real content-addressed store, so the evidence path under test is the same
	// one a scan uses rather than a stub.
	evStore, err := NewEvidenceStore(st, t.TempDir(),
		slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatal(err)
	}

	o, err := New(opts, Dependencies{
		Store: st, Audit: auditLog, Engine: pe, Guard: guard, Modules: mods,
		EvidenceStore: evStore,
		Logger:        slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError})),
		Now:           time.Now,
		DepsFor: func(man sdk.Manifest) (sdk.Deps, error) {
			return sdk.Deps{
				Log:    slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError})),
				Now:    time.Now,
				Config: map[string]any{},
			}, nil
		},
		PipelineConfig: pipeline.DefaultConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return o, st, auditLog
}

// testCaseID is the case every harness test binds to.
const testCaseID = "test-case"

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// echoModule emits one finding per record type, subject to the entity it discovers.
type echoModule struct {
	manifest sdk.Manifest
	fail     bool
	panics   bool
	run      func(ctx context.Context, t sdk.Task, e sdk.Emitter) error
}

func (m *echoModule) Manifest() sdk.Manifest { return m.manifest }

func (m *echoModule) Init(context.Context, sdk.Deps) error { return nil }
func (m *echoModule) Close() error                         { return nil }

func (m *echoModule) Run(ctx context.Context, task sdk.Task, e sdk.Emitter) error {
	if m.panics {
		panic("module bug")
	}
	if m.run != nil {
		return m.run(ctx, task, e)
	}
	if m.fail {
		return sdk.ErrOutOfScope
	}
	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")
	obs := sdk.Observation{
		Predicate:   "resolves_to",
		Object:      task.Target.ID,
		Source:      sdk.Source{Module: m.manifest.Name, Provider: "test", Method: "fixture"},
		Reliability: 'B',
		Credibility: '2',
		ObservedAt:  time.Now(),
	}
	return e.Emit(sdk.Finding{
		Entity:      ip,
		Relations:   []sdk.Relation{sdk.Rel(task.Target.ID, ip.ID, sdk.RelResolvesTo)},
		Observation: obs,
	})
}

func echoManifest(name string) sdk.Manifest {
	return sdk.Manifest{
		Name: name, Version: "1.0.0", Category: "domain",
		Consumes:    []sdk.EntityType{sdk.TypeDomain, sdk.TypeSubdomain},
		Produces:    []sdk.EntityType{sdk.TypeIP},
		Mode:        sdk.ModeSemiActive,
		EgressHosts: []string{"resolver.example"},
	}
}

func drain(o *Orchestrator) {
	for range o.Events() {
	}
}

// --- tests ---

func TestRunEndToEnd(t *testing.T) {
	mod := &echoModule{manifest: echoManifest("echo")}
	o, st, auditLog := newHarness(t, mod)

	stats, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{mod})
	drain(o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Findings != 1 {
		t.Errorf("findings = %d, want 1", stats.Findings)
	}

	// The finding must be retrievable with its provenance and a score.
	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")
	got, err := st.GetEntity(context.Background(), ip.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Confidence <= 0 {
		t.Errorf("confidence = %v; an entity with corroborating observations must not score zero", got.Confidence)
	}
	obs, err := st.Observations(context.Background(), ip.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(obs))
	}
	// The observation must be attributed to the discovered entity, not the scan
	// root: attributing every claim to the target would leave discovered entities
	// without evidence.
	if obs[0].Subject != ip.ID {
		t.Errorf("observation subject = %s, want the discovered entity %s", obs[0].Subject, ip.ID)
	}

	res, err := auditLog.Verify(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("audit chain broken after a scan: %s", res.BrokenReason)
	}
}

func TestOutOfScopeTargetIsRefused(t *testing.T) {
	// The most important refusal in the system: an operator naming a target the
	// engagement does not cover must get nothing, and no scan record.
	mod := &echoModule{manifest: echoManifest("echo")}
	o, st, _ := newHarness(t, mod)

	_, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "evil.com"), []sdk.Module{mod})
	drain(o)
	if err == nil {
		t.Fatal("an out-of-scope target must be refused")
	}
	stats, serr := st.Stats(context.Background())
	if serr != nil {
		t.Fatal(serr)
	}
	if stats.Entities != 0 || stats.Scans != 0 {
		t.Errorf("a refused scan left state behind: %+v", stats)
	}
}

func TestModeCeilingBlocksSemiActiveInPassiveScan(t *testing.T) {
	// A passive scan must not run a semi-active collector.
	mod := &echoModule{manifest: echoManifest("echo")}
	o, st, _ := newHarness(t, mod)
	o.opts.Mode = sdk.ModePassive

	stats, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{mod})
	drain(o)
	// Refusing to run is reported as an error, not a quiet no-op: an operator who
	// asked for work that policy forbids should be told, not left waiting.
	if err == nil {
		t.Fatal("a passive scan accepted a semi-active module")
	}
	if stats.Findings != 0 {
		t.Errorf("a semi-active module ran in a passive scan: %d findings", stats.Findings)
	}
	s, err := st.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Entities != 0 {
		t.Errorf("entities = %d, want 0", s.Entities)
	}
}

func TestModulePanicDoesNotKillTheScan(t *testing.T) {
	// Fail-safe: a bug in one collector must degrade one task, not the run.
	bad := &echoModule{manifest: echoManifest("panicky"), panics: true}
	good := &echoModule{manifest: echoManifest("well-behaved")}
	o, st, _ := newHarness(t, bad, good)

	stats, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{bad, good})
	drain(o)
	if err != nil {
		t.Fatalf("Run should survive a module panic: %v", err)
	}
	if stats.Panics == 0 {
		t.Error("the panic was not recorded")
	}
	if stats.Findings == 0 {
		t.Error("the healthy module produced nothing; one panic took down the scan")
	}
	s, _ := st.Stats(context.Background())
	if s.Entities == 0 {
		t.Error("the healthy module's findings were lost")
	}
}

func TestModuleFailureIsolated(t *testing.T) {
	bad := &echoModule{manifest: echoManifest("failing"), fail: true}
	good := &echoModule{manifest: echoManifest("well-behaved")}
	o, _, _ := newHarness(t, bad, good)

	stats, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{bad, good})
	drain(o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.OutOfScope == 0 {
		t.Error("an out-of-scope error from a module should be counted as such")
	}
	if stats.Findings == 0 {
		t.Error("the healthy module should still have produced findings")
	}
}

func TestDuplicateEntitiesCollapseInOneBatch(t *testing.T) {
	// Two modules reporting the same address must produce one entity and one
	// observation identity, or the graph forks on the first scan.
	m1 := &echoModule{manifest: echoManifest("first")}
	m2 := &echoModule{manifest: echoManifest("second")}
	o, st, _ := newHarness(t, m1, m2)

	if _, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{m1, m2}); err != nil {
		t.Fatal(err)
	}
	drain(o)

	s, err := st.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// One entity: two modules reporting the same address must not fork the graph.
	if s.Entities != 1 {
		t.Errorf("entities = %d, want 1; the same address reported twice must be one entity", s.Entities)
	}
	// Two observations, because the facts come from different sources. Collapsing
	// them would destroy the provenance the scorer needs to tell corroboration from
	// repetition: two modules agreeing is stronger evidence than one repeating
	// itself, and only separate observations can express that.
	if s.Observations != 2 {
		t.Errorf("observations = %d, want 2; one per source is required for scoring", s.Observations)
	}
	if s.Relations != 1 {
		t.Errorf("relations = %d, want 1; the same edge reported twice must be one row", s.Relations)
	}
}

func TestDryRunPlanReportsDenials(t *testing.T) {
	mod := &echoModule{manifest: echoManifest("echo")}
	o, _, _ := newHarness(t, mod)

	plan, err := o.Plan(sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{mod})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Modules) != 1 || plan.Modules[0].Name != "echo" {
		t.Errorf("permitted modules = %+v", plan.Modules)
	}
	if plan.Modules[0].EgressHosts == nil {
		t.Error("the plan must show which hosts the module will contact")
	}
}

func TestDryRunRefusesOutOfScope(t *testing.T) {
	mod := &echoModule{manifest: echoManifest("echo")}
	o, _, _ := newHarness(t, mod)

	if _, err := o.Plan(sdk.NewEntity(sdk.TypeDomain, "evil.com"), []sdk.Module{mod}); err == nil {
		t.Error("planning an out-of-scope target must fail")
	}
}

func TestBudgetStopsChaining(t *testing.T) {
	// The budget is captured when the orchestrator is built, so the limit has to be
	// set on the Budget itself; changing Options afterwards would silently do nothing.
	mod := &echoModule{manifest: echoManifest("echo")}
	o, _, _ := newHarness(t, mod)

	if exceeded, _ := o.budget.Exceeded(); exceeded {
		t.Fatal("precondition: a default budget should not be exhausted")
	}

	// A zero limit means "no limit", which is how Defaults expresses an unlimited
	// budget. Reaching a limit is what stops the scan, so consume one first.
	o.budget.opts.MaxEntities = 1
	if exceeded, _ := o.budget.Exceeded(); exceeded {
		t.Error("a limit of 1 should not be exhausted before any work is done")
	}
	o.budget.AddEntities(1)
	exceeded, why := o.budget.Exceeded()
	if !exceeded || why == "" {
		t.Errorf("a reached entity budget must be reported as exceeded with a reason; got exceeded=%v why=%q", exceeded, why)
	}

	// Other limits report independently.
	o.budget.opts.MaxEntities = 0
	o.budget.opts.MaxCostUSD = 1.00
	o.budget.AddCost(1.50)
	if exceeded, why := o.budget.Exceeded(); !exceeded || why == "" {
		t.Errorf("a reached cost budget must be reported; got exceeded=%v why=%q", exceeded, why)
	}
}

func TestSchedulerExhaustionClosesQueues(t *testing.T) {
	// The scan terminates when the task graph drains. Without the outstanding
	// counter, closing the queues after seeding would either drop every pivot or
	// block forever.
	s := newScheduler()
	q := s.queueFor("m", 4)
	if !s.enqueue("m", sdk.Task{Target: sdk.NewEntity(sdk.TypeDomain, "a.example")}, nil) {
		t.Fatal("enqueue failed")
	}
	if s.remaining() != 1 {
		t.Errorf("remaining = %d, want 1", s.remaining())
	}

	// A worker consumes the task and then reports completion. Exhaustion must not be
	// announced while work is still outstanding.
	if _, open := <-q; !open {
		t.Fatal("the queued task was not delivered")
	}
	if s.remaining() != 1 {
		t.Errorf("remaining = %d before done, want 1", s.remaining())
	}
	s.done()

	select {
	case <-s.exhausted():
	case <-time.After(time.Second):
		t.Fatal("queues were not closed once the task graph drained")
	}
	if _, open := <-q; open {
		t.Error("the queue still yields tasks after exhaustion")
	}
	// A late enqueue must be refused rather than panicking on a closed channel.
	if s.enqueue("m", sdk.Task{Target: sdk.NewEntity(sdk.TypeDomain, "b.example")}, nil) {
		t.Error("enqueue after exhaustion must be refused")
	}
}

func TestSchedulerQueueFullDropsRatherThanBlocks(t *testing.T) {
	// A full queue means the breadth cap is doing its job. Blocking there would let
	// one fan-out stall the entire scan behind a slow collector.
	s := newScheduler()
	s.queueFor("m", 1)
	ok1 := s.enqueue("m", sdk.Task{Target: sdk.NewEntity(sdk.TypeDomain, "a.example")}, nil)
	ok2 := s.enqueue("m", sdk.Task{Target: sdk.NewEntity(sdk.TypeDomain, "b.example")}, nil)
	if !ok1 {
		t.Error("the first enqueue should succeed")
	}
	if ok2 {
		t.Error("enqueue into a full queue must report failure rather than block")
	}
	// The dropped task must not leave the counter inflated, or the scheduler would
	// never announce exhaustion.
	if s.remaining() != 1 {
		t.Errorf("remaining = %d, want 1; a dropped task must not be counted", s.remaining())
	}
}

func TestResolveTarget(t *testing.T) {
	cases := map[string]sdk.EntityType{
		"example.com":      sdk.TypeDomain,
		"www.example.com":  sdk.TypeSubdomain,
		"1.1.1.1":          sdk.TypeIP,
		"2001:db8::1":      sdk.TypeIP,
		"AS64500":          sdk.TypeASN,
		"203.0.113.0/24":   sdk.TypeCIDR,
		"user@example.com": sdk.TypeEmail,
		"CVE-2021-44228":   sdk.TypeCVE,
		"eth:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed": sdk.TypeWallet,
	}
	for in, want := range cases {
		got, err := ResolveTarget(in)
		if err != nil {
			t.Errorf("ResolveTarget(%q): %v", in, err)
			continue
		}
		if got.Type != want {
			t.Errorf("ResolveTarget(%q).Type = %q, want %q", in, got.Type, want)
		}
	}
	if _, err := ResolveTarget(""); err == nil {
		t.Error("an empty target must be rejected")
	}
	if _, err := ResolveTarget("not a target at all"); err == nil {
		t.Error("garbage must be rejected")
	}
}

// evidenceModule stores an artifact and then emits a finding derived from it.
type evidenceModule struct {
	manifest sdk.Manifest
	keep     bool
}

func (m *evidenceModule) Manifest() sdk.Manifest               { return m.manifest }
func (m *evidenceModule) Init(context.Context, sdk.Deps) error { return nil }
func (m *evidenceModule) Close() error                         { return nil }

func (m *evidenceModule) Run(ctx context.Context, task sdk.Task, e sdk.Emitter) error {
	if m.keep {
		if _, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source: "fixture://answer", Method: "test.lookup", MediaType: "application/json",
		}, []byte(`{"answer":"203.0.113.10"}`)); err != nil {
			return err
		}
	}
	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")
	return e.Emit(sdk.Finding{
		Entity:    ip,
		Relations: []sdk.Relation{sdk.Rel(task.Target.ID, ip.ID, sdk.RelResolvesTo)},
		Observation: sdk.Observation{
			Predicate:   "resolves_to",
			Object:      task.Target.ID,
			Source:      sdk.Source{Module: m.manifest.Name, Provider: "fixture", Method: "test.lookup"},
			Reliability: 'A',
			Credibility: '1',
		},
	})
}

func evidenceManifest(name string) sdk.Manifest {
	return sdk.Manifest{
		Name: name, Version: "1.0.0", Category: "domain",
		Consumes: []sdk.EntityType{sdk.TypeDomain},
		Produces: []sdk.EntityType{sdk.TypeIP},
		Mode:     sdk.ModeSemiActive,
		// An authoritative grade with an artifact should score far above the
		// unverified cap; the same grade without one must stay capped.
		EgressHosts: []string{"fixture.example"},
	}
}

func TestEvidenceLiftsConfidenceAboveTheUnverifiedCap(t *testing.T) {
	// This is the evidence-first rule made observable: the same finding from the
	// same authoritative source is capped at 0.5 without a retrievable artifact and
	// scores far above it with one.
	withEvidence := &evidenceModule{manifest: evidenceManifest("evidenced"), keep: true}
	withoutEvidence := &evidenceModule{manifest: evidenceManifest("unevidenced"), keep: false}

	score := func(m *evidenceModule) (float64, []store.Evidence) {
		o, st, _ := newHarness(t, m)
		if _, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{m}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		drain(o)
		ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")
		got, err := st.GetEntity(context.Background(), ip.ID)
		if err != nil {
			t.Fatalf("entity not stored: %v", err)
		}
		recs, err := st.EvidenceForCase(context.Background(), testCaseID, 0)
		if err != nil {
			t.Fatal(err)
		}
		return got.Confidence, recs
	}

	capped, cappedEv := score(withoutEvidence)
	if len(cappedEv) != 0 {
		t.Errorf("expected no evidence records, got %d", len(cappedEv))
	}
	if capped > 0.5 {
		t.Errorf("unverified confidence %.4f exceeds the 0.5 cap; the evidence-first rule is not being applied", capped)
	}

	verified, verifiedEv := score(withEvidence)
	if len(verifiedEv) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(verifiedEv))
	}
	if verified <= 0.5 {
		t.Errorf("confidence %.4f is still capped despite a retained artifact", verified)
	}
	// An authoritative, corroborated source is the top of the Admiralty scale, so it
	// should land near the maximum rather than merely above the cap.
	if verified < 0.9 {
		t.Errorf("confidence %.4f is too low for A/1 evidence with an artifact", verified)
	}
}

func TestEvidenceRecordIsLinkedToTheObservation(t *testing.T) {
	m := &evidenceModule{manifest: evidenceManifest("linked"), keep: true}
	o, st, _ := newHarness(t, m)
	if _, err := o.Run(context.Background(), sdk.NewEntity(sdk.TypeDomain, "example.com"), []sdk.Module{m}); err != nil {
		t.Fatal(err)
	}
	drain(o)

	ip := sdk.NewEntity(sdk.TypeIP, "203.0.113.10")
	obs, err := st.Observations(context.Background(), ip.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(obs))
	}
	if len(obs[0].Evidence) == 0 {
		t.Fatal("the observation carries no evidence reference, so a reviewer cannot reach the artifact")
	}
}
