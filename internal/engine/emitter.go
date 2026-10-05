package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/WildanDeveloper/argus/internal/pipeline"
	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// emitter is the sdk.Emitter handed to a module.
//
// Findings are buffered and written as one batch. A module that emits a thousand
// findings for one entity would otherwise cause a thousand transactions, which
// on a shared SQLite file is the difference between a scan that finishes and one
// that spends its time in fsync.
type emitter struct {
	orch      *Orchestrator
	module    sdk.Manifest
	pipe      *Pipeline
	chainNext func(sdk.Entity, int) bool
	task      sdk.Task
	ctx       context.Context

	mu       sync.Mutex
	batch    store.Batch
	pending  []sdk.Finding
	evidence []sdk.EvidenceRef
	done     chan struct{}
	closed   bool
}

func appendRef(refs []sdk.EvidenceRef, r sdk.EvidenceRef) []sdk.EvidenceRef {
	if containsRef(refs, r) {
		return refs
	}
	return append(refs, r)
}

// Emit reports one finding.
func (e *emitter) Emit(f sdk.Finding) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if f.Entity.ID == "" {
		// A finding with no identity cannot be stored or deduplicated. Skip it
		// rather than writing a row nothing can reference.
		e.warn("emitted finding with no entity id")
		return nil
	}

	// Snapshot the evidence captured for this task before taking the write lock.
	// Reading it under the same lock used for the batch would require unlocking in
	// the middle of the append, which is where a deadlock creeps in.
	e.mu.Lock()
	evidence := append([]sdk.EvidenceRef(nil), e.evidence...)
	e.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return fmt.Errorf("emitter closed")
	}

	// Modules never set confidence: the scorer owns it.
	f.Entity.Confidence = 0
	if f.Observation.ObservedAt.IsZero() {
		f.Observation.ObservedAt = e.orch.now()
	}
	if f.Observation.Source.Module == "" {
		f.Observation.Source.Module = e.module.Name
	}
	// The subject of a claim is the thing it is a claim about. When a module leaves
	// it unset, the entity the finding discovered is the only defensible default.
	//
	// Pointing it at the task target instead would be wrong: "acme.example resolves
	// to 203.0.113.10" attributed to the domain would leave the IP carrying no
	// evidence at all, so its confidence would stay at zero and the address would
	// look unsupported even though two resolvers confirmed it.
	if f.Observation.Subject == "" {
		f.Observation.Subject = f.Entity.ID
	}
	// Attach any evidence this task captured. This is the mechanism behind the
	// evidence-first rule: an observation with a retrievable artifact may exceed the
	// unverified cap, and one without may not.
	for _, ref := range evidence {
		f.Observation.Evidence = appendRef(f.Observation.Evidence, ref)
	}
	// Derive the observation's identity here rather than requiring each module to
	// do it: an observation with no ID is skipped by the store, and the finding
	// then exists with no provenance at all.
	f.Observation.EnsureID()

	e.batch.Entities = appendUniqueEntity(e.batch.Entities, f.Entity)
	e.batch.Observations = appendUniqueObservation(e.batch.Observations, f.Observation)
	for _, r := range f.Relations {
		r.Confidence = 0
		e.batch.Relations = appendUniqueRelation(e.batch.Relations, r)
	}
	if f.Kind != "" {
		e.batch.Findings = append(e.batch.Findings, f)
	}
	e.pending = append(e.pending, f)

	e.orch.bump(func(s *Stats) { s.Findings++ })
	select {
	case e.done <- struct{}{}:
	default:
	}
	return nil
}

// PutEvidence stores an artifact for the current task.
//
// The reference is remembered and attached to every finding this task emits, which
// is what promotes those findings above the unverified cap. A module that stores
// evidence but never links it would leave its own observations looking unsupported,
// so the link is made here rather than left to the module to remember.
func (e *emitter) PutEvidence(ctx context.Context, meta sdk.EvidenceMeta, raw []byte) (sdk.EvidenceRef, error) {
	if err := e.ctx.Err(); err != nil {
		return sdk.EvidenceRef{}, err
	}
	if e.orch.deps.EvidenceStore == nil {
		return sdk.EvidenceRef{}, fmt.Errorf("engine: no evidence store configured")
	}
	if meta.CapturedAt.IsZero() {
		meta.CapturedAt = e.orch.now()
	}
	if meta.Collector == "" {
		meta.Collector = e.module.Name + "@" + e.module.Version
	}

	ref, err := e.orch.Store(ctx, e.orch.scanID(), e.task.CaseID, meta, raw)
	if err != nil {
		return sdk.EvidenceRef{}, err
	}

	e.mu.Lock()
	if !containsRef(e.evidence, ref) {
		e.evidence = append(e.evidence, ref)
	}
	e.mu.Unlock()

	return ref, nil
}

func containsRef(refs []sdk.EvidenceRef, r sdk.EvidenceRef) bool {
	for _, x := range refs {
		if x.ID == r.ID {
			return true
		}
	}
	return false
}

// Progress reports completion counters. It is advisory and never blocks.
func (e *emitter) Progress(done, total int) {
	e.orch.emit(Event{Kind: "progress", Module: e.module.Name, Extra: map[string]any{"done": done, "total": total}})
}

// Warn reports a non-fatal problem.
func (e *emitter) Warn(msg string, kv ...any) {
	e.warn(msg, kv...)
}

func (e *emitter) warn(msg string, kv ...any) {
	args := append([]any{"module", e.module.Name, "message", msg}, kv...)
	e.orch.log.Warn("module warning", args...)
	e.orch.emit(Event{Kind: "warning", Module: e.module.Name, Text: msg})
}

// drain writes the buffered batch.
func (e *emitter) drain() {
	e.mu.Lock()
	b := e.batch
	e.batch = store.Batch{}
	e.closed = true
	e.mu.Unlock()

	if b.IsEmpty() {
		return
	}
	if e.orch.deps.Store == nil {
		return
	}
	// Use a context detached from the task: findings already collected must be
	// persisted even if the task was cancelled or timed out.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 30*time.Second)
	defer cancel()

	e.orch.budget.AddEntities(int64(len(b.Entities)))
	e.orch.budget.AddRequests(int64(len(b.Entities)))
	if e.module.CostPerCall > 0 {
		e.orch.budget.AddCost(e.module.CostPerCall * float64(len(b.Entities)))
	}

	if err := e.orch.deps.Store.UpsertBatch(ctx, e.orch.scanID(), b); err != nil {
		e.orch.log.Error("persist batch", "module", e.module.Name, "err", err.Error())
		e.orch.bump(func(s *Stats) { s.Errors++ })
		return
	}
	// Score what was just stored so entities carry a confidence an analyst can
	// filter on.
	e.pipe.Score(ctx, e.orch.scanID(), b)
}

func appendUniqueEntity(list []sdk.Entity, e sdk.Entity) []sdk.Entity {
	for i := range list {
		if list[i].ID == e.ID {
			// Merge tags rather than replacing: two modules can each contribute
			// context to the same entity in one batch.
			for _, t := range e.Tags {
				list[i].AddTag(t)
			}
			return list
		}
	}
	return append(list, e)
}

func appendUniqueObservation(list []sdk.Observation, o sdk.Observation) []sdk.Observation {
	for i := range list {
		if list[i].ID == o.ID {
			return list
		}
	}
	return append(list, o)
}

func appendUniqueRelation(list []sdk.Relation, r sdk.Relation) []sdk.Relation {
	for i := range list {
		if list[i].ID == r.ID {
			// Keep the strongest confidence and never promote a heuristic edge.
			if r.Confidence > list[i].Confidence {
				list[i].Confidence = r.Confidence
			}
			list[i].Heuristic = list[i].Heuristic && r.Heuristic
			return list
		}
	}
	return append(list, r)
}

// scanID returns the current scan ID.
func (o *Orchestrator) scanID() string { return o.opts.ScanID }

// DryRunPlan describes what a scan would do without executing it.
type DryRunPlan struct {
	Target     sdk.Entity
	Modules    []DryRunModule
	Denied     []PolicyDenial
	Mode       sdk.Mode
	MaxDepth   int
	WouldPivot bool
}

// PolicyDenial records why a module or a target was refused.
type PolicyDenial struct {
	Rule   string
	Reason string
}

// DependedOn reports the configured auto-chaining depth, for plan output.
func (p DryRunPlan) DependedOn() int { return p.MaxDepth }

// DryRunModule is one planned module invocation.
type DryRunModule struct {
	Name        string
	Mode        sdk.Mode
	Sensitivity sdk.Sensitivity
	Consumes    []sdk.EntityType
	Produces    []sdk.EntityType
	EgressHosts []string
	Secrets     []string
	Reason      string
}

// Plan produces the execution plan for --dry-run.
//
// Running the plan matters: an analyst who cannot see what a command will do
// cannot judge whether it is safe, and a scan that quietly runs a collector
// nobody expected is exactly the kind of surprise this tool must not produce.
func (o *Orchestrator) Plan(target sdk.Entity, modules []sdk.Module) (DryRunPlan, error) {
	plan := DryRunPlan{Target: target, Mode: o.opts.Mode}

	if o.deps.Guard != nil {
		d := o.deps.Guard.Check(target)
		if !d.Allowed {
			plan.Denied = append(plan.Denied, PolicyDenial{Rule: d.Rule, Reason: d.Reason})
			return plan, fmt.Errorf("%w: %s", sdk.ErrOutOfScope, d.Reason)
		}
		if ok, reason := o.deps.Guard.Scope().Authorization.Allows(o.opts.Mode, o.now()); !ok {
			plan.Denied = append(plan.Denied, PolicyDenial{Rule: "authorization", Reason: reason})
			return plan, fmt.Errorf("%w: %s", sdk.ErrOutOfScope, reason)
		}
	}

	allowed, denied := o.filterModules(target, modules)
	for _, d := range denied {
		plan.Denied = append(plan.Denied, PolicyDenial{Rule: d.Rule, Reason: d.Reason})
	}
	sort.Slice(plan.Denied, func(i, j int) bool { return plan.Denied[i].Rule < plan.Denied[j].Rule })

	for _, m := range allowed {
		man := m.Manifest()
		plan.Modules = append(plan.Modules, DryRunModule{
			Name: man.Name, Mode: man.Mode, Sensitivity: man.Sensitivity,
			Consumes: man.Consumes, Produces: man.Produces,
			EgressHosts: man.EgressHosts, Secrets: man.SecretNames(), Reason: "policy-ok",
		})
	}
	sort.Slice(plan.Modules, func(i, j int) bool { return plan.Modules[i].Name < plan.Modules[j].Name })
	plan.MaxDepth = o.opts.MaxDepth
	plan.MaxDepth = o.opts.MaxDepth
	plan.WouldPivot = o.opts.MaxDepth > 0
	return plan, nil
}

// Pipeline wraps the analysis stages for one module's output.
type Pipeline struct {
	inner *pipeline.Pipeline
	store store.Store
	log   *slog.Logger
}

// pipelineFor lazily builds the per-module pipeline.
func (o *Orchestrator) pipelineFor(m sdk.Module) (*Pipeline, error) {
	name := m.Manifest().Name
	o.pipeMu.Lock()
	defer o.pipeMu.Unlock()
	if p, ok := o.pipelines[name]; ok {
		return p, nil
	}
	p, err := pipeline.New(pipeline.Config{Logger: o.log, Now: o.now})
	if err != nil {
		return nil, fmt.Errorf("engine: pipeline for %s: %w", name, err)
	}
	out := &Pipeline{inner: p, store: o.deps.Store, log: o.log}
	o.pipelines[name] = out
	return out, nil
}

// Score computes and persists confidence for a batch.
//
// Failures here are surfaced rather than swallowed: an unscored entity looks
// exactly like an entity whose sources are unreliable, and an analyst cannot tell
// the two apart from the data.
func (p *Pipeline) Score(ctx context.Context, scanID string, b store.Batch) {
	if p == nil || p.store == nil {
		return
	}
	scored := p.inner.ScoreBatch(b.Entities, b.Observations, b.Relations)
	if err := p.store.UpsertBatch(ctx, scanID, store.Batch{
		Entities:  scored.Entities,
		Relations: scored.Relations,
	}); err != nil {
		p.log.Error("persist scores", "scan", scanID, "err", err.Error())
	}
}

// Flush is a no-op hook that lets the orchestrator drain a pipeline per task.
func (p *Pipeline) Flush(ctx context.Context) {}

// Store writes an evidence record through the store.
func (o *Orchestrator) Store(ctx context.Context, scanID, caseID string, meta sdk.EvidenceMeta, raw []byte) (sdk.EvidenceRef, error) {
	if o.deps.Store == nil {
		return sdk.EvidenceRef{}, fmt.Errorf("engine: no evidence store configured")
	}
	return o.deps.EvidenceStore.Store(ctx, scanID, caseID, meta, raw)
}
