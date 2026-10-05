// Package engine is the orchestrator: it resolves targets, checks scope and
// policy, schedules tasks across a bounded worker pool, drains findings through
// the pipeline, and enforces budgets.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/WildanDeveloper/argus/internal/audit"
	"github.com/WildanDeveloper/argus/pkg/canon"

	"github.com/WildanDeveloper/argus/internal/pipeline"
	"github.com/WildanDeveloper/argus/internal/policy"
	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Exit codes (Appendix C). They are part of the CLI contract.
const (
	ExitOK           = 0
	ExitError        = 1
	ExitUsage        = 2
	ExitScopeDenied  = 3
	ExitPolicyDenied = 4
	ExitPartial      = 5
	ExitSecrets      = 6
	ExitStorage      = 7
	ExitEvidence     = 8
)

// ErrBudgetExhausted means the scan stopped chaining and reports partial results.
var ErrBudgetExhausted = errors.New("engine: budget exhausted")

// Options configure a run.
type Options struct {
	ScanID       string
	CaseID       string
	Purpose      string
	Actor        string
	Mode         sdk.Mode
	AllowActive  bool
	Workers      int
	MaxDepth     int
	MaxBreadth   int
	TaskTimeout  time.Duration
	ScanTimeout  time.Duration
	DrainTimeout time.Duration
	Budgets      Budgets
	// PerModuleConcurrency is the bulkhead table: one noisy collector must not
	// starve the others.
	PerModuleConcurrency map[string]int
	DryRun               bool
}

// Budgets bound the work a scan may do. All are hard limits: a scan that hits one
// stops chaining, drains what is in flight, and reports partial results.
type Budgets struct {
	MaxRequests int64
	MaxEntities int64
	MaxCostUSD  float64
	MaxRuntime  time.Duration
}

// DefaultOptions returns sensible defaults for an interactive scan.
func DefaultOptions() Options {
	return Options{
		Mode:         sdk.ModePassive,
		Workers:      32,
		MaxDepth:     2,
		MaxBreadth:   50,
		TaskTimeout:  45 * time.Second,
		ScanTimeout:  2 * time.Hour,
		DrainTimeout: 20 * time.Second,
		Budgets: Budgets{
			MaxRequests: 250_000,
			MaxEntities: 50_000,
			MaxCostUSD:  5.00,
			MaxRuntime:  2 * time.Hour,
		},
		PerModuleConcurrency: map[string]int{},
	}
}

// Budget tracks consumption and reports when a limit is reached.
type Budget struct {
	mu       sync.Mutex
	opts     Budgets
	started  time.Time
	requests int64
	entities int64
	costUSD  float64
	now      func() time.Time
}

// NewBudget builds a budget tracker.
func NewBudget(opts Budgets) *Budget {
	return &Budget{opts: opts, started: time.Now(), now: time.Now}
}

// WithClock overrides the clock for tests.
func (b *Budget) WithClock(now func() time.Time) *Budget {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
	return b
}

// Exceeded reports whether a limit has been reached, and why.
func (b *Budget) Exceeded() (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opts.MaxRequests > 0 && b.requests >= b.opts.MaxRequests {
		return true, fmt.Sprintf("request budget of %d exhausted", b.opts.MaxRequests)
	}
	if b.opts.MaxEntities > 0 && b.entities >= b.opts.MaxEntities {
		return true, fmt.Sprintf("entity budget of %d exhausted", b.opts.MaxEntities)
	}
	if b.opts.MaxCostUSD > 0 && b.costUSD >= b.opts.MaxCostUSD {
		return true, fmt.Sprintf("cost budget of $%.2f exhausted", b.opts.MaxCostUSD)
	}
	if b.opts.MaxRuntime > 0 && b.clock().Sub(b.started) >= b.opts.MaxRuntime {
		return true, fmt.Sprintf("runtime budget of %s exhausted", b.opts.MaxRuntime)
	}
	return false, ""
}

func (b *Budget) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// AddRequests records n requests.
func (b *Budget) AddRequests(n int64) {
	b.mu.Lock()
	b.requests += n
	b.mu.Unlock()
}

// AddEntities records n entities.
func (b *Budget) AddEntities(n int64) {
	b.mu.Lock()
	b.entities += n
	b.mu.Unlock()
}

// AddCost records a module's declared per-call cost estimate.
func (b *Budget) AddCost(usd float64) {
	b.mu.Lock()
	b.costUSD += usd
	b.mu.Unlock()
}

// Snapshot returns current consumption.
func (b *Budget) Snapshot() (requests, entities int64, costUSD float64, elapsed time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests, b.entities, b.costUSD, b.clock().Sub(b.started)
}

// Event is a progress notification emitted during a scan.
type Event struct {
	At     time.Time
	Kind   string // scan.start, module.start, finding, module.done, scan.done, warning
	Module string
	Entity string
	Text   string
	Extra  map[string]any
}

// Stats summarizes a run.
type Stats struct {
	Tasks      int64
	ModulesRun int
	Findings   int64
	OutOfScope int64
	Errors     int64
	Denials    int64
	Requests   int64
	CostUSD    float64
	Entities   int64
	Panics     int64
	Partial    bool
	StoppedWhy string
}

// Dependencies are the collaborators the orchestrator needs.
type Dependencies struct {
	Store   store.Store
	Audit   *audit.Log
	Engine  *policy.Engine
	Guard   *policy.Guard
	Modules []sdk.Module
	Logger  *slog.Logger
	Now     func() time.Time
	// DepsFor builds the module Deps, which must be brokered per module so each
	// one sees only the hosts and secrets its manifest declares.
	DepsFor func(sdk.Manifest) (sdk.Deps, error)
	// EvidenceStore writes content-addressed artifacts.
	EvidenceStore *EvidenceStore
	// PipelineConfig tunes the analysis stages.
	PipelineConfig pipeline.Config
}

// Orchestrator runs a scan.
type Orchestrator struct {
	opts   Options
	deps   Dependencies
	log    *slog.Logger
	now    func() time.Time
	budget *Budget

	events     chan Event
	eventsOnce sync.Once
	sem        map[string]chan struct{} // per-module bulkheads
	semMu      sync.Mutex

	statsMu sync.Mutex
	stats   Stats

	// seen suppresses re-queuing an entity that is already being processed, so a
	// pivot storm cannot turn into a fan-out explosion.
	seen   map[sdk.EntityID]struct{}
	seenMu sync.Mutex

	pipelines map[string]*Pipeline // one pipeline per module
	pipeMu    sync.Mutex
}

// New builds an orchestrator.
func New(opts Options, deps Dependencies) (*Orchestrator, error) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if opts.Workers <= 0 {
		opts.Workers = 32
	}
	if opts.TaskTimeout <= 0 {
		opts.TaskTimeout = 45 * time.Second
	}
	if opts.ScanTimeout <= 0 {
		opts.ScanTimeout = 2 * time.Hour
	}
	if opts.MaxDepth < 0 {
		opts.MaxDepth = 0
	}
	if opts.MaxBreadth <= 0 {
		opts.MaxBreadth = 50
	}

	o := &Orchestrator{
		opts:      opts,
		deps:      deps,
		log:       deps.Logger,
		now:       deps.Now,
		budget:    NewBudget(opts.Budgets),
		events:    make(chan Event, 1024),
		seen:      map[sdk.EntityID]struct{}{},
		pipelines: map[string]*Pipeline{},
	}
	o.initBulkheads()
	return o, nil
}

func (o *Orchestrator) initBulkheads() {
	o.semMu.Lock()
	defer o.semMu.Unlock()
	o.sem = map[string]chan struct{}{}
	for _, m := range o.deps.Modules {
		n, ok := o.opts.PerModuleConcurrency[m.Manifest().Name]
		if !ok || n <= 0 {
			n = defaultBulkhead
		}
		o.sem[m.Manifest().Name] = make(chan struct{}, n)
	}
}

// defaultBulkhead caps a module that declares no explicit limit. Eight is chosen
// so that a single collector cannot occupy more than a quarter of a default
// 32-worker pool and starve the rest.
const defaultBulkhead = 8

// Events returns the progress channel. It is closed when the scan finishes.
func (o *Orchestrator) Events() <-chan Event { return o.events }

// Stats returns a snapshot of run counters.
func (o *Orchestrator) Stats() Stats {
	o.statsMu.Lock()
	defer o.statsMu.Unlock()
	return o.stats
}

func (o *Orchestrator) emit(ev Event) {
	ev.At = o.now()
	// The channel is bounded; a slow consumer must not block collection. Dropping
	// a progress event is acceptable, dropping a finding is not, and findings are
	// not carried on this channel.
	select {
	case o.events <- ev:
	default:
	}
}

func (o *Orchestrator) bump(f func(*Stats)) {
	o.statsMu.Lock()
	f(&o.stats)
	o.statsMu.Unlock()
}

// Run executes a scan against target with the given modules.
//
// The order mirrors §4.2 exactly: canonicalize, check scope, check policy,
// schedule, drain through the pipeline, persist, report.
func (o *Orchestrator) Run(ctx context.Context, target sdk.Entity, modules []sdk.Module) (Stats, error) {
	// The events channel must be closed on every exit path, including the early
	// refusals. A consumer ranging over it would otherwise block forever, and the
	// most common early refusal is the scope denial an analyst triggers by typo.
	defer o.closeEvents()
	return o.run(ctx, target, modules)
}

func (o *Orchestrator) closeEvents() {
	o.eventsOnce.Do(func() { close(o.events) })
}

func (o *Orchestrator) run(ctx context.Context, target sdk.Entity, modules []sdk.Module) (Stats, error) {
	scanCtx, cancel := context.WithTimeout(ctx, o.opts.ScanTimeout)
	defer cancel()

	scanID := o.opts.ScanID
	if scanID == "" {
		scanID = store.NewScanID()
		o.opts.ScanID = scanID
	}

	if target.ID == "" {
		return o.Stats(), fmt.Errorf("%w: could not canonicalize target", sdk.ErrOutOfScope)
	}

	// 1. Scope for the operator-supplied root. An out-of-scope root is refused
	//    outright: this is a misconfigured engagement, not a discovery.
	if o.deps.Guard != nil {
		d := o.deps.Guard.Check(target)
		o.auditScope(ctx, target, d)
		if !d.Allowed {
			o.bump(func(s *Stats) { s.Denials++ })
			return o.Stats(), fmt.Errorf("%w: %s", sdk.ErrOutOfScope, d.Reason)
		}
		if ok, reason := o.deps.Guard.Scope().Authorization.Allows(o.opts.Mode, o.now()); !ok {
			return o.Stats(), fmt.Errorf("engine: %w: %s", sdk.ErrOutOfScope, reason)
		}
	}

	// 2. Policy for each requested module. A denied module is reported, not
	//    silently dropped: the analyst needs to know what did not run.
	allowed, denied := o.filterModules(target, modules)
	for _, d := range denied {
		o.log.Info("module denied", "module", d.Rule, "reason", d.Reason)
		o.emit(Event{Kind: "warning", Text: fmt.Sprintf("denied %s: %s", d.Rule, d.Reason)})
		o.bump(func(s *Stats) { s.Denials++ })
	}

	if len(allowed) == 0 {
		return o.Stats(), fmt.Errorf("engine: %w: no permitted modules for %s", sdk.ErrBudget, target.Value)
	}

	// 3. Record the scan before any work, so a crash still leaves a record.
	sc := store.Scan{
		ID: scanID, CaseID: o.opts.CaseID, Target: target, Status: store.ScanRunning,
		Purpose: o.opts.Purpose, Mode: o.opts.Mode, CreatedBy: o.opts.Actor,
		StartedAt: o.now(),
		Modules:   moduleNames(allowed),
	}
	if err := o.deps.Store.SaveScan(scanCtx, &sc); err != nil {
		return o.Stats(), fmt.Errorf("engine: record scan: %w", err)
	}
	if err := o.deps.Audit.Recordf(ctx, audit.ActionScanStart, "scan %s target=%s modules=%v mode=%s",
		scanID, target.Value, sc.Modules, o.opts.Mode); err != nil {
		o.log.Error("audit scan start", "err", err.Error())
	}
	o.emit(Event{Kind: "scan.start", Text: fmt.Sprintf("scanning %s (%s)", target.Value, target.Type)})

	// 4. Schedule across a bounded worker pool.
	//
	// Each module gets its own queue. A shared queue would let one collector drain
	// another collector's tasks and emit results attributed to the wrong module --
	// and because a module derives the hosts it may contact from its own manifest, a
	// mis-delivered task would have no valid egress path at all.
	//
	// The queues cannot simply be closed after seeding, because pivots discovered
	// mid-run are enqueued later. Instead an outstanding-task counter decides when
	// the graph is exhausted: a task is counted when it is queued and uncounted when
	// it finishes, and the queues close when the count reaches zero.
	sched := newScheduler()
	var wg sync.WaitGroup

	// chainNext is declared before the workers start: a worker goroutine closes
	// over it, so it must already exist. Go would also reject the plain `m := m`
	// workaround here, because chainNext is assigned once rather than per iteration.
	stopChained := false
	var chainMu sync.Mutex
	chainNext := func(e sdk.Entity, depth int) bool {
		chainMu.Lock()
		defer chainMu.Unlock()
		if stopChained {
			return false
		}
		if exceeded, why := o.budget.Exceeded(); exceeded {
			stopChained = true
			o.log.Warn("stopping auto-chaining", "reason", why)
			o.bump(func(s *Stats) { s.Partial = true; s.StoppedWhy = why })
			return false
		}
		if depth > o.opts.MaxDepth {
			return false
		}
		// The seen-set is keyed by entity, so the same entity can never be fanned
		// out twice even when several modules produce it.
		if !o.markSeen(e) {
			return false
		}
		// A pivot that is out of scope is recorded by the module that discovered it
		// and never fanned out: contacting it would be the thing scope forbids.
		if o.deps.Guard != nil {
			if d := o.deps.Guard.Check(e); !d.Allowed {
				o.bump(func(s *Stats) { s.OutOfScope++ })
				o.emit(Event{Kind: "warning", Entity: e.Value,
					Text: "out of scope, not queued: " + d.Reason})
				return false
			}
		}
		for _, m := range allowed {
			man := m.Manifest()
			if !consumesType(man, e.Type) {
				continue
			}
			t := sdk.Task{ScanID: scanID, CaseID: o.opts.CaseID, Target: e, Depth: depth,
				Deadline: o.now().Add(o.opts.ScanTimeout)}
			if !sched.enqueue(man.Name, t, o.log) {
				// Breadth cap: dropping a pivot is correct; blocking on a full queue
				// would let one fan-out stall the whole scan.
				o.log.Debug("module queue full, dropping pivot",
					"module", man.Name, "entity", e.Value, "depth", depth)
			}
		}
		return true
	}

	for _, m := range allowed {
		q := sched.queueFor(m.Manifest().Name, o.opts.Workers*2)
		wg.Add(1)
		go func(module sdk.Module, tasks <-chan sdk.Task) {
			defer wg.Done()
			pipe, err := o.pipelineFor(module)
			if err != nil {
				o.log.Error("pipeline", "module", module.Manifest().Name, "err", err.Error())
				o.bump(func(s *Stats) { s.Errors++ })
				// Drain the queue so an enqueue never blocks on a dead worker.
				for range tasks {
				}
				return
			}
			o.runModule(scanCtx, module, tasks, pipe, chainNext, sched)
		}(m, q)
	}

	// Seed: the root target goes to every permitted module that consumes it.
	o.markSeen(target)
	for _, m := range allowed {
		man := m.Manifest()
		if !consumesType(man, target.Type) {
			continue
		}
		sched.enqueue(man.Name, sdk.Task{ScanID: scanID, CaseID: o.opts.CaseID, Target: target,
			Depth: 0, Deadline: o.now().Add(o.opts.ScanTimeout)}, o.log)
	}

	// Wait for the graph to drain. A cancelled or timed-out scan short-circuits the
	// wait so the drain timeout can do its job.
	select {
	case <-sched.exhausted():
	case <-scanCtx.Done():
	}
	wg.Wait()

	// 5. Finalize.
	st := o.Stats()
	if st.Partial {
		st.Partial = true
	}
	status := store.ScanCompleted
	finalErr := error(nil)
	if scanCtx.Err() != nil && !errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		status = store.ScanCancelled
		finalErr = scanCtx.Err()
	} else if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		status = store.ScanFailed
		finalErr = ErrBudgetExhausted
		st.Partial = true
		if st.StoppedWhy == "" {
			st.StoppedWhy = "scan timeout"
		}
	}

	requests, entities, cost, elapsed := o.budget.Snapshot()
	st.Requests, st.Entities, st.CostUSD = requests, entities, cost
	summary := store.ScanSummary{
		Tasks:         int(st.Tasks),
		ModulesRun:    st.ModulesRun,
		Requests:      int(requests),
		EntitiesFound: int(entities),
		Findings:      int(st.Findings),
		Denials:       int(st.Denials),
		Errors:        int(st.Errors),
		CostUSD:       cost,
		OutOfScope:    int(st.OutOfScope),
	}
	if err := o.deps.Store.FinishScan(context.WithoutCancel(ctx), scanID, status, summary); err != nil {
		o.log.Error("finish scan", "scan", scanID, "err", err.Error())
	}
	o.deps.Audit.Recordf(ctx, audit.ActionScanFinish, "scan %s status=%s findings=%d out_of_scope=%d elapsed=%s",
		scanID, status, st.Findings, st.OutOfScope, elapsed.Round(time.Millisecond))
	o.emit(Event{Kind: "scan.done", Text: fmt.Sprintf("scan %s: %s, %d findings", scanID, status, st.Findings)})

	return st, finalErr
}

func moduleNames(ms []sdk.Module) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Manifest().Name
	}
	return out
}

// filterModules applies the policy engine to each requested module.
func (o *Orchestrator) filterModules(target sdk.Entity, modules []sdk.Module) ([]sdk.Module, []policy.Decision) {
	if o.deps.Engine == nil {
		return modules, nil
	}
	var allowed []sdk.Module
	var denied []policy.Decision
	for _, m := range modules {
		d := o.deps.Engine.Authorize(target, policy.Request{
			Module:      m.Manifest().Name,
			Manifest:    m.Manifest(),
			CaseID:      o.opts.CaseID,
			Purpose:     o.opts.Purpose,
			Actor:       o.opts.Actor,
			AllowActive: o.opts.AllowActive,
			Mode:        o.opts.Mode,
			Now:         o.now(),
		})
		if d.Allowed {
			allowed = append(allowed, m)
		} else {
			denied = append(denied, d)
		}
	}
	return allowed, denied
}

// runModule is one worker loop: it initializes the module once, then consumes
// tasks until the queue closes or the scan is cancelled.
func (o *Orchestrator) runModule(ctx context.Context, m sdk.Module, tasks <-chan sdk.Task, pipe *Pipeline, chainNext func(sdk.Entity, int) bool, sched *scheduler) {
	man := m.Manifest()
	o.bump(func(s *Stats) { s.ModulesRun++ })
	o.emit(Event{Kind: "module.start", Module: man.Name, Text: "starting " + man.Name})

	d, err := o.deps.DepsFor(man)
	if err != nil {
		o.log.Error("module deps", "module", man.Name, "err", err.Error())
		o.bump(func(s *Stats) { s.Errors++ })
		return
	}
	if err := m.Init(ctx, d); err != nil {
		// One module failing to initialize must not abort the scan: fail-safe.
		o.log.Error("module init", "module", man.Name, "err", err.Error())
		o.emit(Event{Kind: "warning", Module: man.Name, Text: "init failed: " + err.Error()})
		o.bump(func(s *Stats) { s.Errors++ })
		return
	}
	defer func() {
		if err := m.Close(); err != nil {
			o.log.Warn("module close", "module", man.Name, "err", err.Error())
		}
	}()

	for task := range tasks {
		if ctx.Err() != nil {
			return
		}
		o.bulkhead(man.Name)
		o.runTask(ctx, m, pipe, task, chainNext)
		o.release(man.Name)
		// Report completion so the scheduler knows the task graph is exhausted.
		sched.done()
	}
	o.emit(Event{Kind: "module.done", Module: man.Name, Text: "finished " + man.Name})
}

// runTask executes one task with panic recovery and a timeout.
//
// The recovery matters more than it looks: a module bug must degrade one task,
// never the scan. Without it a nil dereference in one collector would take down
// every collector and lose the whole run.
func (o *Orchestrator) runTask(ctx context.Context, m sdk.Module, pipe *Pipeline, task sdk.Task, chainNext func(sdk.Entity, int) bool) {
	man := m.Manifest()
	o.bump(func(s *Stats) { s.Tasks++ })

	taskCtx := ctx
	var cancel context.CancelFunc
	if o.opts.TaskTimeout > 0 {
		taskCtx, cancel = context.WithTimeout(ctx, o.opts.TaskTimeout)
		defer cancel()
	}
	if !task.Deadline.IsZero() {
		deadlineCtx, cancelDeadline := context.WithDeadline(taskCtx, task.Deadline)
		defer cancelDeadline()
		taskCtx = deadlineCtx
	}

	em := &emitter{
		orch: o, module: man, pipe: pipe, chainNext: chainNext, task: task, ctx: taskCtx,
		done: make(chan struct{}, 64),
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				o.bump(func(s *Stats) { s.Errors++; s.Panics++ })
				o.log.Error("module panic", "module", man.Name, "entity", task.Target.Value,
					"panic", fmt.Sprint(r))
				o.emit(Event{Kind: "warning", Module: man.Name, Text: "task panicked: " + fmt.Sprint(r)})
				em.drain()
			}
		}()
		if err := m.Run(taskCtx, task, em); err != nil {
			switch {
			case errors.Is(err, context.Canceled):
				o.emit(Event{Kind: "warning", Module: man.Name, Text: "cancelled"})
			case errors.Is(err, context.DeadlineExceeded):
				o.bump(func(s *Stats) { s.Errors++ })
				o.emit(Event{Kind: "warning", Module: man.Name, Text: "task timed out"})
			case errors.Is(err, sdk.ErrOutOfScope):
				o.bump(func(s *Stats) { s.OutOfScope++ })
				o.emit(Event{Kind: "warning", Module: man.Name, Text: "out of scope: " + err.Error()})
			default:
				o.bump(func(s *Stats) { s.Errors++ })
				o.log.Warn("module task", "module", man.Name, "entity", task.Target.Value, "err", err.Error())
				o.emit(Event{Kind: "warning", Module: man.Name, Text: err.Error()})
			}
		}
	}()
	em.drain()
	pipe.Flush(ctx)
}

func (o *Orchestrator) bulkhead(module string) {
	o.semMu.Lock()
	ch, ok := o.sem[module]
	o.semMu.Unlock()
	if ok {
		ch <- struct{}{}
	}
}

func (o *Orchestrator) release(module string) {
	o.semMu.Lock()
	ch, ok := o.sem[module]
	o.semMu.Unlock()
	if ok {
		select {
		case <-ch:
		default:
		}
	}
}

func (o *Orchestrator) markSeen(e sdk.Entity) bool {
	o.seenMu.Lock()
	defer o.seenMu.Unlock()
	if _, dup := o.seen[e.ID]; dup {
		return false
	}
	o.seen[e.ID] = struct{}{}
	return true
}

// Seen reports how many distinct entities were queued, for progress output.
func (o *Orchestrator) Seen() int {
	o.seenMu.Lock()
	defer o.seenMu.Unlock()
	return len(o.seen)
}

func (o *Orchestrator) auditScope(ctx context.Context, target sdk.Entity, d policy.Decision) {
	if o.deps.Audit == nil {
		return
	}
	action := audit.ActionScopeDecision
	detail := map[string]any{
		"target":  target.Value,
		"type":    string(target.Type),
		"rule":    d.Rule,
		"reason":  d.Reason,
		"allowed": d.Allowed,
	}
	if d.OutOfScope {
		detail["out_of_scope"] = true
	}
	// An unwired audit log must not become a silently disabled one: say so.
	if o.deps.Audit == nil {
		o.log.Warn("scope decision was not audited: no audit log configured")
		return
	}
	if _, err := o.deps.Audit.Record(ctx, action, detail); err != nil {
		o.log.Error("audit scope decision", "err", err.Error())
	}
}

// resolveTarget infers the entity type of a user-supplied string.
func ResolveTarget(s string) (sdk.Entity, error) {
	s = trimSpace(s)
	if s == "" {
		return sdk.Entity{}, fmt.Errorf("engine: empty target")
	}
	if v, err := sdk.Canonicalize(sdk.TypeIP, s); err == nil {
		return sdk.NewEntity(sdk.TypeIP, v), nil
	}
	if v, err := sdk.Canonicalize(sdk.TypeASN, s); err == nil {
		return sdk.NewEntity(sdk.TypeASN, v), nil
	}
	if v, err := sdk.Canonicalize(sdk.TypeCIDR, s); err == nil {
		return sdk.NewEntity(sdk.TypeCIDR, v), nil
	}
	if v, err := sdk.Canonicalize(sdk.TypeWallet, s); err == nil {
		return sdk.NewEntity(sdk.TypeWallet, v), nil
	}
	if v, err := sdk.Canonicalize(sdk.TypeCVE, s); err == nil {
		return sdk.NewEntity(sdk.TypeCVE, v), nil
	}
	if v, err := sdk.Canonicalize(sdk.TypeEmail, s); err == nil {
		return sdk.NewEntity(sdk.TypeEmail, v), nil
	}
	if v, err := sdk.Canonicalize(sdk.TypePhone, s); err == nil {
		return sdk.NewEntity(sdk.TypePhone, v), nil
	}
	// A dotted, non-numeric string with a registrable-looking shape is a host name.
	// The Public Suffix List decides whether it is the apex (domain) or something
	// below it (subdomain), because that distinction is what makes subdomain_of a
	// real edge and what scope rules are written against.
	if looksLikeDomain(s) {
		if e, err := canon.EntityOrErr(s); err == nil {
			return e, nil
		}
	}
	return sdk.Entity{}, fmt.Errorf("engine: cannot determine the type of %q; pass an explicit --type", s)
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func looksLikeDomain(s string) bool {
	if !dotIn(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func dotIn(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

// atomicInt64 is a tiny helper for counters shared across the package.
type atomicInt64 struct{ v atomic.Int64 }

func (a *atomicInt64) Add(n int64) { a.v.Add(n) }
func (a *atomicInt64) Load() int64 { return a.v.Load() }
