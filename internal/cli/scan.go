package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/WildanDeveloper/argus/internal/audit"
	"github.com/WildanDeveloper/argus/internal/cache"
	"github.com/WildanDeveloper/argus/internal/config"
	"github.com/WildanDeveloper/argus/internal/egress"
	"github.com/WildanDeveloper/argus/internal/engine"
	"github.com/WildanDeveloper/argus/internal/pipeline"
	"github.com/WildanDeveloper/argus/internal/policy"
	"github.com/WildanDeveloper/argus/internal/secrets"
	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// scanFlags are the flags `argus scan` accepts beyond the global set.
type scanFlags struct {
	modules       string
	exclude       string
	category      string
	mode          string
	allowActive   bool
	allowSubmit   bool
	depth         int
	workers       int
	maxRequests   int64
	maxCost       float64
	maxRuntime    time.Duration
	caseID        string
	purpose       string
	scopePath     string
	policyPath    string
	timeout       time.Duration
	noCache       bool
	refresh       bool
	minConfidence float64
	format        string
	output        string
	dryRun        bool
	explain       bool
	offline       bool
	allowPrivate  bool
}

func runScan(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("scan", stderr)
	var g globalFlags
	g.register(fs)

	var f scanFlags
	fs.StringVar(&f.modules, "m", "", "comma-separated module allow-list")
	fs.StringVar(&f.modules, "modules", "", "comma-separated module allow-list")
	fs.StringVar(&f.exclude, "x", "", "modules to exclude")
	fs.StringVar(&f.exclude, "exclude", "", "modules to exclude")
	fs.StringVar(&f.category, "category", "", "select by category")
	fs.StringVar(&f.mode, "mode", "", "passive | standard | active")
	fs.BoolVar(&f.allowActive, "allow-active", false, "permit active-mode modules (also requires scope authorization)")
	fs.BoolVar(&f.allowSubmit, "allow-submit", false, "permit modules that disclose the URL to a third party")
	fs.IntVar(&f.depth, "d", -1, "max auto-chaining depth")
	fs.IntVar(&f.depth, "depth", -1, "max auto-chaining depth")
	fs.IntVar(&f.workers, "w", 0, "worker count")
	fs.IntVar(&f.workers, "workers", 0, "worker count")
	fs.Int64Var(&f.maxRequests, "max-requests", 0, "request budget")
	fs.Float64Var(&f.maxCost, "max-cost", 0, "cost budget in USD")
	fs.DurationVar(&f.maxRuntime, "max-runtime", 0, "runtime budget")
	fs.StringVar(&f.caseID, "case", "", "case binding (required for sensitive modules)")
	fs.StringVar(&f.purpose, "purpose", "", "purpose binding (required for sensitive modules)")
	fs.StringVar(&f.scopePath, "scope", "", "scope file override")
	fs.StringVar(&f.policyPath, "policy", "", "policy file override")
	fs.DurationVar(&f.timeout, "timeout", 0, "per-task timeout")
	fs.BoolVar(&f.noCache, "no-cache", false, "bypass the cache")
	fs.BoolVar(&f.refresh, "refresh", false, "ignore cached entries and refresh them")
	fs.Float64Var(&f.minConfidence, "min-confidence", 0, "filter output to this confidence")
	fs.StringVar(&f.format, "format", "table", "table | json | jsonl")
	fs.StringVar(&f.output, "o", "", "output file or directory")
	fs.StringVar(&f.output, "output", "", "output file or directory")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the plan without executing")
	fs.BoolVar(&f.explain, "explain", false, "explain decisions")
	fs.BoolVar(&f.offline, "offline", false, "air-gapped mode: no network modules run")
	fs.BoolVar(&f.allowPrivate, "allow-private", false, "permit private ranges (authorized internal assessment only)")

	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	targets := fs.Args()
	if len(targets) == 0 {
		return engine.ExitUsage, fmt.Errorf("usage: argus scan <target> [target...] [flags]")
	}

	cfg, err := g.load()
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return engine.ExitUsage, err
	}

	// Environment and flags override the file, per §8.
	if f.offline {
		cfg.General.Mode = "passive"
	}
	mode := cfg.General.Mode
	if f.mode != "" {
		mode = f.mode
	}
	scanMode, err := sdk.ParseMode(mode)
	if err != nil {
		return engine.ExitUsage, fmt.Errorf("--mode: %w", err)
	}

	opts := engine.DefaultOptions()
	opts.CaseID = f.caseID
	opts.Purpose = f.purpose
	opts.Actor = currentActor()
	opts.Mode = scanMode
	opts.AllowActive = f.allowActive
	if f.depth >= 0 {
		opts.MaxDepth = f.depth
	} else {
		opts.MaxDepth = cfg.Engine.MaxDepth
	}
	if f.workers > 0 {
		opts.Workers = f.workers
	} else {
		opts.Workers = cfg.Engine.Workers
	}
	if f.timeout > 0 {
		opts.TaskTimeout = f.timeout
	} else {
		opts.TaskTimeout = cfg.Engine.TaskTimeout.Duration()
	}
	opts.ScanTimeout = cfg.Engine.ScanTimeout.Duration()
	opts.DrainTimeout = cfg.Engine.DrainTimeout.Duration()
	opts.MaxBreadth = cfg.Engine.MaxBreadth
	if f.maxRequests > 0 {
		opts.Budgets.MaxRequests = f.maxRequests
	} else {
		opts.Budgets.MaxRequests = cfg.Engine.Budgets.MaxRequests
	}
	if f.maxCost > 0 {
		opts.Budgets.MaxCostUSD = f.maxCost
	} else {
		opts.Budgets.MaxCostUSD = cfg.Engine.Budgets.MaxCostUSD
	}
	if f.maxRuntime > 0 {
		opts.Budgets.MaxRuntime = f.maxRuntime
	} else {
		opts.Budgets.MaxRuntime = cfg.Engine.Budgets.MaxRuntime.Duration()
	}
	if f.allowPrivate {
		// An explicit flag, because a bare config toggle would let a config typo
		// quietly open the SSRF guard.
		cfg.Network.Egress.BlockPrivate = false
	}

	// Resolve the target before touching the store or the network, so a
	// nonsensical target fails in a millisecond instead of after setup.
	entities, err := resolveTargets(targets)
	if err != nil {
		return engine.ExitUsage, err
	}

	scopeFile := f.scopePath
	if scopeFile == "" {
		scopeFile = cfg.Scope.File
	}
	guard, scopeFound, err := loadScope(scopeFile, cfg.Scope.Enforce, f.allowPrivate)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return engine.ExitStorage, err
	}
	if !scopeFound && cfg.Scope.Enforce && scanMode > sdk.ModePassive {
		return engine.ExitScopeDenied, fmt.Errorf(
			"scope.yaml not found at %s and scope.enforce is true; %s mode needs a declared scope",
			scopeFile, scanMode)
	}

	policyFile := f.policyPath
	if policyFile == "" {
		policyFile = cfg.Policy.File
	}
	pol, err := loadPolicy(policyFile)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return engine.ExitStorage, err
	}
	pol.SetCase(f.caseID, f.purpose)
	if f.purpose != "" {
		if err := policyEnginePrecheck(pol, f.purpose); err != nil {
			return engine.ExitPolicyDenied, err
		}
	}

	mods, err := selectModules(f.modules, f.exclude, f.category, cfg.Modules.Disabled)
	if err != nil {
		return engine.ExitUsage, err
	}
	if len(mods) == 0 {
		return engine.ExitUsage, fmt.Errorf("no modules matched; run `argus modules list`")
	}

	// The first target is the scan root; the rest are additional roots in the same
	// engagement, which keeps one scan's budget and case coherent.
	root := entities[0]

	// A local file's identity is its content digest, so the path it was named by has to
	// travel beside it for a module that must open the file.
	if root.Type == sdk.TypeFile || root.Type == sdk.TypeImage {
		if _, ok := engine.ExistingFile(targets[0]); ok {
			opts.FilePath = targets[0]
		}
	}

	deps, closeFn, err := buildDeps(cfg, guard, pol, f, g.quiet)
	if err != nil {
		return engine.ExitStorage, err
	}
	defer closeFn()

	orch, err := engine.New(opts, deps)
	if err != nil {
		return engine.ExitStorage, err
	}

	// --dry-run is answered before any consumer is attached: Plan does not emit
	// events, and starting a consumer here would leave two readers on a channel
	// that only the real run closes.
	if f.dryRun {
		plan, err := orch.Plan(root, mods)
		if err != nil {
			if errors.Is(err, sdk.ErrOutOfScope) {
				return engine.ExitScopeDenied, err
			}
			return engine.ExitError, err
		}
		printPlan(stdout, plan, f.explain, root)
		return engine.ExitOK, nil
	}

	// Progress is streamed as it happens so a long scan is not a silent wait.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range orch.Events() {
			if g.quiet {
				continue
			}
			switch ev.Kind {
			case "scan.start", "module.start", "module.done", "scan.done":
				fmt.Fprintf(stderr, "[%s] %s %s\n", ev.At.Format("15:04:05"), ev.Kind, ev.Text)
			case "warning":
				fmt.Fprintf(stderr, "[%s] warning (%s): %s\n", ev.At.Format("15:04:05"), ev.Module, ev.Text)
			}
		}
	}()

	// A cancelled scan drains, checkpoints, and exits 130 rather than losing work.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stats, runErr := orch.Run(ctx, root, mods)
	<-done

	reportScan(stdout, stats, runErr)

	if runErr != nil {
		switch {
		case errors.Is(runErr, sdk.ErrOutOfScope):
			return engine.ExitScopeDenied, runErr
		case errors.Is(runErr, engine.ErrBudgetExhausted):
			return engine.ExitPartial, runErr
		}
	}
	if stats.Partial {
		return engine.ExitPartial, nil
	}
	if stats.Errors > 0 {
		return engine.ExitPartial, nil
	}
	return engine.ExitOK, nil
}

func currentActor() string {
	for _, k := range []string{"ARGUS_ACTOR", "USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "unknown"
}

func resolveTargets(targets []string) ([]sdk.Entity, error) {
	out := make([]sdk.Entity, 0, len(targets))
	for _, t := range targets {
		e, err := engine.ResolveTarget(t)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", t, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// selectModules resolves the allow-list, exclusion list, and category filter
// into concrete module instances.
func selectModules(allow, exclude, category string, globallyDisabled []string) ([]sdk.Module, error) {
	allowSet := splitList(allow)
	excludeSet := splitList(exclude)
	for _, d := range globallyDisabled {
		excludeSet[d] = true
	}
	if len(allowSet) == 0 {
		return nil, fmt.Errorf("no module allow-list: pass -m, or run this command from a full build with modules imported")
	}

	var out []sdk.Module
	for _, name := range sortedKeys(allowSet) {
		if excludeSet[name] {
			continue
		}
		m, ok := sdk.New(name)
		if !ok {
			return nil, fmt.Errorf("no such module %q; run `argus modules list`", name)
		}
		if category != "" && m.Manifest().Category != category {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func splitList(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p != "" {
			out[p] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func printPlan(w io.Writer, plan engine.DryRunPlan, explain bool, root sdk.Entity) {
	fmt.Fprintf(w, "Plan for %s (%s)\n", root.Value, root.Type)
	fmt.Fprintf(w, "  ceiling: %s\n", plan.Mode)
	fmt.Fprintf(w, "  depth:   %d\n\n", plan.DependedOn())
	fmt.Fprintf(w, "  modules permitted (%d):\n", len(plan.Modules))
	for _, m := range plan.Modules {
		fmt.Fprintf(w, "    %-20s %-12s sens=%-6s consumes=%s produces=%s\n",
			m.Name, m.Mode, m.Sensitivity, joinTypes(m.Consumes), joinTypes(m.Produces))
		if explain {
			if len(m.EgressHosts) > 0 {
				fmt.Fprintf(w, "      egress:  %s\n", strings.Join(m.EgressHosts, ", "))
			}
			if len(m.Secrets) > 0 {
				fmt.Fprintf(w, "      secrets: %s\n", strings.Join(m.Secrets, ", "))
			}
			fmt.Fprintf(w, "      reason:  %s\n", m.Reason)
		}
	}
	if len(plan.Denied) > 0 {
		fmt.Fprintf(w, "\n  modules denied (%d):\n", len(plan.Denied))
		for _, d := range plan.Denied {
			fmt.Fprintf(w, "    [%s] %s\n", d.Rule, d.Reason)
		}
	}
}

func reportScan(w io.Writer, stats engine.Stats, err error) {
	fmt.Fprintf(w, "\nscan finished\n")
	fmt.Fprintf(w, "  modules run   %d\n", stats.ModulesRun)
	fmt.Fprintf(w, "  tasks         %d\n", stats.Tasks)
	fmt.Fprintf(w, "  findings      %d\n", stats.Findings)
	fmt.Fprintf(w, "  entities      %d\n", stats.Entities)
	fmt.Fprintf(w, "  requests      %d\n", stats.Requests)
	fmt.Fprintf(w, "  out of scope  %d\n", stats.OutOfScope)
	fmt.Fprintf(w, "  denials       %d\n", stats.Denials)
	fmt.Fprintf(w, "  errors        %d\n", stats.Errors)
	if stats.CostUSD > 0 {
		fmt.Fprintf(w, "  est. cost     $%.4f\n", stats.CostUSD)
	}
	if stats.StoppedWhy != "" {
		fmt.Fprintf(w, "  stopped       %s\n", stats.StoppedWhy)
	}
	if stats.Partial {
		fmt.Fprintf(w, "\npartial results: the scan stopped early and the data is incomplete\n")
	}
	if err != nil {
		fmt.Fprintf(w, "  reason        %v\n", err)
	}
}

// buildDeps wires the store, audit log, egress broker, and per-module deps.
func buildDeps(cfg *config.Config, guard *policy.Guard, pol *policy.Policy, f scanFlags, quiet bool) (engine.Dependencies, func(), error) {
	noop := func() {}

	st, err := store.Open(context.Background(), store.Driver(cfg.Storage.Primary.Driver), cfg.Storage.Primary.DSN)
	if err != nil {
		return engine.Dependencies{}, noop, err
	}
	closeFn := func() { st.Close() }

	auditLog, err := audit.OpenJSONL(cfg.Storage.Primary.DSN + ".audit.jsonl")
	if err != nil {
		return engine.Dependencies{}, closeFn, err
	}

	policyEngine, err := policy.NewEngine(pol, guard)
	if err != nil {
		return engine.Dependencies{}, closeFn, err
	}

	var memoryCache *cache.Memory
	if cfg.Cache.Enabled && !f.noCache && !f.refresh {
		memoryCache = cache.NewMemory(cache.DefaultMaxItems)
	}

	globalRate, err := egress.ParseRate(cfg.RateLimit.Default)
	if err != nil {
		return engine.Dependencies{}, closeFn, fmt.Errorf("ratelimit.default: %w", err)
	}
	perHost := map[string]egress.Rate{}
	for host, spec := range cfg.RateLimit.PerHost {
		r, err := egress.ParseRate(spec)
		if err != nil {
			return engine.Dependencies{}, closeFn, fmt.Errorf("ratelimit.per_host[%s]: %w", host, err)
		}
		perHost[host] = r
	}
	perModule := map[string]egress.Rate{}
	for name, spec := range cfg.RateLimit.PerModule {
		r, err := egress.ParseRate(spec)
		if err != nil {
			return engine.Dependencies{}, closeFn, fmt.Errorf("ratelimit.per_module[%s]: %w", name, err)
		}
		perModule[name] = r
	}

	breaker := egress.NewBreaker(egress.BreakerSettings{
		FailureThreshold: cfg.Network.CircuitBreaker.FailureThreshold,
		Window:           cfg.Network.CircuitBreaker.Window.Duration(),
		Cooldown:         cfg.Network.CircuitBreaker.Cooldown.Duration(),
	})
	retry := egress.NewRetryer(egress.RetryConfig{
		MaxAttempts: cfg.Network.Retry.MaxAttempts,
		Backoff:     cfg.Network.Retry.Backoff,
		Base:        cfg.Network.Retry.Base.Duration(),
		Max:         cfg.Network.Retry.Max.Duration(),
	})

	secretReader := secrets.NewEnvReader()

	// scopeCheck adapts the guard to the broker's narrow interface, keeping the
	// dependency one-way: egress must not import policy.
	// The grant table is shared across modules: each entry is keyed by module name,
	// so one collector's bootstrap never widens another's reach.
	grants := egress.NewBootstrapGrant()
	scopeCheck := &guardAdapter{guard: guard, policy: policyEngine, grants: grants}

	evidenceStore, err := engine.NewEvidenceStore(st, cfg.Storage.Blobs.Path, nil)
	if err != nil {
		return engine.Dependencies{}, closeFn, err
	}

	deps := engine.Dependencies{
		Store:          st,
		Audit:          auditLog,
		Engine:         policyEngine,
		Guard:          guard,
		Logger:         newLogger(cfg, quiet),
		Now:            time.Now,
		EvidenceStore:  evidenceStore,
		PipelineConfig: pipeline.DefaultConfig(),
	}

	// DepsFor builds brokered dependencies per module, so each module sees only the
	// hosts and secrets it declared.
	deps.DepsFor = func(man sdk.Manifest) (sdk.Deps, error) {
		client, err := egress.NewClient(egress.ClientConfig{
			Module:            man.Name,
			UserAgent:         cfg.Network.UserAgent,
			MaxBodyBytes:      cfg.Network.HTTP.MaxBodyBytes,
			MaxRedirects:      cfg.Network.HTTP.MaxRedirects,
			AllowPrivate:      !cfg.Network.Egress.BlockPrivate,
			AllowPrivateCIDRs: cfg.Network.Egress.AllowPrivateCIDRs,
			Timeout:           f.timeout,
			DisableCache:      f.noCache || f.refresh,
			Logger:            deps.Logger,
			// The broker derives additional reachable hosts from whatever these
			// bootstrap documents return. The module never asserts a host itself.
			BootstrapHosts: man.BootstrapHosts,
			Grant:          grants,
		}, nil,
			egress.NewRateLimiter(globalRate, cfg.RateLimit.Burst, perHost, withModuleHint(perModule, man)),
			breaker, retry, brokerCache(memoryCache), nil, scopeCheck)
		if err != nil {
			return sdk.Deps{}, err
		}
		resolver := egress.NewDoHResolver(client, cfg.Network.DNS.Consensus)

		// The TCP broker is built per module too, so its rate limit and audit entries
		// name the module that opened the connection.
		tcp, err := egress.NewTCPDialer(egress.TCPConfig{
			Module: man.Name,
			// The TCP guard mirrors the HTTP client's, so a port 43 connection is
			// held to exactly the same address rules as an HTTP one.
			Guard:   tcpGuard(cfg),
			Limits:  egress.NewRateLimiter(globalRate, cfg.RateLimit.Burst, perHost, withModuleHint(perModule, man)),
			Breaker: breaker,
			Scope:   scopeCheck,
			// The per-exchange TCP timeout, not the scan timeout. A task that follows a
			// WHOIS referral opens more than one connection, and giving each the whole
			// task budget means the task can never complete.
			Timeout: cfg.Network.TCP.Timeout.Duration(),
			Logger:  deps.Logger,
		})
		if err != nil {
			return sdk.Deps{}, err
		}

		d := sdk.Deps{
			HTTP:    client,
			DNS:     resolver,
			Dial:    tcp,
			Secrets: scopedSecrets{reader: secretReader, allowed: man.SecretNames()},
			Blobs:   newBlobWriter(evidenceStore),
			InScope: inScopeHelper{guard: guard}.InScope,
			Log:     deps.Logger.With("module", man.Name),
			Now:     time.Now,
			Config:  moduleConfig(cfg, man.Name),
		}
		if memoryCache != nil {
			d.Cache = &cacheAdapter{memoryCache}
		}
		return d, nil
	}

	return deps, closeFn, nil
}

// withModuleHint merges a module's own rate hints under the configured limits.
// A hint may only make a module slower, never faster than the operator
// configured: the operator's setting is the authority, the manifest is a claim.
func withModuleHint(configured map[string]egress.Rate, man sdk.Manifest) map[string]egress.Rate {
	out := make(map[string]egress.Rate, len(configured)+len(man.RateHints))
	for k, v := range configured {
		out[k] = v
	}
	for host, hint := range man.RateHints {
		r := egress.Rate{Requests: hint.Requests, Per: hint.Per}
		existing, ok := out[host]
		if !ok {
			out[host] = r
			continue
		}
		if r.Requests < existing.Requests {
			out[host] = r
		}
	}
	return out
}

func brokerCache(m *cache.Memory) egress.Cache {
	if m == nil {
		return nil
	}
	return &brokerCacheAdapter{m}
}

func moduleConfig(cfg *config.Config, name string) map[string]any {
	if s, ok := cfg.Modules.Settings[name]; ok {
		return s
	}
	return map[string]any{}
}

// guardAdapter bridges policy.Guard to the broker's ScopeChecker.
// tcpGuard builds the address guard for the TCP broker from the same configuration the
// HTTP broker uses, so a port 43 connection is held to identical address rules.
func tcpGuard(cfg *config.Config) *egress.SSRFGuard {
	g := &egress.SSRFGuard{AllowPrivate: !cfg.Network.Egress.BlockPrivate}
	for _, raw := range cfg.Network.Egress.AllowPrivateCIDRs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			g.AllowPrivateCIDRs = append(g.AllowPrivateCIDRs, p)
		}
	}
	return g
}

// CheckDial applies the same scope rules to a TCP connection as to a URL. A WHOIS
// server is a third-party host reached outside the subject's infrastructure, so it is
// held to the module's declared reach just as an HTTP host is.
func (a *guardAdapter) CheckDial(_ context.Context, host string, port int, module string) error {
	// Resolved from the compile-time registry, exactly as the URL path does, so a host
	// permitted for an HTTP request is permitted for the same reason on a TCP one.
	man, ok := sdk.New(module)
	if !ok {
		return fmt.Errorf("unknown module %q", module)
	}
	if !man.Manifest().AllowsHost(host) {
		return fmt.Errorf("module %s does not declare %s in its EgressHosts allow-list", module, host)
	}
	return nil
}

type guardAdapter struct {
	guard  *policy.Guard
	policy *policy.Engine
	// grants holds hosts a module's own bootstrap document authorized.
	grants *egress.BootstrapGrant
}

// CheckEgress decides whether a module may reach a URL.
//
// Two things are checked here, and the distinction between them matters:
//
//  1. The manifest's declared EgressHosts allow-list. This is least privilege: a
//     module can only reach hosts it declared, so a collector cannot quietly grow
//     its own network access.
//  2. The SSRF guard, which lives in the egress package at dial time and therefore
//     covers this path already.
//
// Target scope is deliberately NOT applied to the request URL. Third-party
// infrastructure that a collector legitimately queries -- a certificate
// transparency log, an RDAP bootstrap, a public resolver -- is not the engagement's
// asset, and requiring it in scope would make passive collection impossible. Scope
// governs what may be *investigated*: the orchestrator checks the scan root, and a
// module checks any entity it is about to probe using Deps.InScope.
func (a *guardAdapter) CheckEgress(_ context.Context, u *url.URL, module string) error {
	man, ok := sdk.New(module)
	if !ok {
		return fmt.Errorf("unknown module %q", module)
	}
	mm := man.Manifest()
	host := u.Hostname()
	if !mm.AllowsHost(host) && !a.grants.Allows(module, host) {
		// A host reached without a declaration and without a bootstrap grant is a
		// collector trying to exceed its declared reach. Refusing here is what makes
		// the manifest mean something.
		return fmt.Errorf("module %s may not reach %s: it is neither in EgressHosts nor granted by a bootstrap document", module, host)
	}
	if a.guard != nil && a.policy != nil {
		// An active-mode module must additionally hold an authorization that
		// permits active work before it may issue any request at all, so a
		// misconfigured collector cannot probe first and ask later.
		if mm.Mode == sdk.ModeActive {
			if !a.guard.Scope().Authorization.ActivePermitted() {
				return fmt.Errorf("module %s is active-mode; add `active` to authorization.allowed_modes with written permission", module)
			}
		}
	}
	return nil
}

// inScopeHelper exposes the scope guard to modules as Deps.InScope, so a module
// can check an entity before probing it without importing internal/policy.
type inScopeHelper struct{ guard *policy.Guard }

// InScope reports whether an entity may be investigated, with the reason.
func (h inScopeHelper) InScope(e sdk.Entity) (bool, string) {
	if h.guard == nil {
		return false, "no scope guard configured"
	}
	d := h.guard.Check(e)
	return d.Allowed, d.Reason
}

// scopedSecrets returns only the secrets a manifest declared.
type scopedSecrets struct {
	reader  *secrets.EnvReader
	allowed []string
}

func (s scopedSecrets) Secret(ctx context.Context, name string) (string, error) {
	for _, a := range s.allowed {
		if a == name {
			return s.reader.Secret(ctx, name)
		}
	}
	// Least privilege is enforced here, not by convention: a module cannot read a
	// secret its manifest did not declare.
	return "", fmt.Errorf("secret %q is not declared in this module's manifest", name)
}

// cacheAdapter exposes the in-memory cache as an sdk.Cache.
type cacheAdapter struct{ m *cache.Memory }

func (c *cacheAdapter) Get(key string) (any, bool)               { return c.m.Get(key) }
func (c *cacheAdapter) Put(key string, v any, ttl time.Duration) { c.m.Put(key, v, ttl) }
func (c *cacheAdapter) Delete(key string)                        { c.m.Delete(key) }

// brokerCacheAdapter exposes the memory cache as an egress.Cache, holding
// responses rather than arbitrary values.
type brokerCacheAdapter struct{ m *cache.Memory }

func (b *brokerCacheAdapter) Get(key string) (*egress.CachedResponse, bool) {
	v, ok := b.m.Get(key)
	if !ok {
		return nil, false
	}
	cr, ok := v.(*egress.CachedResponse)
	return cr, ok
}

func (b *brokerCacheAdapter) Put(key string, v *egress.CachedResponse, ttl time.Duration) {
	b.m.Put(key, v, ttl)
}

func (b *brokerCacheAdapter) Delete(key string) { b.m.Delete(key) }

// blobWriter adapts the engine's evidence store to the SDK's BlobWriter.
type blobWriter struct{ es *engine.EvidenceStore }

func (b blobWriter) Put(ctx context.Context, meta sdk.EvidenceMeta, raw []byte) (sdk.EvidenceRef, error) {
	// The SDK signature carries no scan or case context, so this records
	// provenance only; the orchestrator's emitter supplies scan and case on the
	// authoritative evidence path.
	return b.es.Store(ctx, "", "", meta, raw)
}

func newBlobWriter(es *engine.EvidenceStore) sdk.BlobWriter { return blobWriter{es} }

// sha256Hex hashes bytes for content verification.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
