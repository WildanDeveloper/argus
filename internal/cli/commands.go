package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/internal/audit"
	"github.com/WildanDeveloper/argus/internal/config"
	"github.com/WildanDeveloper/argus/internal/engine"
	"github.com/WildanDeveloper/argus/internal/policy"
	"github.com/WildanDeveloper/argus/internal/secrets"
	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"

	"gopkg.in/yaml.v3"
)

func newLogger(cfg *config.Config, quiet bool) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Observability.Logs.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	if quiet {
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var w io.Writer = os.Stderr
	if strings.ToLower(cfg.Observability.Logs.Format) == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	// Structured JSON by default: logs are ingested, not read.
	return slog.New(slog.NewJSONHandler(w, opts))
}

// loadScope reads scope.yaml and builds the guard.
func loadScope(path string, enforce, allowPrivate bool) (*policy.Guard, bool, error) {
	if path == "" || !exists(path) {
		g, err := policy.NewGuard(nil)
		if err != nil {
			return nil, false, err
		}
		// No scope file means no scope. The guard denies by default; this is what
		// makes "I forgot to write scope.yaml" safe rather than catastrophic.
		return g, false, nil
	}
	raw, err := config.LoadYAML(path)
	if err != nil {
		return nil, false, err
	}
	var sc policy.Scope
	if err := yaml.Unmarshal(raw, &sc); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	g, err := policy.NewGuard(&sc)
	if err != nil {
		return nil, false, fmt.Errorf("compile %s: %w", path, err)
	}
	return g, true, nil
}

// loadPolicy reads policy.yaml, falling back to the built-in defaults.
func loadPolicy(path string) (*policy.Policy, error) {
	p := policy.NewPolicy()
	if path == "" || !exists(path) {
		return p, nil
	}
	raw, err := config.LoadYAML(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return p, nil
}

// policyEnginePrecheck reports a purpose problem before any work starts.
func policyEnginePrecheck(p *policy.Policy, purpose string) error {
	e, err := policy.NewEngine(p, nil)
	if err != nil {
		return err
	}
	if err := e.ValidatePurpose(purpose); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}

func runScope(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return engine.ExitUsage, fmt.Errorf("usage: argus scope <init|show|validate|check>")
	}
	switch args[0] {
	case "init":
		return scopeInit(args[1:], stdout, stderr)
	case "check":
		return scopeCheck(args[1:], stdout, stderr)
	case "show":
		return scopeShow(args[1:], stdout, stderr)
	case "validate":
		return scopeValidate(args[1:], stdout, stderr)
	}
	return engine.ExitUsage, fmt.Errorf("unknown subcommand %q for scope", args[0])
}

type scopeInitFlags struct {
	engagement string
	domain     string
	cidr       string
	authorized string
	contact    string
	validDays  int
	output     string
	force      bool
}

func scopeInit(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("scope init", stderr)
	var g globalFlags
	g.register(fs)
	var f scopeInitFlags
	fs.StringVar(&f.engagement, "engagement", "", "engagement identifier")
	fs.StringVar(&f.domain, "domain", "", "in-scope domain (repeatable via comma list)")
	fs.StringVar(&f.cidr, "cidr", "", "in-scope IP prefix (repeatable via comma list)")
	fs.StringVar(&f.authorized, "authorized-by", "", "who authorized this engagement")
	fs.StringVar(&f.contact, "contact", "", "security contact for the engagement")
	fs.IntVar(&f.validDays, "valid-days", 30, "authorization validity in days")
	fs.StringVar(&f.output, "o", "", "output path (default: the configured scope file)")
	fs.BoolVar(&f.force, "force", false, "overwrite an existing scope file")
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	if f.engagement == "" {
		return engine.ExitUsage, fmt.Errorf("--engagement is required")
	}
	if f.domain == "" && f.cidr == "" {
		// Either kind of asset is enough to state an engagement, and an IP-only
		// assessment is a real one. Requiring --domain would make those engagements
		// inexpressible, which is why the scope model carries allow.cidrs at all.
		return engine.ExitUsage, fmt.Errorf("--domain or --cidr is required")
	}
	if f.authorized == "" {
		// Written authorization is not optional. A scope file with an empty
		// authorized_by would allow semi-active work with no record of consent.
		return engine.ExitUsage, fmt.Errorf("--authorized-by is required; record who permitted this engagement")
	}

	cfg, err := g.load()
	if err != nil {
		return engine.ExitUsage, err
	}
	out := f.output
	if out == "" {
		out = cfg.Scope.File
	}
	if out == "" {
		out = "scope.yaml"
	}
	if exists(out) && !f.force {
		return engine.ExitUsage, fmt.Errorf("%s already exists; pass --force to replace it", out)
	}

	now := time.Now().UTC()
	var sc policy.Scope
	sc.Version = 1
	sc.Authorization = policy.Authorization{
		EngagementID: f.engagement,
		AuthorizedBy: f.authorized,
		Contact:      f.contact,
		ValidFrom:    now,
		ValidUntil:   now.Add(time.Duration(f.validDays) * 24 * time.Hour),
		// Active is omitted deliberately: adding it requires written permission for
		// probing, so it is never generated by a convenience command.
		AllowedModes: []string{"passive", "semi-active"},
	}
	// Each named domain gets both the apex and a wildcard for its subdomains.
	// The wildcard deliberately does not match the apex (see policy.addDomain), so
	// writing only "*.example.com" would exclude example.com itself; emitting both
	// is what makes `--domain example.com` mean what an operator expects.
	sc.Allow.Domains = apexAndSubdomains(splitNonEmpty(f.domain))
	sc.Allow.CIDRs = normalizeCIDRs(splitNonEmpty(f.cidr))
	sc.Deny.Domains = []string{"*.gov", "*.mil"}
	sc.Deny.CIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	sc.ThirdPartyData.RecordOutOfScope = true

	b, err := yaml.Marshal(&sc)
	if err != nil {
		return engine.ExitError, err
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		return engine.ExitStorage, err
	}
	fmt.Fprintf(stdout, "wrote %s\n", out)
	fmt.Fprintf(stdout, "  engagement  %s\n", sc.Authorization.EngagementID)
	fmt.Fprintf(stdout, "  authorized  %s\n", sc.Authorization.AuthorizedBy)
	fmt.Fprintf(stdout, "  valid until %s\n", sc.Authorization.ValidUntil.Format(time.RFC3339))
	if len(sc.Allow.Domains) > 0 {
		fmt.Fprintf(stdout, "  domains     %s\n", strings.Join(sc.Allow.Domains, ", "))
	}
	if len(sc.Allow.CIDRs) > 0 {
		fmt.Fprintf(stdout, "  prefixes    %s\n", strings.Join(sc.Allow.CIDRs, ", "))
	}
	fmt.Fprintf(stdout, "\nvalidate it with: argus scope validate\n")
	return engine.ExitOK, nil
}

// normalizeCIDRs validates and masks each requested prefix.
//
// A bare address is accepted and widened to a single-address prefix, because writing
// 8.8.8.8 into a prefix field is the obvious thing for an operator to do and it
// should not silently scope nothing. Host bits are cleared so a scope file cannot
// read as wider than it is: 8.8.8.8/24 is stored as 8.8.8.0/24, which is what the
// guard will actually enforce.
func normalizeCIDRs(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true

		if !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				// Not a usable prefix and not an address. Emitting it would produce a
				// scope file that fails validation later, away from the command that
				// caused it.
				continue
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()).String())
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		out = append(out, p.Masked().String())
	}
	return out
}

// apexAndSubdomains expands each domain into its apex plus a subdomain wildcard,
// skipping entries that are already wildcards.
func apexAndSubdomains(domains []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(d string) {
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		out = append(out, d)
	}
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") || strings.HasPrefix(d, ".") {
			add(d)
			continue
		}
		add(d)
		add("*." + d)
	}
	return out
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func scopeCheck(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("scope check", stderr)
	var g globalFlags
	g.register(fs)
	modeStr := fs.String("mode", "", "mode ceiling to check against: passive, standard, active")
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	if fs.NArg() == 0 {
		return engine.ExitUsage, fmt.Errorf("usage: argus scope check <target>")
	}

	cfg, err := g.load()
	if err != nil {
		return engine.ExitUsage, err
	}
	guard, found, err := loadScope(cfg.Scope.File, cfg.Scope.Enforce, false)
	if err != nil {
		return engine.ExitStorage, err
	}
	if !found {
		fmt.Fprintf(stderr, "no scope file at %s; the guard denies by default\n", cfg.Scope.File)
	}

	ceiling := cfg.General.Mode
	if *modeStr != "" {
		ceiling = *modeStr
	}
	mode, err := sdk.ParseMode(ceiling)
	if err != nil {
		return engine.ExitUsage, err
	}

	exit := engine.ExitOK
	for _, raw := range fs.Args() {
		e, err := engine.ResolveTarget(raw)
		if err != nil {
			fmt.Fprintf(stdout, "%-40s UNKNOWN  %v\n", raw, err)
			exit = engine.ExitScopeDenied
			continue
		}
		d := guard.Check(e)
		status := "IN SCOPE"
		if !d.Allowed {
			status = "OUT OF SCOPE"
			exit = engine.ExitScopeDenied
		}
		fmt.Fprintf(stdout, "%-40s %-12s [%s] %s\n", e.Value, status, d.Rule, d.Reason)
		if ok, reason := guard.Scope().Authorization.Allows(mode, time.Now()); !ok {
			fmt.Fprintf(stdout, "%-40s MODE %s denied: %s\n", raw, mode, reason)
			if exit == engine.ExitOK {
				exit = engine.ExitScopeDenied
			}
		}
	}
	return exit, nil
}

func scopeShow(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("scope show", stderr)
	var g globalFlags
	g.register(fs)
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	cfg, err := g.load()
	if err != nil {
		return engine.ExitUsage, err
	}
	raw, err := config.LoadYAML(cfg.Scope.File)
	if err != nil {
		return engine.ExitStorage, err
	}
	fmt.Fprintln(stdout, string(raw))
	return engine.ExitOK, nil
}

func scopeValidate(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("scope validate", stderr)
	var g globalFlags
	g.register(fs)
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	cfg, err := g.load()
	if err != nil {
		return engine.ExitUsage, err
	}
	if !exists(cfg.Scope.File) {
		fmt.Fprintf(stderr, "no scope file at %s\n", cfg.Scope.File)
		return engine.ExitScopeDenied, fmt.Errorf("scope file %s does not exist", cfg.Scope.File)
	}
	guard, _, err := loadScope(cfg.Scope.File, true, false)
	if err != nil {
		fmt.Fprintf(stderr, "invalid: %v\n", err)
		return engine.ExitScopeDenied, err
	}
	sc := guard.Scope()
	if sc.Authorization.EngagementID == "" {
		fmt.Fprintf(stderr, "warning: no authorization.engagement_id; active mode will be refused\n")
	}
	if !sc.Authorization.ActivePermitted() {
		fmt.Fprintf(stdout, "valid: %s\n", cfg.Scope.File)
		fmt.Fprintf(stdout, "  engagement   %s\n", sc.Authorization.EngagementID)
		fmt.Fprintf(stdout, "  modes        %s (active not permitted)\n", strings.Join(sc.Authorization.AllowedModes, ", "))
		fmt.Fprintf(stdout, "  allow        %d domain rule(s), %d CIDR rule(s), %d ASN rule(s)\n",
			len(sc.Allow.Domains), len(sc.Allow.CIDRs), len(sc.Allow.ASNs))
		return engine.ExitOK, nil
	}
	fmt.Fprintf(stdout, "valid: %s\n", cfg.Scope.File)
	fmt.Fprintf(stdout, "  engagement   %s\n", sc.Authorization.EngagementID)
	fmt.Fprintf(stdout, "  modes        %s (ACTIVE PERMITTED - verify this matches your written permission)\n",
		strings.Join(sc.Authorization.AllowedModes, ", "))
	return engine.ExitOK, nil
}

func runDoctor(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("doctor", stderr)
	var g globalFlags
	g.register(fs)
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	cfg, err := g.load()
	if err != nil {
		fmt.Fprintf(stderr, "config: FAIL %v\n", err)
		return engine.ExitUsage, err
	}
	fmt.Fprintf(stdout, "config      ok    %s (profile %s)\n", cfg.SourcePathOr("built-in defaults"), cfg.AppliedProfile)

	// The audit log must be writable. A tool that cannot record what it did is not
	// usable for an authorized engagement.
	if auditLog, err := audit.OpenJSONL(cfg.Storage.Primary.DSN + ".audit.jsonl"); err != nil {
		fmt.Fprintf(stdout, "audit log   FAIL  %v\n", err)
	} else if head, ok := auditLog.Head(); ok {
		fmt.Fprintf(stdout, "audit log   ok    head %s\n", shortHash(head.Hash))
	} else {
		fmt.Fprintf(stdout, "audit log   ok    empty chain\n")
	}

	if st, err := store.Open(context.Background(), store.Driver(cfg.Storage.Primary.Driver), cfg.Storage.Primary.DSN); err != nil {
		fmt.Fprintf(stdout, "store       FAIL  %v\n", err)
	} else {
		stats, _ := st.Stats(context.Background())
		fmt.Fprintf(stdout, "store       ok    %s (%d entities, %d observations)\n",
			cfg.Storage.Primary.DSN, stats.Entities, stats.Observations)
		st.Close()
	}

	scopeFile := cfg.Scope.File
	if exists(scopeFile) {
		guard, _, err := loadScope(scopeFile, true, false)
		if err != nil {
			fmt.Fprintf(stdout, "scope       FAIL  %v\n", err)
		} else {
			sc := guard.Scope()
			modes := strings.Join(sc.Authorization.AllowedModes, ",")
			if modes == "" {
				modes = "passive only (allowed_modes empty)"
			}
			fmt.Fprintf(stdout, "scope       ok    %s (engagement %s, modes %s)\n",
				scopeFile, sc.Authorization.EngagementID, modes)
		}
	} else {
		fmt.Fprintf(stdout, "scope       warn  %s not found; the guard will deny every target\n", scopeFile)
	}

	mods := sdk.RegisteredModules()
	var problems int
	for _, m := range mods {
		problems += len(sdk.ValidateManifest(m.Manifest()))
	}
	fmt.Fprintf(stdout, "modules     %d registered, %d manifest problem(s)\n", len(mods), problems)

	reader := secrets.NewEnvReader()
	names := reader.ListNames()
	fmt.Fprintf(stdout, "secrets     %d environment key(s) available\n", len(names))

	if !cfg.Network.Egress.BlockPrivate {
		fmt.Fprintf(stdout, "egress      warn  private ranges are reachable; confirm this is an authorized internal assessment\n")
	} else {
		fmt.Fprintf(stdout, "egress      ok    private and metadata ranges blocked at dial time\n")
	}

	fmt.Fprintf(stdout, "clock       %s\n", time.Now().UTC().Format(time.RFC3339))
	return engine.ExitOK, nil
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:8] + ".." + h[len(h)-4:]
}
