// Package cli implements the Argus command-line interface.
//
// Exit codes follow Appendix C, because they are part of the automation contract:
// a script must be able to distinguish "target out of scope" from "storage broken"
// without parsing text.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/WildanDeveloper/argus/internal/config"
	"github.com/WildanDeveloper/argus/internal/engine"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped at build time with -ldflags.
var Version = "dev"

// Run dispatches a command and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		usage(stderr)
		return engine.ExitUsage, nil
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "-h", "--help", "help":
		usage(stdout)
		return engine.ExitOK, nil
	case "-V", "--version", "version":
		fmt.Fprintf(stdout, "argus %s\n", Version)
		return engine.ExitOK, nil
	case "scan":
		return runScan(rest, stdout, stderr)
	case "modules":
		return runModules(rest, stdout, stderr)
	case "scope":
		return runScope(rest, stdout, stderr)
	case "show":
		return runShow(rest, stdout, stderr)
	case "config":
		return runConfig(rest, stdout, stderr)
	case "audit":
		return runAudit(rest, stdout, stderr)
	case "doctor":
		return runDoctor(rest, stdout, stderr)
	}

	fmt.Fprintf(stderr, "argus: unknown command %q\n", cmd)
	fmt.Fprintf(stderr, "run `argus help` for the command list\n")
	return engine.ExitUsage, fmt.Errorf("unknown command %q", cmd)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `argus - a modular, concurrent, evidence-first OSINT framework

Usage:
  argus <command> [flags]

Investigation
  scan          Run modules against one or more targets
  workflow      Run, validate, and dry-run workflow definitions
  query         Run ArgusQL queries against stored data
  show          Display entities, relations, observations, evidence
  graph         Export, path-search, and analyze the entity graph
  timeline      Per-entity or per-case timelines
  diff          Compare two scans or two points in time
  pivot         Ask the Pivot Advisor for next-best actions

Cases and evidence
  case          Create, list, annotate, close, and bundle cases
  evidence      List, verify, timestamp, and export evidence
  import        Import data from other tools
  export        Export data
  report        Generate reports

Platform
  serve         Start the API server, UI, and scheduler
  worker        Start a distributed worker
  modules       list | info | doctor | test
  plugin        install | verify | list | remove
  scope         init | show | validate | check <target>
  policy        show | validate
  secrets       set | list | test | rotate | import
  data          fetch | status | verify
  db            migrate | status | backup | vacuum
  purge         Erase data by subject, case, or age
  audit         Query and verify the audit chain

Utility
  config        show | validate | path
  doctor        Environment, clock drift, connectivity, key validity
  version

Exit codes
  0 success            4 policy violation    7 storage error
  1 general error      5 partial results     8 evidence verification failed
  2 usage error        6 secrets error       130 interrupted
  3 scope violation

`)
}

// globalFlags are shared by every command that needs configuration.
type globalFlags struct {
	configPath string
	profile    string
	verbose    int
	quiet      bool
	noColor    bool
}

func (g *globalFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&g.configPath, "config", "", "config file path")
	fs.StringVar(&g.configPath, "c", "", "config file path (shorthand)")
	fs.StringVar(&g.profile, "profile", "", "config profile: default, stealth, fast, thorough, monitor")
	fs.IntVar(&g.verbose, "v", 0, "verbosity (repeat for more)")
	fs.BoolVar(&g.quiet, "q", false, "suppress non-essential output")
	fs.BoolVar(&g.noColor, "no-color", false, "disable coloured output")
}

func (g *globalFlags) load() (*config.Config, error) {
	return config.Load(g.configPath, g.profile)
}

// newFlagSet builds a flag set that reports errors instead of exiting, so the
// library-style Run signature can control the exit code.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func runModules(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return moduleList(args, stdout, stderr)
	}
	switch args[0] {
	case "list", "ls":
		return moduleList(args[1:], stdout, stderr)
	case "info":
		if len(args) < 2 {
			return engine.ExitUsage, fmt.Errorf("usage: argus modules info <name>")
		}
		return moduleInfo(args[1], args[2:], stdout, stderr)
	case "doctor":
		return moduleDoctor(args[1:], stdout, stderr)
	}
	return engine.ExitUsage, fmt.Errorf("unknown subcommand %q for modules", args[0])
}

func moduleList(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("modules list", stderr)
	var g globalFlags
	g.register(fs)
	category := fs.String("category", "", "filter by category")
	verbose := fs.Bool("explain", false, "show egress hosts, secrets, and declared inputs")
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}

	mods := sdk.RegisteredModules()
	sort.Slice(mods, func(i, j int) bool { return mods[i].Manifest().Name < mods[j].Manifest().Name })

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MODULE\tVER\tCATEGORY\tMODE\tSENSITIVITY\tCONSUME\tPRODUCE")
	for _, m := range mods {
		man := m.Manifest()
		if *category != "" && man.Category != *category {
			continue
		}
		if *verbose {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				man.Name, man.Version, man.Category, man.Mode, man.Sensitivity,
				joinTypes(man.Consumes), joinTypes(man.Produces))
			fmt.Fprintf(tw, "  egress\t%s\n", strings.Join(man.EgressHosts, ", "))
			if len(man.Secrets) > 0 {
				var names []string
				for _, s := range man.Secrets {
					req := "optional"
					if s.Required {
						req = "required"
					}
					names = append(names, fmt.Sprintf("%s (%s)", s.Name, req))
				}
				fmt.Fprintf(tw, "  secrets\t%s\n", strings.Join(names, ", "))
			}
			if man.CostPerCall > 0 {
				fmt.Fprintf(tw, "  cost\t$%.4f per call\n", man.CostPerCall)
			}
			if problems := sdk.ValidateManifest(man); len(problems) > 0 {
				fmt.Fprintf(tw, "  PROBLEMS\t%s\n", strings.Join(problems, "; "))
			}
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			man.Name, man.Version, man.Category, man.Mode, man.Sensitivity,
			joinTypes(man.Consumes), joinTypes(man.Produces))
	}
	if err := tw.Flush(); err != nil {
		return engine.ExitError, err
	}
	if len(mods) == 0 {
		fmt.Fprintln(stderr, "no modules are registered; the binary may have been built without the module imports")
	}
	return engine.ExitOK, nil
}

func moduleInfo(name string, args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("modules info", stderr)
	var g globalFlags
	g.register(fs)
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	m, ok := sdk.New(name)
	if !ok {
		return engine.ExitError, fmt.Errorf("no such module %q; run `argus modules list`", name)
	}
	man := m.Manifest()
	fmt.Fprintf(stdout, "name        %s\n", man.Name)
	fmt.Fprintf(stdout, "version     %s\n", man.Version)
	fmt.Fprintf(stdout, "category    %s\n", man.Category)
	fmt.Fprintf(stdout, "description %s\n", man.Description)
	fmt.Fprintf(stdout, "mode        %s\n", man.Mode)
	fmt.Fprintf(stdout, "sensitivity %s\n", man.Sensitivity)
	fmt.Fprintf(stdout, "consumes    %s\n", joinTypes(man.Consumes))
	fmt.Fprintf(stdout, "produces    %s\n", joinTypes(man.Produces))
	fmt.Fprintf(stdout, "egress      %s\n", strings.Join(man.EgressHosts, ", "))
	if len(man.Secrets) > 0 {
		fmt.Fprintf(stdout, "secrets     %s\n", strings.Join(man.SecretNames(), ", "))
	} else {
		fmt.Fprintln(stdout, "secrets     none")
	}
	fmt.Fprintf(stdout, "cost/call   $%.4f\n", man.CostPerCall)
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		fmt.Fprintf(stdout, "\nmanifest problems:\n")
		for _, p := range problems {
			fmt.Fprintf(stdout, "  - %s\n", p)
		}
		return engine.ExitError, nil
	}
	return engine.ExitOK, nil
}

// moduleDoctor validates every manifest. It is the check that catches a collector
// declaring an empty egress allow-list, which would otherwise be allowed to reach
// anything.
func moduleDoctor(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("modules doctor", stderr)
	var g globalFlags
	g.register(fs)
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}
	mods := sdk.RegisteredModules()
	sort.Slice(mods, func(i, j int) bool { return mods[i].Manifest().Name < mods[j].Manifest().Name })

	bad := 0
	for _, m := range mods {
		man := m.Manifest()
		problems := sdk.ValidateManifest(man)
		if len(problems) == 0 {
			fmt.Fprintf(stdout, "ok    %-24s %s\n", man.Name, man.Mode)
			continue
		}
		bad++
		fmt.Fprintf(stdout, "FAIL  %-24s %s\n", man.Name, man.Mode)
		for _, p := range problems {
			fmt.Fprintf(stdout, "        - %s\n", p)
		}
	}
	fmt.Fprintf(stdout, "\n%d module(s) checked, %d with problems\n", len(mods), bad)
	if bad > 0 {
		return engine.ExitError, nil
	}
	return engine.ExitOK, nil
}

func joinTypes(ts []sdk.EntityType) string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = string(t)
	}
	return strings.Join(out, ",")
}

func runConfig(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return engine.ExitUsage, fmt.Errorf("usage: argus config <show|validate|path>")
	}
	switch args[0] {
	case "show":
		fs := newFlagSet("config show", stderr)
		var g globalFlags
		g.register(fs)
		if err := parse(fs, args[1:]); err != nil {
			return engine.ExitUsage, err
		}
		c, err := g.load()
		if err != nil {
			return engine.ExitStorage, err
		}
		b, err := config.MarshalYAML(c)
		if err != nil {
			return engine.ExitError, err
		}
		fmt.Fprint(stdout, string(b))
		return engine.ExitOK, nil

	case "validate":
		fs := newFlagSet("config validate", stderr)
		var g globalFlags
		g.register(fs)
		if err := parse(fs, args[1:]); err != nil {
			return engine.ExitUsage, err
		}
		c, err := g.load()
		if err != nil {
			fmt.Fprintf(stderr, "invalid: %v\n", err)
			return engine.ExitUsage, err
		}
		src := c.SourcePath
		if src == "" {
			src = "(built-in defaults)"
		}
		fmt.Fprintf(stdout, "valid: %s (profile %s)\n", src, c.AppliedProfile)
		return engine.ExitOK, nil

	case "path":
		fs := newFlagSet("config path", stderr)
		var g globalFlags
		g.register(fs)
		if err := parse(fs, args[1:]); err != nil {
			return engine.ExitUsage, err
		}
		c, err := g.load()
		if err != nil {
			return engine.ExitStorage, err
		}
		fmt.Fprintln(stdout, c.Storage.Primary.DSN)
		return engine.ExitOK, nil
	}
	return engine.ExitUsage, fmt.Errorf("unknown subcommand %q for config", args[0])
}

// formatDuration renders a duration compactly for tables.
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return d.Round(time.Second).String()
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
