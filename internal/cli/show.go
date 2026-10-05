package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/WildanDeveloper/argus/internal/audit"
	"github.com/WildanDeveloper/argus/internal/config"
	"github.com/WildanDeveloper/argus/internal/engine"
	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

func runShow(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return engine.ExitUsage, fmt.Errorf("usage: argus show <entities|relations|observations> [flags]")
	}
	switch args[0] {
	case "entities", "entity":
		return showEntities(args[1:], stdout, stderr)
	}
	return engine.ExitUsage, fmt.Errorf("unknown subcommand %q for show", args[0])
}

func showEntities(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("show entities", stderr)
	var g globalFlags
	g.register(fs)
	var typ, tags, scan string
	var minConf float64
	var limit, offset int
	var asJSON bool
	fs.StringVar(&typ, "type", "", "filter by entity type")
	fs.StringVar(&tags, "tags", "", "comma-separated required tags")
	fs.StringVar(&scan, "scan", "", "restrict to entities observed in a scan")
	fs.Float64Var(&minConf, "min-confidence", 0, "minimum confidence")
	fs.IntVar(&limit, "limit", 50, "maximum rows")
	fs.IntVar(&offset, "offset", 0, "rows to skip")
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	if err := parse(fs, args); err != nil {
		return engine.ExitUsage, err
	}

	cfg, err := g.load()
	if err != nil {
		return engine.ExitUsage, err
	}
	st, err := store.Open(context.Background(), store.Driver(cfg.Storage.Primary.Driver), cfg.Storage.Primary.DSN)
	if err != nil {
		return engine.ExitStorage, err
	}
	defer st.Close()

	q := store.EntityQuery{
		ScanID: scan, Tags: splitNonEmpty(tags),
		MinConfidence: minConf, Limit: limit, Offset: offset,
	}
	if typ != "" {
		for _, t := range splitNonEmpty(typ) {
			if !sdk.ValidEntityType(t) {
				return engine.ExitUsage, fmt.Errorf("unknown entity type %q; known types: %s", t, strings.Join(typeNames(), ", "))
			}
			q.Types = append(q.Types, sdk.EntityType(t))
		}
	}

	list, total, err := st.ListEntities(context.Background(), q)
	if err != nil {
		return engine.ExitStorage, err
	}

	if asJSON {
		if err := renderJSON(stdout, list, total); err != nil {
			return engine.ExitError, err
		}
		return engine.ExitOK, nil
	}
	fmt.Fprintf(stdout, "%-12s %-42s %6s  %s\n", "TYPE", "VALUE", "CONF", "FIRST SEEN")
	shown := 0
	for _, e := range list {
		fmt.Fprintf(stdout, "%-12s %-42s %6.3f  %s\n",
			e.Type, truncate(e.Value, 42), e.Confidence, e.FirstSeen.UTC().Format("2006-01-02"))
		shown++
	}
	fmt.Fprintf(stdout, "\n%d of %d entities\n", shown, total)
	return engine.ExitOK, nil
}

func typeNames() []string {
	out := make([]string, 0, 30)
	for _, t := range sdk.AllEntityTypes() {
		out = append(out, string(t))
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func renderJSON(w io.Writer, list []sdk.Entity, total int) error {
	out := struct {
		Total    int          `json:"total"`
		Returned int          `json:"returned"`
		Entities []sdk.Entity `json:"entities"`
	}{total, len(list), list}
	b, err := config.MarshalYAML(out)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func runAudit(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return engine.ExitUsage, fmt.Errorf("usage: argus audit <verify|show> [flags]")
	}
	fs := newFlagSet("audit "+args[0], stderr)
	var g globalFlags
	g.register(fs)
	limit := fs.Int("limit", 50, "maximum entries to show")
	action := fs.String("action", "", "filter by action")
	if err := parse(fs, args[1:]); err != nil {
		return engine.ExitUsage, err
	}
	cfg, err := g.load()
	if err != nil {
		return engine.ExitUsage, err
	}
	path := cfg.Storage.Primary.DSN + ".audit.jsonl"

	switch args[0] {
	case "verify":
		log, err := audit.OpenJSONL(path)
		if err != nil {
			return engine.ExitStorage, err
		}
		res, err := log.Verify(context.Background(), 0)
		if err != nil {
			return engine.ExitStorage, err
		}
		if !res.OK {
			fmt.Fprintf(stderr, "CHAIN BROKEN at sequence %d: %s\n", res.BrokenAtSeq, res.BrokenReason)
			return engine.ExitEvidence, fmt.Errorf("audit chain verification failed")
		}
		fmt.Fprintf(stdout, "chain intact\n")
		fmt.Fprintf(stdout, "  entries  %d\n", res.Entries)
		fmt.Fprintf(stdout, "  head     %s\n", res.HeadHash)
		return engine.ExitOK, nil

	case "show":
		log, err := audit.OpenJSONL(path)
		if err != nil {
			return engine.ExitStorage, err
		}
		entries, err := log.Query(context.Background(), audit.Query{Action: *action, Limit: *limit})
		if err != nil {
			return engine.ExitStorage, err
		}
		fmt.Fprintf(stdout, "%6s %-20s %-24s %s\n", "SEQ", "AT", "ACTION", "DETAIL")
		for _, e := range entries {
			fmt.Fprintf(stdout, "%6d %-20s %-24s %v\n", e.Seq, e.At.UTC().Format("2006-01-02T15:04:05Z"), e.Action, e.Detail)
		}
		return engine.ExitOK, nil
	}
	return engine.ExitUsage, fmt.Errorf("unknown subcommand %q for audit", args[0])
}
