package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/internal/engine"
	"github.com/WildanDeveloper/argus/internal/store"
)

func runEvidence(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return engine.ExitUsage, fmt.Errorf("usage: argus evidence <list|verify|show> [flags]")
	}

	fs := newFlagSet("evidence "+args[0], stderr)
	var g globalFlags
	g.register(fs)
	caseID := fs.String("case", "", "case to inspect")
	limit := fs.Int("limit", 50, "maximum records")
	raw := fs.Bool("raw", false, "print the artifact contents")
	if err := parse(fs, args[1:]); err != nil {
		return engine.ExitUsage, err
	}

	cfg, err := g.load()
	if err != nil {
		return engine.ExitUsage, err
	}
	if *caseID == "" {
		return engine.ExitUsage, fmt.Errorf("--case is required: evidence is scoped to a case so its chain stays meaningful")
	}

	st, err := store.Open(context.Background(), store.Driver(cfg.Storage.Primary.Driver), cfg.Storage.Primary.DSN)
	if err != nil {
		return engine.ExitStorage, err
	}
	defer st.Close()
	ctx := context.Background()

	switch args[0] {
	case "list":
		recs, err := st.EvidenceForCase(ctx, *caseID, *limit)
		if err != nil {
			return engine.ExitStorage, err
		}
		if len(recs) == 0 {
			fmt.Fprintf(stdout, "no evidence recorded for case %s\n", *caseID)
			return engine.ExitOK, nil
		}
		fmt.Fprintf(stdout, "%-16s %-14s %-8s %-20s %s\n", "ID", "SHA256", "SIZE", "CAPTURED", "COLLECTOR")
		for _, r := range recs {
			fmt.Fprintf(stdout, "%-16s %-14s %-8d %-20s %s\n",
				r.ID, r.SHA256[:min(14, len(r.SHA256))], r.Size,
				r.CapturedAt.UTC().Format("2006-01-02T15:04:05Z"), r.Collector)
		}
		fmt.Fprintf(stdout, "\n%d record(s)\n", len(recs))
		return engine.ExitOK, nil

	case "verify":
		ev, err := engine.NewEvidenceStore(st, cfg.Storage.Blobs.Path, nil)
		if err != nil {
			return engine.ExitStorage, err
		}
		res, err := ev.Verify(ctx, *caseID, *limit)
		if err != nil {
			return engine.ExitStorage, err
		}
		if !res.OK {
			fmt.Fprintf(stderr, "CHAIN BROKEN: %s\n", res.Problem)
			if len(res.BlobsMissing) > 0 {
				for _, m := range res.BlobsMissing {
					fmt.Fprintf(stderr, "  missing artifact: %s\n", m)
				}
			}
			return engine.ExitEvidence, fmt.Errorf("evidence verification failed")
		}
		fmt.Fprintln(stdout, "evidence intact")
		fmt.Fprintf(stdout, "  case     %s\n", *caseID)
		fmt.Fprintf(stdout, "  records  %d\n", res.Checked)
		fmt.Fprintf(stdout, "  blobs    %d re-hashed and matched\n", res.BlobsPresent)
		fmt.Fprintf(stdout, "  head     %s\n", res.ChainHead)
		return engine.ExitOK, nil

	case "show":
		if fs.NArg() < 1 {
			return engine.ExitUsage, fmt.Errorf("usage: argus evidence show <id> --case <id>")
		}
		id := fs.Arg(0)
		recs, err := st.EvidenceForCase(ctx, *caseID, *limit*10)
		if err != nil {
			return engine.ExitStorage, err
		}
		var found *store.Evidence
		for i := range recs {
			if recs[i].ID == id {
				found = &recs[i]
				break
			}
		}
		if found == nil {
			return engine.ExitStorage, fmt.Errorf("%w: evidence %s in case %s", store.ErrNotFound, id, *caseID)
		}
		fmt.Fprintf(stdout, "id           %s\n", found.ID)
		fmt.Fprintf(stdout, "sha256       %s\n", found.SHA256)
		fmt.Fprintf(stdout, "size         %d bytes\n", found.Size)
		fmt.Fprintf(stdout, "media type   %s\n", found.MediaType)
		fmt.Fprintf(stdout, "source       %s\n", found.Source)
		fmt.Fprintf(stdout, "method       %s\n", found.Method)
		fmt.Fprintf(stdout, "collector    %s\n", found.Collector)
		fmt.Fprintf(stdout, "captured     %s\n", found.CapturedAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(stdout, "prev hash    %s\n", found.PrevHash)
		fmt.Fprintf(stdout, "record hash  %s\n", found.RecordHash)

		if *raw {
			ev, err := engine.NewEvidenceStore(st, cfg.Storage.Blobs.Path, nil)
			if err != nil {
				return engine.ExitStorage, err
			}
			data, err := ev.Read(found.SHA256)
			if err != nil {
				return engine.ExitStorage, err
			}
			if sha := sha256Hex(data); sha != found.SHA256 {
				return engine.ExitEvidence, fmt.Errorf("artifact content does not match its digest")
			}
			fmt.Fprintf(stdout, "\n%s\n", strings.TrimRight(string(data), "\n"))
		}
		return engine.ExitOK, nil
	}

	return engine.ExitUsage, fmt.Errorf("unknown subcommand %q for evidence", args[0])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
