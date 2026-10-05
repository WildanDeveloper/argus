<div align="center">

# 🛰️ ARGUS

### A modular, concurrent, evidence-first OSINT framework written in Go

*One target in → dozens of collectors in parallel → normalized, correlated, scored, evidence-backed results out.*

[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-pre--alpha-orange)
![Default mode](https://img.shields.io/badge/default%20mode-passive-brightgreen)

</div>

---

> **Status: under construction.** This repository holds a working slice of
> milestone **0.1** (foundation), not the finished product.

> **Use responsibly.** Argus is for authorized security assessments, threat
> intelligence, due diligence, journalism, and research on public information.
> Read the responsible-use guidance before your first scan.

## What works today

```bash
go install github.com/WildanDeveloper/argus/cmd/argus@latest

argus init                                              # or: make build
argus scope init --engagement ACME-2026-01 \
     --domain acme.example --authorized-by "J. Doe" --valid-days 30
argus scan acme.example -m dns-records --mode standard --dry-run --explain
argus scan acme.example -m dns-records --mode standard
argus show entities --min-confidence 0.7
argus audit verify
```

A scan against a real target:

```
$ argus scan example.com -m dns-records --mode standard
scan finished
  modules run   1
  findings      9
  entities      9
  errors        0

$ argus show entities
TYPE         VALUE                             CONF  FIRST SEEN
ip           104.20.23.154                    0.500  2026-10-05
ip           2606:4700:10::6814:179a          0.500  2026-10-05
subdomain    elliott.ns.cloudflare.com        0.500  2026-10-05
text         v=spf1 -all                      0.500  2026-10-05
```

Confidence sits at 0.500 rather than higher because `dns-records` does not yet
retain a retrievable artifact, so every finding is *unverified* and capped by the
evidence-first rule. Capturing evidence per module is the next step.

## Built so far

| Area | What exists |
|---|---|
| `pkg/sdk` | The module contract: `Manifest`, `Task`, `Emitter`, `Deps`. Canonicalization per Appendix A, content-derived entity/observation/relation IDs, compile-time registry. Standard library plus three vetted `golang.org/x` packages. |
| `pkg/canon` | Registrable-domain resolution via the Public Suffix List, and the `domain` vs `subdomain` distinction. |
| `pkg/sdktest` | Harness for module authors: fake deps, fixed clock, recording emitter, egress-allow-list assertions. |
| `internal/audit` | Append-only hash-chained log. Detects modification, deletion, and reordering; survives restart; readable as plain JSONL without this tool. |
| `internal/policy` | Scope-as-code that denies by default, purpose limitation, four-eyes approval. |
| `internal/egress` | The single choke point for outbound requests. SSRF guard at dial time, three-level rate limiting, circuit breaker, narrow retry set, body limits, audit of every outcome. |
| `internal/pipeline` | Admiralty-graded Noisy-OR confidence with independence grouping, freshness decay, conflict penalties, and explainable output. |
| `internal/store` | SQLite store with idempotent atomic batch upserts, bitemporal observations, and cascade-aware erasure. |
| `internal/engine` | Orchestrator: per-module task queues, bulkheads, budgets, depth-bounded chaining, panic isolation. |
| `modules/domain/dnsrecords` | The first collector. Multi-resolver DoH consensus. |

## Principles the code actually enforces

These are not aspirations in a document; each one is a check that fails a test
when it is violated.

- **Passive-first.** Active-mode modules are disabled by default and require both
  `--allow-active` and written authorization in `scope.yaml`.
- **Scope-as-code.** No packet leaves the machine without passing the guard, and
  the guard denies when scope is missing. An out-of-scope asset discovered mid-scan
  is recorded and never contacted.
- **Evidence-first.** A finding with no retrievable artifact is capped at 0.5
  confidence, so it can never reach an alerting threshold.
- **Observation-centric.** Facts are claims by a source at a time. Nothing is
  overwritten, only superseded, so "who said what, when" stays answerable.
- **Explainable.** Every score and every refusal carries a reason a human can read.
- **Least privilege.** A module can only reach the hosts its manifest declares, and
  only read the secrets its manifest declares.
- **Honest identification.** Argus never rotates or spoofs its user agent
  (ADR-010). A tool that hides itself cannot be attributed by the party scanned.

## Development

```bash
make build      # static binaries into ./bin
make test       # unit tests with the race detector
make lint       # gofmt check, go vet, and the §4.5 import layering rules
make cover      # coverage report with a threshold gate
make help       # all targets
```

`make lint` verifies the layering rules mechanically: `pkg/sdk` may not import
`internal/` or `modules/`, and `modules/*` may not import `internal/` or other
modules. Those are compile-time errors, not style preferences.

## Not implemented

Deliberately out of scope by design, and contributions adding them will not be
merged: exploitation, credential stuffing, account-existence oracles, messaging-app
contact lookups, biometric identification, pattern-of-life tracking, bypassing
CAPTCHAs or rate limits, and scraping people-search sites.

The full non-goals list and the milestone roadmap are tracked in the project
issue tracker.

## License

MIT. Bundled and downloadable datasets carry their own licenses and terms of
service; you are responsible for complying with each provider's terms.
