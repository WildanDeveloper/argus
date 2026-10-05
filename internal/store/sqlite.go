package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"

	_ "modernc.org/sqlite" // pure-Go SQLite, so CGO stays optional (ADR-005)
)

// SQLite is the default store: zero-setup, single file, WAL mode.
type SQLite struct {
	db *sql.DB
	// writeMu serializes write transactions. SQLite allows one writer at a time;
	// without this, concurrent upserts return SQLITE_BUSY and the pipeline would
	// have to retry at a layer that knows nothing about SQL.
	writeMu sync.Mutex
	dsn     string
}

var _ Store = (*SQLite)(nil)

// OpenSQLite opens or creates a database at path.
//
// WAL mode plus a busy timeout is what makes a single-file store usable from a
// 32-worker scan: readers do not block the writer, and a writer that collides
// waits instead of failing.
func OpenSQLite(path string) (*SQLite, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"+
		"&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite %s: %w", path, err)
	}
	// Unlimited open connections would defeat the busy timeout: SQLite serializes
	// writers, so a small pool with a queue is faster and predictable.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(time.Hour)

	s := &SQLite{db: db, dsn: path}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the handle for tests and for the query planner.
func (s *SQLite) DB() *sql.DB { return s.db }

// schema is the SQLite dialect of §17.1. Two deliberate differences from the
// PostgreSQL dialect in the document: attributes and observation objects are JSON
// text (SQLite has no JSONB), and tags live in their own table rather than in a
// TEXT[] column, because SQLite has no array type.
const schema = `
CREATE TABLE IF NOT EXISTS schema_version (
  version    INTEGER NOT NULL,
  applied_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id          TEXT PRIMARY KEY,
  case_id     TEXT,
  workflow    TEXT,
  target_type TEXT NOT NULL DEFAULT '',
  target_value TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL,
  purpose     TEXT,
  mode        TEXT NOT NULL DEFAULT 'passive',
  params      TEXT NOT NULL DEFAULT '{}',
  modules     TEXT NOT NULL DEFAULT '[]',
  created_by  TEXT NOT NULL,
  started_at  TEXT,
  finished_at TEXT,
  summary     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS scans_case ON scans (case_id);
CREATE INDEX IF NOT EXISTS scans_status ON scans (status);

CREATE TABLE IF NOT EXISTS entities (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  value       TEXT NOT NULL,
  display     TEXT,
  attrs       TEXT NOT NULL DEFAULT '{}',
  confidence  REAL NOT NULL DEFAULT 0,
  sensitivity SMALLINT NOT NULL DEFAULT 0,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  UNIQUE (type, value)
);
CREATE INDEX IF NOT EXISTS entities_type ON entities (type);
CREATE INDEX IF NOT EXISTS entities_last_seen ON entities (last_seen DESC);

CREATE TABLE IF NOT EXISTS tags (
  entity_id TEXT NOT NULL,
  tag       TEXT NOT NULL,
  PRIMARY KEY (entity_id, tag)
);
CREATE INDEX IF NOT EXISTS tags_tag ON tags (tag);

CREATE TABLE IF NOT EXISTS observations (
  id              TEXT PRIMARY KEY,
  scan_id         TEXT NOT NULL,
  subject         TEXT NOT NULL,
  predicate       TEXT NOT NULL,
  object          TEXT,
  source_module   TEXT NOT NULL,
  source_provider TEXT,
  source_method   TEXT,
  reliability     TEXT NOT NULL,
  credibility     TEXT NOT NULL,
  observed_at     TEXT NOT NULL,
  valid_from      TEXT,
  valid_to        TEXT,
  attrs           TEXT NOT NULL DEFAULT '{}',
  evidence        TEXT NOT NULL DEFAULT '[]',
  conflict        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS obs_subject ON observations (subject, observed_at DESC);
CREATE INDEX IF NOT EXISTS obs_scan ON observations (scan_id);
CREATE INDEX IF NOT EXISTS obs_predicate ON observations (predicate);

CREATE TABLE IF NOT EXISTS relations (
  id         TEXT PRIMARY KEY,
  from_id    TEXT NOT NULL,
  to_id      TEXT NOT NULL,
  type       TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  heuristic  INTEGER NOT NULL DEFAULT 0,
  obs        TEXT NOT NULL DEFAULT '[]',
  UNIQUE (from_id, to_id, type)
);
CREATE INDEX IF NOT EXISTS rel_from ON relations (from_id, type);
CREATE INDEX IF NOT EXISTS rel_to ON relations (to_id, type);

CREATE TABLE IF NOT EXISTS findings (
  id         TEXT PRIMARY KEY,
  scan_id    TEXT NOT NULL,
  entity_id  TEXT NOT NULL,
  kind       TEXT NOT NULL,
  severity   TEXT NOT NULL DEFAULT '',
  summary    TEXT NOT NULL DEFAULT '',
  attrs      TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS findings_sev ON findings (severity);

CREATE TABLE IF NOT EXISTS evidence (
  id          TEXT PRIMARY KEY,
  case_id     TEXT,
  scan_id     TEXT,
  sha256      TEXT NOT NULL,
  size        INTEGER NOT NULL,
  media_type  TEXT,
  source      TEXT,
  method      TEXT,
  collector   TEXT,
  captured_at TEXT NOT NULL,
  prev_hash   TEXT,
  record_hash TEXT NOT NULL,
  tsa_token   BLOB,
  signature   BLOB,
  blob_path   TEXT
);
CREATE INDEX IF NOT EXISTS evidence_case ON evidence (case_id);
CREATE INDEX IF NOT EXISTS evidence_sha ON evidence (sha256);

CREATE TABLE IF NOT EXISTS entity_scans (
  entity_id TEXT NOT NULL,
  scan_id   TEXT NOT NULL,
  PRIMARY KEY (entity_id, scan_id)
);
CREATE INDEX IF NOT EXISTS entity_scans_scan ON entity_scans (scan_id);

-- An observation is content-addressed and immutable, so two scans that assert the
-- same fact produce ONE row. Membership has to live in a link table, otherwise
-- "what did scan X assert" is unrecoverable and a diff cannot distinguish an
-- unchanged fact from a fact the later scan never observed.
CREATE TABLE IF NOT EXISTS observation_scans (
  observation_id TEXT NOT NULL,
  scan_id        TEXT NOT NULL,
  PRIMARY KEY (observation_id, scan_id)
);
CREATE INDEX IF NOT EXISTS observation_scans_scan ON observation_scans (scan_id);
`

// migrate applies the schema. It is idempotent, so running at every open is safe
// and removes a class of "works on my machine" first-run failure.
func (s *SQLite) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("store: apply schema: %w", err)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_version (version, applied_at) VALUES (1, ?)
		 ON CONFLICT DO NOTHING`, time.Now().UTC().Format(time.RFC3339))
	return err
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// jsonBytes marshals a slice, rendering an empty slice as "[]" rather than "null"
// so a stored column is always valid JSON of a known shape.
func jsonBytes(v any) string {
	if v == nil {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	if string(b) == "null" {
		return "[]"
	}
	return string(b)
}

func jsonMap(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func parseJSONMap(s string) map[string]any {
	if s == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string]any{}
	}
	return out
}

// SaveScan records a scan, assigning an ID when one was not supplied. It takes a
// pointer so a generated ID reaches the caller: without that, a caller cannot
// refer to the scan it just created.
func (s *SQLite) SaveScan(ctx context.Context, sc *Scan) error {
	if sc.ID == "" {
		sc.ID = NewScanID()
	}
	if sc.Status == "" {
		sc.Status = ScanQueued
	}
	if sc.Mode.String() == "" {
		sc.Mode = sdk.ModePassive
	}
	params := jsonMap(toAnyMap(sc.Params))
	modules, _ := json.Marshal(sc.Modules)
	summary, _ := json.Marshal(sc.Summary)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scans (id, case_id, workflow, target_type, target_value, status, purpose, mode, params, modules, created_by, started_at, finished_at, summary)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			case_id=excluded.case_id, workflow=excluded.workflow, status=excluded.status,
			purpose=excluded.purpose, params=excluded.params, modules=excluded.modules,
			summary=excluded.summary, started_at=excluded.started_at, finished_at=excluded.finished_at`,
		sc.ID, nullString(sc.CaseID), sc.Workflow, string(sc.Target.Type), sc.Target.Value,
		string(sc.Status), nullString(sc.Purpose), sc.Mode.String(), params, string(modules),
		sc.CreatedBy, ts(sc.StartedAt), ts(sc.FinishedAt), string(summary))
	if err != nil {
		return describeErr("SaveScan", err)
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// GetScan returns a scan by ID.
func (s *SQLite) GetScan(ctx context.Context, id string) (Scan, error) {
	var sc Scan
	var status, mode, params, modules, summary string
	var started, finished sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, COALESCE(case_id,''), COALESCE(workflow,''), target_type, target_value, status,
		       COALESCE(purpose,''), mode, params, modules, created_by,
		       started_at, finished_at, summary
		FROM scans WHERE id = ?`, id).
		Scan(&sc.ID, &sc.CaseID, &sc.Workflow, &sc.Target.Type, &sc.Target.Value, &status,
			&sc.Purpose, &mode, &params, &modules, &sc.CreatedBy,
			&started, &finished, &summary)
	if errors.Is(err, sql.ErrNoRows) {
		return sc, fmt.Errorf("%w: scan %s", ErrNotFound, id)
	}
	if err != nil {
		return sc, describeErr("GetScan", err)
	}
	sc.Status = ScanStatus(status)
	sc.Mode, _ = sdk.ParseMode(mode)
	sc.Target.ID = sdk.NewEntityID(sc.Target.Type, sc.Target.Value)
	_ = json.Unmarshal([]byte(params), &sc.Params)
	_ = json.Unmarshal([]byte(modules), &sc.Modules)
	_ = json.Unmarshal([]byte(summary), &sc.Summary)
	sc.StartedAt = parseTS(started.String)
	sc.FinishedAt = parseTS(finished.String)
	return sc, nil
}

// FinishScan writes a terminal state and summary.
func (s *SQLite) FinishScan(ctx context.Context, id string, status ScanStatus, summary ScanSummary) error {
	b, _ := json.Marshal(summary)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	res, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ?, summary = ? WHERE id = ?`,
		string(status), ts(time.Now()), string(b), id)
	if err != nil {
		return describeErr("FinishScan", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: scan %s", ErrNotFound, id)
	}
	return nil
}

// UpsertBatch writes a batch atomically and idempotently.
//
// The transaction is the reason a crash mid-write cannot leave a half-applied
// batch: either the observations and their entities land together or neither
// does. Replaying the batch is a no-op because every primary key is derived from
// content, which is what makes at-least-once delivery safe.
func (s *SQLite) UpsertBatch(ctx context.Context, scanID string, b Batch) error {
	if b.IsEmpty() {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return describeErr("UpsertBatch begin", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	now := time.Now().UTC()

	for i := range b.Entities {
		e := &b.Entities[i]
		if e.ID == "" {
			continue
		}
		if e.FirstSeen.IsZero() {
			e.FirstSeen = now
		}
		if e.LastSeen.IsZero() {
			e.LastSeen = now
		}
		attrs, _ := json.Marshal(e.Attrs)
		_, err := tx.ExecContext(ctx, `
			INSERT INTO entities (id, type, value, display, attrs, confidence, sensitivity, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
				attrs      = excluded.attrs,
				display    = COALESCE(NULLIF(excluded.display,''), entities.display),
				confidence = MAX(excluded.confidence, entities.confidence),
				sensitivity = excluded.sensitivity,
				-- first_seen is the earliest sighting and last_seen the latest;
				-- neither is ever moved backwards by a later scan.
				first_seen = MIN(entities.first_seen, excluded.first_seen),
				last_seen  = MAX(entities.last_seen,  excluded.last_seen)`,
			string(e.ID), string(e.Type), e.Value, e.Display, string(attrs), e.Confidence,
			int(e.Sensitivity), ts(e.FirstSeen), ts(e.LastSeen))
		if err != nil {
			return describeErr("UpsertBatch entity", err)
		}

		for _, tag := range e.Tags {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO tags (entity_id, tag) VALUES (?,?) ON CONFLICT DO NOTHING`,
				string(e.ID), tag); err != nil {
				return describeErr("UpsertBatch tag", err)
			}
		}
		if scanID != "" {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO entity_scans (entity_id, scan_id) VALUES (?,?) ON CONFLICT DO NOTHING`,
				string(e.ID), scanID); err != nil {
				return describeErr("UpsertBatch entity_scan", err)
			}
		}
	}

	for i := range b.Observations {
		o := &b.Observations[i]
		if o.ID == "" || o.Subject == "" {
			continue
		}
		obsAt := o.ObservedAt
		if obsAt.IsZero() {
			obsAt = now
		}
		obj, _ := json.Marshal(o.Object)
		ev := jsonBytes(o.Evidence)
		conflict := 0
		if o.Attrs != nil && o.Attrs["conflict"] == true {
			conflict = 1
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO observations (id, scan_id, subject, predicate, object, source_module, source_provider,
				source_method, reliability, credibility, observed_at, valid_from, valid_to, attrs, evidence, conflict)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO NOTHING`,
			o.ID, scanID, string(o.Subject), o.Predicate, string(obj),
			o.Source.Module, nullString(o.Source.Provider), nullString(o.Source.Method),
			string(o.Reliability), string(o.Credibility), ts(obsAt),
			tsPtr(o.ValidFrom), tsPtr(o.ValidTo), jsonMap(o.Attrs), string(ev), conflict)
		if err != nil {
			return describeErr("UpsertBatch observation", err)
		}
		if scanID != "" {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO observation_scans (observation_id, scan_id) VALUES (?,?)
				 ON CONFLICT DO NOTHING`, o.ID, scanID); err != nil {
				return describeErr("UpsertBatch observation_scan", err)
			}
		}
	}

	for i := range b.Relations {
		r := &b.Relations[i]
		if r.ID == "" {
			continue
		}
		obs, _ := json.Marshal(r.Obs)
		// A heuristic edge must not silently be promoted to a verified one, so
		// conflict resolution keeps the verified flag once it is set.
		_, err := tx.ExecContext(ctx, `
			INSERT INTO relations (id, from_id, to_id, type, confidence, heuristic, obs)
			VALUES (?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
				confidence = MAX(excluded.confidence, relations.confidence),
				heuristic  = MIN(excluded.heuristic, relations.heuristic),
				obs        = excluded.obs`,
			r.ID, string(r.From), string(r.To), string(r.Type), r.Confidence,
			boolInt(r.Heuristic), string(obs))
		if err != nil {
			return describeErr("UpsertBatch relation", err)
		}
	}

	for i := range b.Findings {
		f := &b.Findings[i]
		if f.Entity.ID == "" || f.Kind == "" {
			continue
		}
		attrs := map[string]any{}
		if f.Observation.Attrs != nil {
			for k, v := range f.Observation.Attrs {
				attrs[k] = v
			}
		}
		attrs["entity_value"] = f.Entity.Value
		attrs["source"] = f.Observation.Source.String()
		if f.Severity != "" {
			attrs["severity"] = f.Severity
		}
		id := sdk.ObservationID("finding", string(f.Entity.ID), f.Kind, attrs, nil)
		_, err := tx.ExecContext(ctx, `
			INSERT INTO findings (id, scan_id, entity_id, kind, severity, summary, attrs, created_at)
			VALUES (?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO NOTHING`,
			id, scanID, string(f.Entity.ID), f.Kind, f.Severity,
			fmt.Sprintf("%s: %s", f.Kind, f.Entity.Value), jsonMap(attrs), ts(now))
		if err != nil {
			return describeErr("UpsertBatch finding", err)
		}
	}

	return tx.Commit()
}

func tsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const entityCols = `id, type, value, COALESCE(display,''), attrs, confidence, sensitivity, first_seen, last_seen`

// entityColsPrefixed is the same list qualified for use with an alias. Rewriting
// entityCols by string substitution would corrupt the "COALESCE(display,”)"
// fragment, so the prefixed form is written out.
const entityColsPrefixed = `e.id, e.type, e.value, COALESCE(e.display,''), e.attrs, e.confidence, e.sensitivity, e.first_seen, e.last_seen`

func scanEntity(rows interface{ Scan(...any) error }) (sdk.Entity, error) {
	var e sdk.Entity
	var typ, attrs, firstSeen, lastSeen string
	err := rows.Scan(&e.ID, &typ, &e.Value, &e.Display, &attrs, &e.Confidence, &e.Sensitivity, &firstSeen, &lastSeen)
	if err != nil {
		return e, err
	}
	e.Type = sdk.EntityType(typ)
	e.Attrs = map[string]sdk.Attr{}
	_ = json.Unmarshal([]byte(attrs), &e.Attrs)
	e.FirstSeen = parseTS(firstSeen)
	e.LastSeen = parseTS(lastSeen)
	e.Tags = []string{}
	return e, nil
}

// GetEntity returns one entity.
func (s *SQLite) GetEntity(ctx context.Context, id sdk.EntityID) (sdk.Entity, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+entityCols+` FROM entities WHERE id = ?`, string(id))
	e, err := scanEntity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return e, fmt.Errorf("%w: entity %s", ErrNotFound, id)
	}
	if err != nil {
		return e, describeErr("GetEntity", err)
	}
	e.Tags = s.tagsFor(ctx, id)
	return e, nil
}

// GetEntityByValue finds an entity by type and canonical value.
func (s *SQLite) GetEntityByValue(ctx context.Context, t sdk.EntityType, value string) (sdk.Entity, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+entityCols+` FROM entities WHERE type = ? AND value = ?`,
		string(t), value)
	e, err := scanEntity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return e, fmt.Errorf("%w: %s %s", ErrNotFound, t, value)
	}
	if err != nil {
		return e, describeErr("GetEntityByValue", err)
	}
	e.Tags = s.tagsFor(ctx, idOf(e.ID))
	return e, nil
}

func idOf(id sdk.EntityID) sdk.EntityID { return id }

func (s *SQLite) tagsFor(ctx context.Context, id sdk.EntityID) []string {
	rows, err := s.db.QueryContext(ctx, `SELECT tag FROM tags WHERE entity_id = ? ORDER BY tag`, string(id))
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err == nil {
			out = append(out, tag)
		}
	}
	return out
}

// Observations returns an entity's observation history, newest first.
func (s *SQLite) Observations(ctx context.Context, id sdk.EntityID, limit int) ([]sdk.Observation, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, subject, predicate, object, source_module, COALESCE(source_provider,''),
		       COALESCE(source_method,''), reliability, credibility, observed_at,
		       valid_from, valid_to, attrs, evidence, conflict
		FROM observations WHERE subject = ? ORDER BY observed_at DESC LIMIT ?`,
		string(id), limit)
	if err != nil {
		return nil, describeErr("Observations", err)
	}
	defer rows.Close()

	var out []sdk.Observation
	for rows.Next() {
		var o sdk.Observation
		var subject, rel, cred, obj, attrs, ev string
		var observedAt, validFrom, validTo sql.NullString
		var conflict int
		if err := rows.Scan(&o.ID, &subject, &o.Predicate, &obj, &o.Source.Module, &o.Source.Provider,
			&o.Source.Method, &rel, &cred, &observedAt, &validFrom, &validTo, &attrs, &ev, &conflict); err != nil {
			return nil, describeErr("Observations scan", err)
		}
		o.Subject = sdk.EntityID(subject)
		if len(rel) > 0 {
			o.Reliability = rel[0]
		}
		if len(cred) > 0 {
			o.Credibility = cred[0]
		}
		if obj != "" && obj != "null" {
			var any any
			if json.Unmarshal([]byte(obj), &any) == nil {
				o.Object = any
			}
		}
		o.ObservedAt = parseTS(observedAt.String)
		if validFrom.String != "" {
			t := parseTS(validFrom.String)
			o.ValidFrom = &t
		}
		if validTo.String != "" {
			t := parseTS(validTo.String)
			o.ValidTo = &t
		}
		o.Attrs = parseJSONMap(attrs)
		if conflict == 1 {
			if o.Attrs == nil {
				o.Attrs = map[string]any{}
			}
			o.Attrs["conflict"] = true
		}
		if ev != "" && ev != "[]" {
			_ = json.Unmarshal([]byte(ev), &o.Evidence)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// Relations returns edges touching an entity.
func (s *SQLite) Relations(ctx context.Context, id sdk.EntityID, limit int) ([]sdk.Relation, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, from_id, to_id, type, confidence, heuristic, obs FROM relations
		WHERE from_id = ? OR to_id = ? ORDER BY type LIMIT ?`,
		string(id), string(id), limit)
	if err != nil {
		return nil, describeErr("Relations", err)
	}
	defer rows.Close()

	var out []sdk.Relation
	for rows.Next() {
		var r sdk.Relation
		var from, to, typ, obs string
		var heuristic int
		if err := rows.Scan(&r.ID, &from, &to, &typ, &r.Confidence, &heuristic, &obs); err != nil {
			return nil, describeErr("Relations scan", err)
		}
		r.From, r.To, r.Type = sdk.EntityID(from), sdk.EntityID(to), sdk.RelationType(typ)
		r.Heuristic = heuristic == 1
		if obs != "" && obs != "[]" {
			_ = json.Unmarshal([]byte(obs), &r.Obs)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Neighbors returns entities adjacent to id, breadth-first up to depth hops.
func (s *SQLite) Neighbors(ctx context.Context, id sdk.EntityID, depth, limit int) ([]sdk.Entity, error) {
	if depth <= 0 {
		depth = 1
	}
	if limit <= 0 {
		limit = 200
	}
	seen := map[sdk.EntityID]bool{id: true}
	frontier := []sdk.EntityID{id}
	var out []sdk.Entity

	for hop := 0; hop < depth && len(frontier) > 0 && len(out) < limit; hop++ {
		var next []sdk.EntityID
		for _, cur := range frontier {
			rows, err := s.db.QueryContext(ctx,
				`SELECT `+entityCols+` FROM entities WHERE id IN
				 (SELECT to_id FROM relations WHERE from_id = ?
				  UNION
				  SELECT from_id FROM relations WHERE to_id = ?) LIMIT ?`,
				string(cur), string(cur), limit)
			if err != nil {
				return out, describeErr("Neighbors", err)
			}
			for rows.Next() {
				e, err := scanEntity(rows)
				if err != nil {
					rows.Close()
					return out, describeErr("Neighbors scan", err)
				}
				if seen[e.ID] {
					continue
				}
				seen[e.ID] = true
				e.Tags = s.tagsFor(ctx, e.ID)
				out = append(out, e)
				next = append(next, e.ID)
				if len(out) >= limit {
					break
				}
			}
			rows.Close()
			if len(out) >= limit {
				break
			}
		}
		frontier = next
	}
	return out, nil
}

// ListEntities pages through entities with filters.
func (s *SQLite) ListEntities(ctx context.Context, q EntityQuery) ([]sdk.Entity, int, error) {
	var where []string
	var args []any
	if len(q.Types) > 0 {
		ph := make([]string, len(q.Types))
		for i, t := range q.Types {
			ph[i] = "?"
			args = append(args, string(t))
		}
		where = append(where, "e.type IN ("+strings.Join(ph, ",")+")")
	}
	if q.MinConfidence > 0 {
		where = append(where, "e.confidence >= ?")
		args = append(args, q.MinConfidence)
	}
	if len(q.Tags) > 0 {
		for _, tag := range q.Tags {
			where = append(where, "EXISTS (SELECT 1 FROM tags t WHERE t.entity_id = e.id AND t.tag = ?)")
			args = append(args, tag)
		}
	}
	if q.ScanID != "" {
		where = append(where, "EXISTS (SELECT 1 FROM entity_scans es WHERE es.entity_id = e.id AND es.scan_id = ?)")
		args = append(args, q.ScanID)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entities e`+clause, args...).Scan(&total); err != nil {
		return nil, 0, describeErr("ListEntities count", err)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	qargs := append(append([]any{}, args...), limit, q.Offset)
	rows, err := s.db.QueryContext(ctx, `SELECT `+entityColsPrefixed+
		` FROM entities e`+clause+` ORDER BY e.confidence DESC, e.last_seen DESC LIMIT ? OFFSET ?`, qargs...)
	if err != nil {
		return nil, total, describeErr("ListEntities", err)
	}
	defer rows.Close()

	var out []sdk.Entity
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, total, describeErr("ListEntities scan", err)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// PutEvidence stores an evidence record.
func (s *SQLite) PutEvidence(ctx context.Context, e Evidence) (sdk.EvidenceRef, error) {
	if e.ID == "" {
		e.ID = NewEvidenceID()
	}
	if e.CapturedAt.IsZero() {
		e.CapturedAt = time.Now().UTC()
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO evidence (id, case_id, scan_id, sha256, size, media_type, source, method, collector,
			captured_at, prev_hash, record_hash, tsa_token, signature, blob_path)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO NOTHING`,
		e.ID, nullString(e.CaseID), nullString(e.ScanID), e.SHA256, e.Size, nullString(e.MediaType),
		nullString(e.Source), nullString(e.Method), nullString(e.Collector), ts(e.CapturedAt),
		nullString(e.PrevHash), e.RecordHash, e.TSAToken, e.Signature, nullString(e.BlobPath))
	if err != nil {
		return sdk.EvidenceRef{}, describeErr("PutEvidence", err)
	}
	return sdk.EvidenceRef{ID: e.ID, SHA256: e.SHA256}, nil
}

// Evidence returns an evidence record.
func (s *SQLite) Evidence(ctx context.Context, id string) (Evidence, error) {
	var e Evidence
	var caseID, scanID, mediaType, source, method, collector, blobPath sql.NullString
	var capturedAt, prevHash sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, case_id, scan_id, sha256, size, media_type, source, method, collector,
		       captured_at, prev_hash, record_hash, blob_path FROM evidence WHERE id = ?`, id).
		Scan(&e.ID, &caseID, &scanID, &e.SHA256, &e.Size, &mediaType, &source, &method, &collector,
			&capturedAt, &prevHash, &e.RecordHash, &blobPath)
	if errors.Is(err, sql.ErrNoRows) {
		return e, fmt.Errorf("%w: evidence %s", ErrNotFound, id)
	}
	if err != nil {
		return e, describeErr("Evidence", err)
	}
	e.CaseID, e.ScanID = caseID.String, scanID.String
	e.MediaType, e.Source, e.Method, e.Collector, e.BlobPath = mediaType.String, source.String, method.String, collector.String, blobPath.String
	e.CapturedAt = parseTS(capturedAt.String)
	e.PrevHash = prevHash.String
	return e, nil
}

// Stats reports store counters.
func (s *SQLite) Stats(ctx context.Context) (StoreStats, error) {
	var st StoreStats
	queries := []struct {
		q    string
		dest *int64
	}{
		{`SELECT COUNT(*) FROM entities`, &st.Entities},
		{`SELECT COUNT(*) FROM observations`, &st.Observations},
		{`SELECT COUNT(*) FROM relations`, &st.Relations},
		{`SELECT COUNT(*) FROM findings`, &st.Findings},
		{`SELECT COUNT(*) FROM evidence`, &st.Evidence},
		{`SELECT COUNT(*) FROM scans`, &st.Scans},
		{`SELECT COUNT(*) FROM observations WHERE evidence = '[]'`, &st.ObservationsWithoutEvidence},
	}
	for _, item := range queries {
		if err := s.db.QueryRowContext(ctx, item.q).Scan(item.dest); err != nil {
			return st, describeErr("Stats", err)
		}
	}
	return st, nil
}

// Diff compares two scans.
//
// Added and Removed are membership changes and are exact. Changed is derived from
// observations rather than from the entities table: an entity row holds the merged
// current view, which the later scan has already overwritten, so comparing it
// against itself would always report "no change". Observations are append-only
// and carry the scan that produced them, so they are the only place a
// scan-to-scan attribute difference can still be seen.
func (s *SQLite) Diff(ctx context.Context, fromScan, toScan string) (DiffResult, error) {
	res := DiffResult{FromScan: fromScan, ToScan: toScan}

	from, err := s.entitiesOfScan(ctx, fromScan)
	if err != nil {
		return res, err
	}
	to, err := s.entitiesOfScan(ctx, toScan)
	if err != nil {
		return res, err
	}

	for id, e := range to {
		if _, ok := from[id]; !ok {
			res.Added = append(res.Added, e)
			continue
		}
		changes, err := s.attributeChanges(ctx, id, e, fromScan, toScan)
		if err != nil {
			return res, err
		}
		res.Changed = append(res.Changed, changes...)
	}
	for id, e := range from {
		if _, ok := to[id]; !ok {
			// Absent from the later scan means "not observed again", not "gone".
			// Scans are partial by nature, so the field is named for what it
			// proves.
			res.Removed = append(res.Removed, e)
		}
	}
	sort.Slice(res.Added, func(i, j int) bool { return res.Added[i].Value < res.Added[j].Value })
	sort.Slice(res.Removed, func(i, j int) bool { return res.Removed[i].Value < res.Removed[j].Value })
	sort.Slice(res.Changed, func(i, j int) bool {
		if res.Changed[i].Entity.Value != res.Changed[j].Entity.Value {
			return res.Changed[i].Entity.Value < res.Changed[j].Entity.Value
		}
		return res.Changed[i].Field < res.Changed[j].Field
	})
	return res, nil
}

// attributeChanges compares the facts a scan asserted about one entity with the
// facts the other scan asserted, using observations rather than merged attributes.
func (s *SQLite) attributeChanges(ctx context.Context, id sdk.EntityID, e sdk.Entity, fromScan, toScan string) ([]EntityChange, error) {
	before, err := s.factsFor(ctx, id, fromScan)
	if err != nil {
		return nil, err
	}
	after, err := s.factsFor(ctx, id, toScan)
	if err != nil {
		return nil, err
	}

	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)

	var out []EntityChange
	for _, k := range ordered {
		b, okB := before[k]
		a, okA := after[k]
		switch {
		case okB && okA && b == a:
			continue
		case okB && okA:
			out = append(out, EntityChange{Entity: e, Field: k, Before: b, After: a, Severity: diffSeverity(k)})
		case okB:
			out = append(out, EntityChange{Entity: e, Field: k, Before: b, After: nil, Severity: diffSeverity(k)})
		default:
			out = append(out, EntityChange{Entity: e, Field: k, Before: nil, After: a, Severity: diffSeverity(k)})
		}
	}
	return out, nil
}

// factsFor reduces a scan's observations about one entity to a comparable map of
// predicate -> first asserted object. Within a scan the same predicate asserted
// with conflicting objects is itself a finding, so the first is kept and the
// conflict is surfaced by the scorer rather than here.
func (s *SQLite) factsFor(ctx context.Context, id sdk.EntityID, scanID string) (map[string]any, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.predicate, o.object FROM observations o
		 JOIN observation_scans os ON os.observation_id = o.id
		 WHERE o.subject = ? AND os.scan_id = ?
		 ORDER BY o.observed_at, o.id`, string(id), scanID)
	if err != nil {
		return nil, describeErr("Diff facts", err)
	}
	defer rows.Close()
	out := map[string]any{}
	for rows.Next() {
		var predicate, obj string
		if err := rows.Scan(&predicate, &obj); err != nil {
			return nil, describeErr("Diff facts scan", err)
		}
		if _, seen := out[predicate]; seen {
			continue
		}
		if obj == "" || obj == "null" {
			out[predicate] = nil
			continue
		}
		var v any
		if json.Unmarshal([]byte(obj), &v) == nil {
			out[predicate] = v
		} else {
			out[predicate] = obj
		}
	}
	return out, rows.Err()
}

// diffSeverity ranks a changed field. Infrastructure fields matter more than
// descriptive ones because their movement is what an attack surface changes.
func diffSeverity(field string) string {
	// Predicates arrive as "attr:registrar" for entity attributes.
	switch strings.TrimPrefix(field, "attr:") {
	case "resolves_to", "ip", "asn", "ns", "mx", "registrar", "tls_cert", "exposes":
		return sdk.SevMedium
	case "exists", "attr", "http_status":
		return sdk.SevLow
	default:
		return sdk.SevInfo
	}
}

func (s *SQLite) entitiesOfScan(ctx context.Context, scanID string) (map[sdk.EntityID]sdk.Entity, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+entityColsPrefixed+`
		FROM entities e
		WHERE EXISTS (SELECT 1 FROM entity_scans es WHERE es.entity_id = e.id AND es.scan_id = ?)`,
		scanID)
	if err != nil {
		return nil, describeErr("Diff entities", err)
	}
	defer rows.Close()
	out := map[sdk.EntityID]sdk.Entity{}
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, describeErr("Diff scan", err)
		}
		out[e.ID] = e
	}
	return out, rows.Err()
}

// Purge erases data by subject, case, or age.
//
// It deletes rows only. The audit record of the erasure itself is written
// separately and must not contain the subject: an erasure that leaves the subject
// in the audit log has not erased anything.
func (s *SQLite) Purge(ctx context.Context, f PurgeFilter) (PurgeReport, error) {
	rep := PurgeReport{DryRun: f.DryRun}

	var ids []string
	switch {
	case f.Subject != "":
		// A subject may be an email, a domain, or a handle. Match it as a
		// canonical value, as the domain part of an email, and as the local part
		// of an email, so "acme.example" and "jane@acme.example" both resolve to
		// the data an erasure request is about.
		rows, err := s.db.QueryContext(ctx,
			`SELECT id FROM entities
			 WHERE value = ?
			    OR (type = 'email' AND value LIKE ?)
			    OR (type = 'email' AND value LIKE ?)`,
			f.Subject, "%@"+f.Subject, strings.ReplaceAll(f.Subject, "@", "")+"@%")
		if err != nil {
			return rep, describeErr("Purge lookup", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()

		// Cascade along relations. Deleting a subject's own row while leaving the
		// rest of the graph pointing at it would leave dangling references to the
		// very data the erasure request asked to remove, so every entity reachable
		// from a matched seed goes too.
		ids = s.cascadeRelations(ctx, ids)
	case f.CaseID != "":
		rows, err := s.db.QueryContext(ctx,
			`SELECT DISTINCT entity_id FROM entity_scans es
			 JOIN scans sc ON sc.id = es.scan_id WHERE sc.case_id = ?`, f.CaseID)
		if err != nil {
			return rep, describeErr("Purge lookup case", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
	case !f.Before.IsZero():
		rows, err := s.db.QueryContext(ctx,
			`SELECT id FROM entities WHERE last_seen < ?`, ts(f.Before))
		if err != nil {
			return rep, describeErr("Purge lookup age", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
	default:
		rep.Notes = append(rep.Notes, "no filter supplied; nothing purged")
		return rep, nil
	}

	if len(ids) == 0 {
		rep.Notes = append(rep.Notes, "no matching entities")
		return rep, nil
	}

	if f.DryRun {
		for _, id := range ids {
			rep.EntitiesErased++
			var n int
			_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations WHERE subject = ?`, id).Scan(&n)
			rep.ObservationsErased += n
			_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM relations WHERE from_id = ? OR to_id = ?`, id, id).Scan(&n)
			rep.RelationsErased += n
		}
		rep.Notes = append(rep.Notes, "dry run: no rows deleted")
		return rep, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rep, describeErr("Purge begin", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	for _, id := range ids {
		res, err := tx.ExecContext(ctx, `DELETE FROM observations WHERE subject = ?`, id)
		if err != nil {
			return rep, describeErr("Purge observations", err)
		}
		n, _ := res.RowsAffected()
		rep.ObservationsErased += int(n)

		res, err = tx.ExecContext(ctx, `DELETE FROM relations WHERE from_id = ? OR to_id = ?`, id, id)
		if err != nil {
			return rep, describeErr("Purge relations", err)
		}
		n, _ = res.RowsAffected()
		rep.RelationsErased += int(n)

		for _, q := range []string{
			`DELETE FROM tags WHERE entity_id = ?`,
			`DELETE FROM entity_scans WHERE entity_id = ?`,
			`DELETE FROM findings WHERE entity_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return rep, describeErr("Purge "+q, err)
			}
		}
		res, err = tx.ExecContext(ctx, `DELETE FROM entities WHERE id = ?`, id)
		if err != nil {
			return rep, describeErr("Purge entities", err)
		}
		n, _ = res.RowsAffected()
		rep.EntitiesErased += int(n)
	}

	if err := tx.Commit(); err != nil {
		return rep, describeErr("Purge commit", err)
	}
	rep.Notes = append(rep.Notes, "evidence blobs retained; erase separately if required by policy")
	return rep, nil
}

// maxCascadeHops bounds the transitive closure so an erasure cannot walk an
// unbounded component. Beyond a few hops the remaining entities are shared
// infrastructure (a CDN, a nameserver) that is not the subject's personal data,
// and deleting it would destroy unrelated investigations.
const maxCascadeHops = 4

// cascadeRelations expands a seed set to every entity reachable within
// maxCascadeHops relation hops.
func (s *SQLite) cascadeRelations(ctx context.Context, seeds []string) []string {
	seen := make(map[string]bool, len(seeds))
	all := make([]string, 0, len(seeds))
	for _, id := range seeds {
		if !seen[id] {
			seen[id] = true
			all = append(all, id)
		}
	}
	frontier := append([]string(nil), seeds...)

	for hop := 0; hop < maxCascadeHops && len(frontier) > 0; hop++ {
		var next []string
		for _, id := range frontier {
			rows, err := s.db.QueryContext(ctx,
				`SELECT to_id FROM relations WHERE from_id = ?
				 UNION SELECT from_id FROM relations WHERE to_id = ?`, id, id)
			if err != nil {
				return all
			}
			for rows.Next() {
				var neighbour string
				if err := rows.Scan(&neighbour); err != nil {
					continue
				}
				if seen[neighbour] {
					continue
				}
				seen[neighbour] = true
				all = append(all, neighbour)
				next = append(next, neighbour)
			}
			rows.Close()
		}
		frontier = next
	}
	return all
}

// Close releases the database handle.
func (s *SQLite) Close() error { return s.db.Close() }

// Path returns the database file path.
func (s *SQLite) Path() string { return s.dsn }

// Open is the Driver-based constructor used by the CLI.
func Open(ctx context.Context, driver Driver, dsn string) (Store, error) {
	switch driver {
	case DriverSQLite, "":
		return OpenSQLite(dsn)
	default:
		return nil, fmt.Errorf("store: driver %q is not compiled into this binary", driver)
	}
}

// redactURL removes credentials from a DSN for display.
func redactURL(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}
