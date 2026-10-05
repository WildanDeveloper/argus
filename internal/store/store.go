// Package store is the persistence layer: SQLite by default, PostgreSQL for teams,
// with a graph projection for deep analysis.
//
// The schema follows §17.1. The two invariants that shape every decision here
// are idempotence (upserts keyed by entity, observation, and relation identity,
// so at-least-once delivery absorbs duplicates) and append-only observations
// (nothing is ever updated in place, only superseded).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// ErrNotFound is returned when an entity does not exist.
var ErrNotFound = errors.New("store: not found")

// Driver names a storage backend.
type Driver string

const (
	DriverSQLite   Driver = "sqlite"
	DriverPostgres Driver = "postgres"
	DriverMemory   Driver = "memory"
)

// Store is the persistence contract.
type Store interface {
	// SaveScan records a scan and its execution context, assigning an ID when
	// none was supplied. It takes a pointer so the generated ID reaches the caller.
	SaveScan(ctx context.Context, s *Scan) error
	// GetScan returns a scan by ID.
	GetScan(ctx context.Context, id string) (Scan, error)
	// FinishScan updates a scan's terminal state.
	FinishScan(ctx context.Context, id string, status ScanStatus, summary ScanSummary) error

	// UpsertBatch writes entities, observations, and relations atomically.
	// Replaying the same batch must be a no-op, which is what makes at-least-once
	// task delivery safe.
	UpsertBatch(ctx context.Context, scanID string, b Batch) error

	// GetEntity returns one entity with its merged attributes.
	GetEntity(ctx context.Context, id sdk.EntityID) (sdk.Entity, error)
	// GetEntityByValue finds an entity by type and canonical value.
	GetEntityByValue(ctx context.Context, t sdk.EntityType, value string) (sdk.Entity, error)
	// Observations returns the observation history for an entity, newest first.
	Observations(ctx context.Context, id sdk.EntityID, limit int) ([]sdk.Observation, error)
	// Relations returns edges touching an entity.
	Relations(ctx context.Context, id sdk.EntityID, limit int) ([]sdk.Relation, error)
	// Neighbors returns adjacent entities up to depth hops.
	Neighbors(ctx context.Context, id sdk.EntityID, depth int, limit int) ([]sdk.Entity, error)

	// ListEntities pages through entities with optional filters.
	ListEntities(ctx context.Context, q EntityQuery) ([]sdk.Entity, int, error)

	// PutEvidence stores an evidence record and returns its ID.
	PutEvidence(ctx context.Context, e Evidence) (sdk.EvidenceRef, error)
	// Evidence returns an evidence record by ID.
	Evidence(ctx context.Context, id string) (Evidence, error)

	// Diff compares two scans and reports added, removed, and changed entities.
	Diff(ctx context.Context, fromScan, toScan string) (DiffResult, error)

	// Stats reports store-level counters.
	Stats(ctx context.Context) (StoreStats, error)

	// Purge erases data by subject, case, or age, returning what it removed.
	// It never deletes the audit record of the deletion itself.
	Purge(ctx context.Context, f PurgeFilter) (PurgeReport, error)

	// Close releases resources.
	Close() error
}

// ScanStatus is the lifecycle state of a scan.
type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanPaused    ScanStatus = "paused"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

// Scan is the execution context for one investigation run.
type Scan struct {
	ID         string
	CaseID     string
	Workflow   string
	Target     sdk.Entity
	Status     ScanStatus
	Params     map[string]string
	Purpose    string
	Mode       sdk.Mode
	CreatedBy  string
	Modules    []string
	StartedAt  time.Time
	FinishedAt time.Time
	Summary    ScanSummary
}

// ScanSummary aggregates what a scan produced, used for --explain and reports.
type ScanSummary struct {
	Tasks         int
	ModulesRun    int
	Requests      int
	EntitiesFound int
	Observations  int
	Findings      int
	Denials       int
	Errors        int
	CostUSD       float64
	OutOfScope    int
	Unverified    int
}

// Batch is a unit of atomic write. The pipeline emits batches so that a storage
// stall slows collectors rather than growing memory (§4.6 backpressure).
type Batch struct {
	Entities     []sdk.Entity
	Observations []sdk.Observation
	Relations    []sdk.Relation
	Findings     []sdk.Finding
}

// IsEmpty reports whether the batch would write nothing.
func (b Batch) IsEmpty() bool {
	return len(b.Entities) == 0 && len(b.Observations) == 0 && len(b.Relations) == 0
}

// EntityQuery filters a listing.
type EntityQuery struct {
	Types         []sdk.EntityType
	CaseID        string
	ScanID        string
	Tags          []string
	MinConfidence float64
	Limit         int
	Offset        int
}

// Evidence is a stored artifact with chain-of-custody metadata.
type Evidence struct {
	ID         string
	CaseID     string
	ScanID     string
	SHA256     string
	Size       int64
	MediaType  string
	Source     string
	Method     string
	Collector  string
	CapturedAt time.Time
	PrevHash   string
	RecordHash string
	TSAToken   []byte
	Signature  []byte
	BlobPath   string
}

// StoreStats reports counters for `argus doctor` and the status endpoint.
type StoreStats struct {
	Entities                    int64
	Observations                int64
	Relations                   int64
	Findings                    int64
	Evidence                    int64
	Scans                       int64
	ObservationsWithoutEvidence int64
}

// PurgeFilter selects what to erase. The right-to-erasure workflow uses Subject;
// retention uses Before.
type PurgeFilter struct {
	Subject   string
	CaseID    string
	Before    time.Time
	DryRun    bool
	KeepAudit bool // always true in practice; retained for explicitness
}

// PurgeReport describes an erasure.
type PurgeReport struct {
	EntitiesErased     int
	ObservationsErased int
	RelationsErased    int
	EvidenceErased     int
	BlobsErased        int
	DryRun             bool
	Notes              []string
}

// DiffResult reports the change between two scans.
type DiffResult struct {
	FromScan       string
	ToScan         string
	Added          []sdk.Entity
	Removed        []sdk.Entity
	Changed        []EntityChange
	RelationsAdded int
}

// EntityChange is one changed entity with the attribute that moved.
type EntityChange struct {
	Entity   sdk.Entity
	Field    string
	Before   any
	After    any
	Severity string
}

// ULID-ish monotonic identifier. A full ULID implementation is 26 chars of
// Crockford base32 with a 48-bit timestamp; Argus needs sortable, collision-
// resistant identifiers for scans, evidence, and cases, so they are generated
// here rather than pulling a dependency for a dozen lines.
var idCounter struct {
	lastMS uint64
	seq    uint16
}

func newID(prefix string) string {
	now := uint64(time.Now().UTC().UnixMilli())
	// Guard against a clock that steps backwards, which would break sort order.
	if now <= idCounter.lastMS {
		now = idCounter.lastMS
		idCounter.seq++
	} else {
		idCounter.lastMS = now
		idCounter.seq = 0
	}
	ts := encodeCrockford(idCounter.lastMS, 10)
	seq := encodeCrockford(uint64(idCounter.seq), 4)
	random := encodeCrockford(uint64(time.Now().UnixNano())%1024*1024+now%1024*1024, 6)
	return prefix + ts + seq + random
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func encodeCrockford(v uint64, width int) string {
	buf := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		buf[i] = crockford[v&0x1f]
		v >>= 5
	}
	return string(buf)
}

// NewScanID returns a sortable scan identifier.
func NewScanID() string { return newID("01") }

// NewEvidenceID returns a sortable evidence identifier.
func NewEvidenceID() string { return newID("01J") }

// NewCaseID returns a sortable case identifier.
func NewCaseID() string { return newID("01K") }

func describeErr(op string, err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("store %s: %w", op, err)
	}
	return fmt.Errorf("store %s: %w", op, err)
}
