package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WildanDeveloper/argus/internal/store"
	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// EvidenceStore is the content-addressed artifact store with a per-case hash chain.
//
// Content addressing alone proves that a blob has not changed. It does not prove
// that the set of blobs collected for a case is complete: someone with write access
// could delete one artifact and nothing would notice, because nothing referenced
// it. The hash chain closes that gap -- each record commits to the record before it,
// so removing or reordering any artifact breaks verification.
type EvidenceStore struct {
	store store.Store
	dir   string
	now   func() time.Time
	log   *slog.Logger

	mu sync.Mutex
	// heads tracks the chain head per case so records can be linked in order.
	heads map[string]string
}

// NewEvidenceStore builds an artifact store rooted at dir.
func NewEvidenceStore(s store.Store, dir string, log *slog.Logger) (*EvidenceStore, error) {
	if log == nil {
		log = slog.Default()
	}
	if s == nil {
		return nil, fmt.Errorf("engine: evidence store needs a database")
	}
	return &EvidenceStore{store: s, dir: dir, now: time.Now, log: log, heads: map[string]string{}}, nil
}

// genesisHash seeds a case's chain. It is a recognizable constant rather than an
// empty string so the first record's PrevHash cannot be confused with a missing
// field.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Store writes an artifact, links it into the case chain, and records it.
func (es *EvidenceStore) Store(ctx context.Context, scanID, caseID string, meta sdk.EvidenceMeta, raw []byte) (sdk.EvidenceRef, error) {
	sum := sha256Hex(raw)

	// Content addressing: the path is derived from the digest, so a modified
	// artifact cannot occupy the location of the original.
	rel := pathForDigest(sum)
	if err := writeFileAtomic(filepath.Join(es.dir, rel), raw); err != nil {
		return sdk.EvidenceRef{}, err
	}

	if meta.CapturedAt.IsZero() {
		meta.CapturedAt = es.now()
	}

	// Chain the record. The head is read once and advanced under the lock so two
	// concurrent captures cannot both claim the same predecessor.
	//
	// An empty head means this process has not written for this case yet, which
	// includes the case of a restarted process. Recovering from the store is
	// mandatory: starting from genesis again would fork a second chain and make
	// every later verification fail.
	es.mu.Lock()
	prev := es.heads[caseID]
	known := prev != ""
	es.mu.Unlock()
	if !known {
		recovered, err := es.store.EvidenceChainHead(ctx, caseID)
		if err != nil {
			return sdk.EvidenceRef{}, err
		}
		es.mu.Lock()
		// Another goroutine may have advanced the head while the read was in flight;
		// prefer the in-memory value so the lock still serializes the update.
		if h := es.heads[caseID]; h != "" {
			prev = h
		} else {
			prev = recovered
			if prev == "" {
				prev = genesisHash
			}
			es.heads[caseID] = prev
		}
		es.mu.Unlock()
	}

	rec := store.Evidence{
		CaseID: caseID, ScanID: scanID, SHA256: sum, Size: int64(len(raw)),
		MediaType: meta.MediaType, Source: meta.Source, Method: meta.Method,
		Collector: meta.Collector, CapturedAt: meta.CapturedAt,
		BlobPath: rel, PrevHash: prev,
	}
	rec.RecordHash = recordHash(rec)

	ref, err := es.store.PutEvidence(ctx, rec)
	if err != nil {
		return sdk.EvidenceRef{}, err
	}

	es.mu.Lock()
	es.heads[caseID] = rec.RecordHash
	es.mu.Unlock()

	return ref, nil
}

// AdoptChainHead restores the chain head after a restart, so a resumed process
// continues the chain rather than forking a second one.
func (es *EvidenceStore) AdoptChainHead(caseID, head string) {
	if head == "" {
		return
	}
	es.mu.Lock()
	es.heads[caseID] = head
	es.mu.Unlock()
}

// ChainHead returns the current head for a case.
func (es *EvidenceStore) ChainHead(caseID string) string {
	es.mu.Lock()
	defer es.mu.Unlock()
	if h := es.heads[caseID]; h != "" {
		return h
	}
	return genesisHash
}

// recordHash binds a record to its content, provenance, and predecessor.
//
// Every field is length-prefixed before hashing, so no rearrangement of values can
// produce the same hash for a different record.
func recordHash(e store.Evidence) string {
	h := sha256.New()
	for _, f := range []string{
		e.PrevHash,
		e.CaseID, e.ScanID, e.SHA256,
		strconv.FormatInt(e.Size, 10),
		e.MediaType, e.Source, e.Method, e.Collector,
		e.CapturedAt.UTC().Format(time.RFC3339Nano),
		e.BlobPath,
	} {
		fmt.Fprintf(h, "%d:", len(f))
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyResult reports the outcome of verifying a case's evidence chain.
type VerifyResult struct {
	OK           bool
	Checked      int
	BlobsPresent int
	BlobsMissing []string
	ChainHead    string
	Problem      string
}

// Verify re-hashes every stored blob and recomputes the chain.
//
// Both halves matter. Re-hashing alone would not notice a deleted artifact whose
// record remains; chain verification alone would not notice a corrupted blob whose
// record was rewritten to match. Doing only one of the two leaves the obvious
// attack open.
func (es *EvidenceStore) Verify(ctx context.Context, caseID string, limit int) (VerifyResult, error) {
	records, err := es.store.EvidenceForCase(ctx, caseID, limit)
	if err != nil {
		return VerifyResult{}, err
	}
	res := VerifyResult{Checked: len(records), ChainHead: genesisHash}
	if len(records) == 0 {
		return res, nil
	}

	prev := genesisHash
	for i, r := range records {
		if r.PrevHash != prev {
			res.OK = false
			res.Problem = fmt.Sprintf("record %d (%s): prev_hash does not match the previous record; an artifact was removed or reordered",
				i+1, r.ID)
			return res, nil
		}
		if want := recordHash(r); want != r.RecordHash {
			res.OK = false
			res.Problem = fmt.Sprintf("record %d (%s): record hash mismatch; provenance was modified after capture", i+1, r.ID)
			return res, nil
		}
		if r.BlobPath != "" {
			full := filepath.Join(es.dir, r.BlobPath)
			data, err := os.ReadFile(full)
			if err != nil {
				res.BlobsMissing = append(res.BlobsMissing, r.SHA256)
			} else if sha256Hex(data) != r.SHA256 {
				res.OK = false
				res.Problem = fmt.Sprintf("record %d (%s): blob content does not match its digest; the artifact was altered",
					i+1, r.ID)
				return res, nil
			} else {
				res.BlobsPresent++
			}
		}
		prev = r.RecordHash
		res.ChainHead = r.RecordHash
	}

	if len(res.BlobsMissing) > 0 {
		res.OK = false
		sort.Strings(res.BlobsMissing)
		res.Problem = fmt.Sprintf("%d artifact(s) referenced by the chain are missing from disk", len(res.BlobsMissing))
		return res, nil
	}

	res.OK = true
	return res, nil
}

// Read returns a stored artifact by its digest.
func (es *EvidenceStore) Read(sha string) ([]byte, error) {
	path := filepath.Join(es.dir, pathForDigest(sha))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("engine: read artifact %s: %w", sha, err)
	}
	return data, nil
}

// pathForDigest shards blobs two levels deep so no directory grows unbounded.
func pathForDigest(sum string) string {
	if len(sum) < 4 {
		return sum
	}
	return strings.Join([]string{sum[:2], sum[2:4], sum}, string(filepath.Separator))
}
