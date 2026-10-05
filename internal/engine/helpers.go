package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

const osPathSeparator = filepath.Separator

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mkdirAll(dir string) error { return os.MkdirAll(dir, 0o700) }

// writeFileAtomic writes via a temporary file and a rename, so a crash mid-write
// cannot leave a truncated artifact under a content-addressed path. A truncated
// file at a digest-derived path is the one corruption the evidence model cannot
// detect later, because the digest is computed from what was received.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("engine: evidence dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("engine: evidence temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("engine: evidence write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("engine: evidence sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("engine: evidence close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("engine: evidence chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("engine: evidence rename: %w", err)
	}
	return nil
}

// chainRecordHash binds an evidence record to its content and provenance.
func chainRecordHash(scanID, sha string, meta any) string {
	return sha256Hex([]byte(scanID + "|" + sha + "|" + fmt.Sprint(meta)))
}

func itoa(i int) string { return strconv.Itoa(i) }

var _ = time.Now

// scheduler owns the per-module task queues and tracks outstanding work.
//
// The outstanding count is what makes termination decidable: a scan ends when no
// task is queued or running, not when the root tasks finish, because pivots are
// discovered while their parent is still in flight.
type scheduler struct {
	mu          sync.Mutex
	queues      map[string]chan sdk.Task
	outstanding int
	closed      bool
	zero        chan struct{}
	once        sync.Once
}

func newScheduler() *scheduler {
	return &scheduler{queues: map[string]chan sdk.Task{}, zero: make(chan struct{})}
}

func (s *scheduler) queueFor(name string, size int) chan sdk.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.queues[name]
	if !ok {
		if size < 1 {
			size = 1
		}
		q = make(chan sdk.Task, size)
		s.queues[name] = q
	}
	return q
}

// enqueue offers a task to a module's queue. It reports false when the queue is
// full, which is the signal to drop a pivot rather than stall.
func (s *scheduler) enqueue(name string, t sdk.Task, log *slog.Logger) bool {
	s.mu.Lock()
	q, ok := s.queues[name]
	if !ok {
		s.mu.Unlock()
		return false
	}
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.outstanding++
	s.mu.Unlock()

	select {
	case q <- t:
		return true
	default:
		s.done()
		if log != nil {
			log.Debug("dropped task: queue full", "module", name)
		}
		return false
	}
}

// done records one task's completion and closes every queue when the last one
// finishes.
func (s *scheduler) done() {
	s.mu.Lock()
	if s.outstanding > 0 {
		s.outstanding--
	}
	if s.outstanding > 0 || s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for _, q := range s.queues {
		close(q)
	}
	s.mu.Unlock()
	s.once.Do(func() { close(s.zero) })
}

// exhausted returns a channel closed once no work remains.
func (s *scheduler) exhausted() <-chan struct{} { return s.zero }

// remaining reports how many tasks are queued or running.
func (s *scheduler) remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outstanding
}

// consumesType reports whether a module declares it can act on an entity type.
func consumesType(man sdk.Manifest, t sdk.EntityType) bool {
	for _, c := range man.Consumes {
		if c == t {
			return true
		}
	}
	return false
}
