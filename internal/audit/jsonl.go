package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type jsonlFileSink struct {
	mu   sync.Mutex
	path string
	seq  uint64
	// head is cached so Head does not re-read the file on startup of every scan.
	head    Entry
	hasHead bool
}

// OpenJSONL opens (or creates) an append-only JSONL audit log on disk.
//
// JSONL is chosen over a database table deliberately: the log must remain
// readable and verifiable with nothing but a text editor, so that an operator
// who suspects tampering can check it without trusting Argus.
func OpenJSONL(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	s, err := openJSONLSink(path)
	if err != nil {
		return nil, err
	}
	return New(s, defaultActor())
}

func openJSONLSink(path string) (*jsonlFileSink, error) {
	s := &jsonlFileSink{path: path}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer f.Close()

	// Recover the sequence number and chain head by reading the tail.
	sc := newScanner(f)
	var last Entry
	count := uint64(0)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// A corrupt line must not silently truncate the chain. Stop here and
			// let Verify report the break rather than pretending the rest is fine.
			break
		}
		last = e
		count++
	}
	s.seq = count
	s.head, s.hasHead = last, count > 0
	return s, nil
}

func (s *jsonlFileSink) Append(_ context.Context, e Entry) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	e.Seq = s.seq
	b, err := json.Marshal(e)
	if err != nil {
		return 0, err
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return 0, err
	}
	// fsync: an audit record that survives in the page cache but not a power cut
	// is not evidence of anything.
	if err := f.Sync(); err != nil {
		return 0, err
	}
	s.head, s.hasHead = e, true
	return e.Seq, nil
}

func (s *jsonlFileSink) Range(_ context.Context, from, to uint64) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []Entry
	sc := newScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			break
		}
		if e.Seq < from {
			continue
		}
		if to > 0 && e.Seq > to {
			break
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func (s *jsonlFileSink) Head(context.Context) (Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head, s.hasHead, nil
}

// Truncate is not supported for the file sink. Compaction writes a new sealed
// file rather than rewriting history in place.
func (s *jsonlFileSink) Truncate(context.Context, uint64) error {
	return fmt.Errorf("audit: refusing to truncate an append-only JSONL log; use compaction to seal a prefix")
}

func defaultActor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}
