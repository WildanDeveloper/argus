// Package secrets reads provider API keys.
//
// Two rules govern everything here. A secret never appears in a config file, a
// log, a report, a process argument, or a plugin environment; and a module
// receives only the secrets its manifest declares. Both are enforced in code
// rather than documented as conventions, because a convention is not a control.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNotFound means the secret is not configured. It is deliberately not an empty
// string: a module that treats "missing" and "empty" alike will proceed with no
// credential and produce confusing provider errors much later.
var ErrNotFound = errors.New("secrets: not configured")

// ErrAccessDenied means the secret exists but the caller did not declare it.
var ErrAccessDenied = errors.New("secrets: access denied: secret was not declared in the module manifest")

// ErrBackendUnavailable means the backend could not be reached.
var ErrBackendUnavailable = errors.New("secrets: backend unavailable")

// Reader resolves secret names to values.
type Reader interface {
	Secret(ctx context.Context, name string) (string, error)
}

// EnvReader reads ARGUS_<SERVICE>_API_KEY variables.
//
// Env is the default because it is the backend every deployment already has and
// the one that leaves the fewest traces on disk. A file, keyring, or vault
// backend replaces it where a longer-lived credential is needed.
type EnvReader struct {
	// prefix is the environment variable prefix.
	prefix string
	// known restricts lookups to a declared set. Empty means any name is allowed,
	// which is correct only for the CLI-level `secrets list` path.
	known map[string]bool
	mu    sync.Mutex
	// lastUsed records access times so `secrets list` can flag unused keys.
	lastUsed map[string]time.Time
	now      func() time.Time
}

// NewEnvReader builds an environment-backed reader.
func NewEnvReader() *EnvReader {
	return &EnvReader{
		prefix:   "ARGUS_",
		lastUsed: map[string]time.Time{},
		now:      time.Now,
	}
}

// WithKnown restricts the reader to a declared set of secret names.
func (r *EnvReader) WithKnown(names []string) *EnvReader {
	r.known = make(map[string]bool, len(names))
	for _, n := range names {
		r.known[n] = true
	}
	return r
}

// EnvVarFor maps a secret name to its environment variable.
func EnvVarFor(name string) string {
	return "ARGUS_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name)) + "_API_KEY"
}

// Secret returns the value for a declared secret.
func (r *EnvReader) Secret(_ context.Context, name string) (string, error) {
	r.mu.Lock()
	if len(r.known) > 0 && !r.known[name] {
		r.mu.Unlock()
		return "", fmt.Errorf("%w: %s", ErrAccessDenied, name)
	}
	r.mu.Unlock()

	key := EnvVarFor(name)
	v := os.Getenv(key)
	if v == "" {
		// Also accept the bare uppercase name, which some deployments find easier.
		v = os.Getenv(strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name)))
	}
	if v == "" {
		return "", fmt.Errorf("%w: set %s", ErrNotFound, key)
	}

	r.mu.Lock()
	if r.lastUsed == nil {
		r.lastUsed = map[string]time.Time{}
	}
	r.lastUsed[name] = r.now()
	r.mu.Unlock()

	return v, nil
}

// ListNames returns the configured secret names, derived from the environment.
// Values are never returned.
func (r *EnvReader) ListNames() []string {
	var out []string
	for _, env := range os.Environ() {
		k, v, ok := strings.Cut(env, "=")
		if !ok || v == "" {
			continue
		}
		if !strings.HasPrefix(k, r.prefix) || !strings.HasSuffix(k, "_API_KEY") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(k, r.prefix), "_API_KEY")
		out = append(out, strings.ToLower(name))
	}
	sort.Strings(out)
	return out
}

// LastUsed reports when a secret was last read.
func (r *EnvReader) LastUsed(name string) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.lastUsed[name]
	return t, ok
}

// Redact returns a value safe for logs and errors.
//
// A fingerprint is kept rather than nothing at all: an operator needs to tell
// "key A" from "key B" when a rotation appears not to have taken effect, without
// ever seeing either value.
func Redact(v string) string {
	if v == "" {
		return "(empty)"
	}
	if len(v) <= 4 {
		return "****"
	}
	return v[:2] + strings.Repeat("*", 6) + v[len(v)-2:] + " (len=" + fmt.Sprint(len(v)) + ")"
}

// Fingerprint returns a short, non-reversible identifier for a secret, so two
// keys can be told apart without exposing either.
func Fingerprint(v string) string {
	if v == "" {
		return ""
	}
	// A short hash is enough to distinguish keys and is not worth brute-forcing
	// given the entropy of a real API key.
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var h uint64 = 1469598103934665603
	for i := 0; i < len(v); i++ {
		h ^= uint64(v[i])
		h *= 1099511628211
	}
	out := make([]byte, 6)
	for i := range out {
		out[i] = alphabet[h&0x3f]
		h >>= 6
	}
	return string(out)
}

// MemoryReader serves secrets from an in-process map. It exists for tests and for
// air-gapped analysis where keys were injected by the operator at startup.
type MemoryReader struct {
	mu     sync.RWMutex
	values map[string]string
	known  map[string]bool
}

// NewMemoryReader builds a map-backed reader.
func NewMemoryReader(values map[string]string) *MemoryReader {
	return &MemoryReader{values: values, known: map[string]bool{}}
}

// WithKnown restricts access to declared names.
func (r *MemoryReader) WithKnown(names []string) *MemoryReader {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.known = make(map[string]bool, len(names))
	for _, n := range names {
		r.known[n] = true
	}
	return r
}

// Secret returns a value.
func (r *MemoryReader) Secret(_ context.Context, name string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.known) > 0 && !r.known[name] {
		return "", fmt.Errorf("%w: %s", ErrAccessDenied, name)
	}
	v, ok := r.values[name]
	if !ok || v == "" {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return v, nil
}

// Names returns the configured secret names.
func (r *MemoryReader) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.values))
	for k := range r.values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
