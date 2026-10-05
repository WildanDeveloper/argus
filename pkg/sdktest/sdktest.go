// Package sdktest is the test harness for module authors.
//
// It supplies the fake Deps a module needs — in-memory cache, recording emitter,
// fixed clock, no network — plus the assertions from the module checklist, so a
// module can be tested without standing up the whole engine.
package sdktest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// FakeClock is a manually advanced clock.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock fixed at t.
func NewClock(t time.Time) *FakeClock { return &FakeClock{now: t.UTC()} }

// Now returns the current fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// Set moves the clock to an absolute time.
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t.UTC()
	c.mu.Unlock()
}

// Recorder captures an HTTPDoer.
type Recorder struct {
	mu        sync.Mutex
	calls     []RecordedCall
	responses []cannedResponse
}

// RecordedCall is one captured request.
type RecordedCall struct {
	Method string
	URL    string
	Host   string
	Header http.Header
}

// Calls returns the recorded calls in order.
func (r *Recorder) Calls() []RecordedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RecordedCall(nil), r.calls...)
}

// Hosts returns the distinct hosts contacted.
func (r *Recorder) Hosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, c := range r.calls {
		if !seen[c.Host] {
			seen[c.Host] = true
			out = append(out, c.Host)
		}
	}
	sort.Strings(out)
	return out
}

// Record appends a call.
func (r *Recorder) Record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, RecordedCall{
		Method: req.Method, URL: req.URL.String(), Host: req.URL.Hostname(), Header: req.Header.Clone(),
	})
}

var _ sdk.HTTPDoer = (*Recorder)(nil)

// Do records the request and returns a scripted response if one matches. With no
// script, it fails loudly: a unit test must never silently depend on the network,
// and a nil response would turn into a confusing nil dereference later.
func (r *Recorder) Do(req *http.Request) (*http.Response, error) {
	r.Record(req)
	c := r.canned(req.URL.String())
	if c == nil {
		return nil, fmt.Errorf("sdktest: no scripted response for %s; call Respond before running the module", req.URL.Redacted())
	}
	ct := c.contentType
	if ct == "" {
		ct = "application/json"
	}
	body := c.body
	return &http.Response{
		StatusCode:    c.status,
		Status:        http.StatusText(c.status),
		Header:        http.Header{"Content-Type": []string{ct}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}

// Respond scripts a canned response for any URL containing match. Substring
// matching keeps tests readable; a real network is never involved.
func (r *Recorder) Respond(match string, status int, body, contentType string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.responses = append(r.responses, cannedResponse{match: match, status: status, body: body, contentType: contentType})
}

// canned returns the first scripted response whose match is a substring of the
// request URL.
func (r *Recorder) canned(rawURL string) *cannedResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.responses {
		if strings.Contains(rawURL, r.responses[i].match) {
			return &r.responses[i]
		}
	}
	return nil
}

type cannedResponse struct {
	match       string
	status      int
	body        string
	contentType string
}

// FakeDNS is a scripted sdk.DNSResolver.
type FakeDNS struct {
	mu      sync.Mutex
	answers map[string][]sdk.DNSRecord // "name/TYPE"
	errs    map[string]error
	calls   []string
}

var _ sdk.DNSResolver = (*FakeDNS)(nil)

// NewFakeDNS returns an empty scripted resolver.
func NewFakeDNS() *FakeDNS {
	return &FakeDNS{answers: map[string][]sdk.DNSRecord{}, errs: map[string]error{}}
}

// Set scripts answers for name/rrType.
func (f *FakeDNS) Set(name, rrType string, recs ...sdk.DNSRecord) *FakeDNS {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[strings.ToLower(strings.TrimSuffix(name, "."))+"/"+strings.ToUpper(rrType)] = recs
	return f
}

// SetErr scripts a failure for name/rrType.
func (f *FakeDNS) SetErr(name, rrType string, err error) *FakeDNS {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[strings.ToLower(strings.TrimSuffix(name, "."))+"/"+strings.ToUpper(rrType)] = err
	return f
}

// Lookup returns the scripted answer.
func (f *FakeDNS) Lookup(_ context.Context, name, rrType string) ([]sdk.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.ToLower(strings.TrimSuffix(name, ".")) + "/" + strings.ToUpper(rrType)
	f.calls = append(f.calls, key)
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	return f.answers[key], nil
}

// Calls returns the lookups performed, in order.
func (f *FakeDNS) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// FakeCache is an in-memory sdk.Cache.
type FakeCache struct {
	mu      sync.Mutex
	entries map[string]any
}

var _ sdk.Cache = (*FakeCache)(nil)

// NewFakeCache returns an empty cache.
func NewFakeCache() *FakeCache { return &FakeCache{entries: map[string]any{}} }

// Get returns a cached value.
func (c *FakeCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[key]
	return v, ok
}

// Put stores a value.
func (c *FakeCache) Put(key string, val any, _ time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = val
}

// Delete removes a value.
func (c *FakeCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Len reports the number of entries.
func (c *FakeCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// FakeSecrets returns declared secrets and records every access.
type FakeSecrets struct {
	mu       sync.Mutex
	values   map[string]string
	declared []string
	accessed []string
}

var _ sdk.SecretReader = (*FakeSecrets)(nil)

// NewFakeSecrets builds a secret store restricted to declared names.
func NewFakeSecrets(declared []string, values map[string]string) *FakeSecrets {
	return &FakeSecrets{values: values, declared: declared}
}

// Secret returns a declared secret.
func (s *FakeSecrets) Secret(_ context.Context, name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed := false
	for _, d := range s.declared {
		if d == name {
			allowed = true
			break
		}
	}
	if !allowed {
		// A module asking for an undeclared secret is the failure mode the
		// capability model exists to prevent, so the harness surfaces it loudly.
		return "", fmt.Errorf("sdktest: secret %q was not declared in the manifest", name)
	}
	s.accessed = append(s.accessed, name)
	v, ok := s.values[name]
	if !ok {
		return "", fmt.Errorf("sdktest: secret %q not configured", name)
	}
	return v, nil
}

// Accessed returns the secret names requested.
func (s *FakeSecrets) Accessed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.accessed...)
}

// Blobs records evidence writes.
type Blobs struct {
	mu      sync.Mutex
	written [][]byte
	refs    []sdk.EvidenceRef
	seq     int
}

var _ sdk.BlobWriter = (*Blobs)(nil)

// NewBlobs returns a recording blob writer.
func NewBlobs() *Blobs { return &Blobs{} }

// Put records an artifact.
func (b *Blobs) Put(_ context.Context, _ sdk.EvidenceMeta, raw []byte) (sdk.EvidenceRef, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	cp := append([]byte(nil), raw...)
	b.written = append(b.written, cp)
	ref := sdk.EvidenceRef{ID: fmt.Sprintf("blob-%03d", b.seq)}
	b.refs = append(b.refs, ref)
	return ref, nil
}

// Count reports how many artifacts were written.
func (b *Blobs) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.written)
}

// Bytes returns the concatenated artifacts.
func (b *Blobs) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []byte
	for _, w := range b.written {
		out = append(out, w...)
	}
	return out
}

// Capture is a recording sdk.Emitter.
type Capture struct {
	mu       sync.Mutex
	Findings []sdk.Finding
	Warnings []string
	// Steps records (done, total) progress reports.
	Steps [][2]int
}

// Emit records a finding.
func (c *Capture) Emit(f sdk.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Findings = append(c.Findings, f)
	return nil
}

// PutEvidence is a no-op: the harness Blobs is used directly by modules that
// declare one.
func (c *Capture) PutEvidence(_ context.Context, _ sdk.EvidenceMeta, raw []byte) (sdk.EvidenceRef, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sdk.EvidenceRef{ID: "captured"}, nil
}

// Progress records a progress report.
func (c *Capture) Progress(done, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Steps = append(c.Steps, [2]int{done, total})
}

// Warn records a warning.
func (c *Capture) Warn(msg string, _ ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Warnings = append(c.Warnings, msg)
}

var _ sdk.Emitter = (*Capture)(nil)

// Harness wraps a module with fake dependencies and assertions.
type Harness struct {
	T       *testing.T
	Module  sdk.Module
	Clock   *FakeClock
	DNS     *FakeDNS
	HTTP    *Recorder
	Cache   *FakeCache
	Secrets *FakeSecrets
	Blobs   *Blobs
	Out     *Capture

	deps sdk.Deps
}

// DefaultClock is the fixed time used when a test does not choose one. A fixed
// clock is what makes a golden file stable.
var DefaultClock = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// NewHarness builds a harness for a module.
func NewHarness(t *testing.T, m sdk.Module, opts ...func(*Harness)) *Harness {
	t.Helper()
	h := &Harness{
		T:      t,
		Module: m,
		Clock:  NewClock(DefaultClock),
		DNS:    NewFakeDNS(),
		HTTP:   &Recorder{},
		Cache:  NewFakeCache(),
		Blobs:  NewBlobs(),
		Out:    &Capture{},
	}
	man := m.Manifest()
	h.Secrets = NewFakeSecrets(man.SecretNames(), map[string]string{})
	h.deps = sdk.Deps{
		HTTP:    h.HTTP,
		DNS:     h.DNS,
		Cache:   h.Cache,
		Blobs:   h.Blobs,
		Secrets: h.Secrets,
		Log:     slog.New(slog.NewTextHandler(nopWriter{}, &slog.HandlerOptions{Level: slog.LevelError})),
		Now:     h.Clock.Now,
		Config:  map[string]any{},
	}
	for _, o := range opts {
		o(h)
	}
	if err := m.Init(context.Background(), h.deps); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return h
}

// WithConfig injects module configuration.
func WithConfig(cfg map[string]any) func(*Harness) {
	return func(h *Harness) { h.deps.Config = cfg }
}

// WithSecrets supplies secret values.
func WithSecrets(values map[string]string) func(*Harness) {
	return func(h *Harness) { h.Secrets = NewFakeSecrets(h.Module.Manifest().SecretNames(), values) }
}

// WithClock overrides the fake clock.
func WithClock(t time.Time) func(*Harness) {
	return func(h *Harness) { h.Clock.Set(t) }
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// Run executes the module against targets and returns the captured findings.
func (h *Harness) Run(targets ...sdk.Entity) []sdk.Finding {
	h.T.Helper()
	for _, t := range targets {
		task := sdk.Task{
			ScanID:   "test-scan",
			CaseID:   "test-case",
			Target:   t,
			Params:   map[string]string{},
			Deadline: h.Clock.Now().Add(time.Minute),
		}
		if err := h.Module.Run(context.Background(), task, h.Out); err != nil {
			h.T.Fatalf("Run(%s): %v", t.Value, err)
		}
	}
	return h.Out.Findings
}

// RunExpectingError executes the module and requires an error.
func (h *Harness) RunExpectingError(target sdk.Entity) error {
	h.T.Helper()
	task := sdk.Task{Target: target, Params: map[string]string{}, Deadline: h.Clock.Now().Add(time.Minute)}
	return h.Module.Run(context.Background(), task, h.Out)
}

// AssertEntities requires findings producing entities of type with the given
// canonical values.
func (h *Harness) AssertEntities(typ sdk.EntityType, values ...string) {
	h.T.Helper()
	got := h.EntityValues(typ)
	want := map[string]bool{}
	for _, v := range values {
		want[v] = true
	}
	for _, v := range values {
		if !got[v] {
			h.T.Errorf("missing %s %q; got %v", typ, v, sortedKeys(got))
		}
	}
}

// RefuteEntities requires no finding produced the given values.
func (h *Harness) RefuteEntities(typ sdk.EntityType, values ...string) {
	h.T.Helper()
	got := h.EntityValues(typ)
	for _, v := range values {
		if got[v] {
			h.T.Errorf("unexpected %s %q", typ, v)
		}
	}
}

// EntityValues returns the canonical values of produced entities of a type.
func (h *Harness) EntityValues(typ sdk.EntityType) map[string]bool {
	out := map[string]bool{}
	for _, f := range h.Out.Findings {
		if f.Entity.Type == typ {
			out[f.Entity.Value] = true
		}
	}
	return out
}

// CountEntities counts produced entities of a type.
func (h *Harness) CountEntities(typ sdk.EntityType) int {
	n := 0
	for _, f := range h.Out.Findings {
		if f.Entity.Type == typ {
			n++
		}
	}
	return n
}

// AssertRelations requires at least one relation of the given type between the
// given entity values.
func (h *Harness) AssertRelations(typ sdk.RelationType, pairs ...[2]string) {
	h.T.Helper()
	byID := map[sdk.EntityID]sdk.Entity{}
	for _, f := range h.Out.Findings {
		byID[f.Entity.ID] = f.Entity
	}
	seen := map[sdk.RelationType]map[[2]string]bool{}
	for _, f := range h.Out.Findings {
		for _, r := range f.Relations {
			if seen[r.Type] == nil {
				seen[r.Type] = map[[2]string]bool{}
			}
			seen[r.Type][[2]string{valueOf(byID, r.From), valueOf(byID, r.To)}] = true
		}
	}
	for _, pair := range pairs {
		if !seen[typ][pair] {
			h.T.Errorf("missing relation %s %s -> %s", typ, pair[0], pair[1])
		}
	}
}

func valueOf(byID map[sdk.EntityID]sdk.Entity, id sdk.EntityID) string {
	if e, ok := byID[id]; ok {
		return e.Value
	}
	return string(id)
}

// AssertNoEgressTo verifies the module's manifest allow-list covers every host it
// actually contacted. This is the assertion that catches a collector quietly
// reaching a host nobody declared.
func (h *Harness) AssertNoEgressTo(forbidden ...string) {
	h.T.Helper()
	bad := map[string]bool{}
	for _, f := range forbidden {
		bad[strings.ToLower(f)] = true
	}
	man := h.Module.Manifest()
	for _, host := range h.HTTP.Hosts() {
		if bad[host] {
			h.T.Errorf("module %s contacted %s, which the test forbids", man.Name, host)
		}
		if !man.AllowsHost(host) {
			h.T.Errorf("module %s contacted %s, which its manifest EgressHosts does not declare", man.Name, host)
		}
	}
}

// AssertManifestIsValid runs the SDK's manifest validation.
func (h *Harness) AssertManifestIsValid() {
	h.T.Helper()
	if problems := sdk.ValidateManifest(h.Module.Manifest()); len(problems) > 0 {
		h.T.Errorf("manifest problems: %v", problems)
	}
}

// AssertNoConfidenceSet requires the module never set Entity.Confidence, which
// belongs to the scorer alone.
func (h *Harness) AssertNoConfidenceSet() {
	h.T.Helper()
	for i, f := range h.Out.Findings {
		if f.Entity.Confidence != 0 {
			h.T.Errorf("finding %d set Entity.Confidence to %v; the scorer owns confidence", i, f.Entity.Confidence)
		}
	}
}

// AssertObservationsGraded requires every finding to carry an observation with
// Admiralty grades in range.
func (h *Harness) AssertObservationsGraded() {
	h.T.Helper()
	for i, f := range h.Out.Findings {
		o := f.Observation
		if o.Source.Module == "" {
			h.T.Errorf("finding %d has no observation source", i)
		}
		if o.Reliability < 'A' || o.Reliability > 'F' {
			h.T.Errorf("finding %d reliability %q out of range A-F", i, string(o.Reliability))
		}
		if o.Credibility < '1' || o.Credibility > '6' {
			h.T.Errorf("finding %d credibility %q out of range 1-6", i, string(o.Credibility))
		}
	}
}

// AssertGolden compares the emitted findings against a JSON golden file,
// creating it with -update.
func (h *Harness) AssertGolden(path string) {
	h.T.Helper()
	got, err := json.MarshalIndent(h.normalised(), "", "  ")
	if err != nil {
		h.T.Fatalf("marshal golden: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			h.T.Fatal(err)
		}
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			h.T.Fatalf("write golden: %v", err)
		}
		h.T.Logf("wrote golden file %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		h.T.Fatal(err)
	}
	if !equalJSON(want, got) {
		h.T.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

// normalised projects the capture to a stable shape: timestamps come from the
// fake clock, so a golden file stays reproducible.
func (h *Harness) normalised() any {
	type entity struct{ Type, Value string }
	type rel struct {
		Type, From, To string
		Heuristic      bool
	}
	type finding struct {
		Entity     entity
		Kind       string
		Severity   string
		Predicate  string
		Object     string
		Source     string
		Rel, Cred  string
		Relations  []rel
		Attributes map[string]any
	}
	var out []finding

	// Resolve entity IDs to values so relations are readable in the golden file.
	values := map[sdk.EntityID]string{}
	for _, f := range h.Out.Findings {
		values[f.Entity.ID] = f.Entity.Value
	}

	for _, f := range h.Out.Findings {
		fr := finding{
			Entity: entity{Type: string(f.Entity.Type), Value: f.Entity.Value},
			Kind:   f.Kind, Severity: f.Severity,
			Predicate: f.Observation.Predicate,
			Object:    fmt.Sprint(f.Observation.Object),
			Source:    f.Observation.Source.String(),
			Rel:       string(f.Observation.Reliability),
			Cred:      string(f.Observation.Credibility),
		}
		for _, r := range f.Relations {
			fr.Relations = append(fr.Relations, rel{
				Type: string(r.Type), From: values[r.From], To: values[r.To], Heuristic: r.Heuristic,
			})
		}
		out = append(out, fr)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Entity.Type != b.Entity.Type {
			return a.Entity.Type < b.Entity.Type
		}
		return a.Entity.Value < b.Entity.Value
	})
	return out
}

func equalJSON(a, b []byte) bool {
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseURL is a small helper for tests that build fixture URLs.
func ParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return u
}
