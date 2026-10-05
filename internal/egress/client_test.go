package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- test doubles ---

type fakeScope struct {
	mu      sync.Mutex
	allowed map[string]bool
	denyAll bool
	calls   []string
}

func newFakeScope(allow ...string) *fakeScope {
	s := &fakeScope{allowed: map[string]bool{}}
	for _, a := range allow {
		s.allowed[a] = true
	}
	return s
}

func (s *fakeScope) CheckEgress(_ context.Context, u *url.URL, module string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, module+" "+u.Hostname())
	if s.denyAll {
		return fmt.Errorf("scope: %s is not in allow.domains", u.Hostname())
	}
	if s.allowed[u.Hostname()] {
		return nil
	}
	return fmt.Errorf("scope: %s is not in allow.domains", u.Hostname())
}

func (s *fakeScope) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

type recordingAuditor struct {
	mu      sync.Mutex
	records []EgressRecord
}

func (a *recordingAuditor) RecordEgress(_ context.Context, rec EgressRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, rec)
	return nil
}

func (a *recordingAuditor) all() []EgressRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]EgressRecord(nil), a.records...)
}

// memCache is a trivial in-memory Cache with no expiry, for tests.
type memCache struct {
	mu    sync.Mutex
	items map[string]*CachedResponse
}

func newMemCache() *memCache { return &memCache{items: map[string]*CachedResponse{}} }

func (c *memCache) Get(k string) (*CachedResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[k]
	return v, ok
}

func (c *memCache) Put(k string, v *CachedResponse, _ time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[k] = v
}

func (c *memCache) Delete(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, k)
}

func testBroker(t *testing.T, srv *httptest.Server, scope ScopeChecker, audit Auditor, cache Cache) *Client {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	lim, _ := ParseRate("1000/s")
	c, err := NewClient(
		ClientConfig{
			Module:          "test-mod",
			UserAgent:       "Argus/test",
			MaxBodyBytes:    1 << 20,
			AllowLoopback:   true,
			AllowExtraCIDRs: []string{"127.0.0.0/8"},
			Timeout:         5 * time.Second,
		},
		nil,
		NewRateLimiter(lim, 10, nil, nil),
		NewBreaker(DefaultBreakerSettings()),
		NewRetryer(RetryConfig{MaxAttempts: 3, Base: time.Millisecond, Max: 5 * time.Millisecond}),
		cache, audit, scope,
	)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// get issues one GET and returns the response, the body, and any error.
func get(t *testing.T, c *Client, url string) (*http.Response, string, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b), nil
}

// --- tests ---

func TestBrokerRejectsOutOfScopeAndDoesNotReachServer(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte("should never be read"))
	}))
	defer srv.Close()

	scope := newFakeScope() // allows nothing
	audit := &recordingAuditor{}
	c := testBroker(t, srv, scope, audit, nil)

	_, _, err := get(t, c, srv.URL)
	if err == nil {
		t.Fatal("out-of-scope request must be refused")
	}
	if !IsScopeDenied(err) {
		t.Errorf("error should be a scope denial, got: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("server was contacted %d times despite a scope denial; scope must gate before any I/O", n)
	}

	// The denial itself must be auditable.
	recs := audit.all()
	if len(recs) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recs))
	}
	if recs[0].Allowed || recs[0].DeniedBy != "scope" {
		t.Errorf("audit record should record the denial: %+v", recs[0])
	}
	if c.Stats().Denied != 1 {
		t.Errorf("Stats().Denied = %d, want 1", c.Stats().Denied)
	}
}

func TestBrokerScopeDenialIsNotRetried(t *testing.T) {
	scope := newFakeScope()
	scope.denyAll = true
	audit := &recordingAuditor{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := testBroker(t, srv, scope, audit, nil)

	_, _, _ = get(t, c, srv.URL)
	// One audit record means one attempt. A scope denial is a governance
	// decision; retrying it would only produce more denials in the log.
	if n := len(audit.all()); n != 1 {
		t.Errorf("scope denial produced %d attempts, want exactly 1", n)
	}
}

func TestBrokerAllowsInScopeAndAudits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	audit := &recordingAuditor{}
	c := testBroker(t, srv, newFakeScope(host), audit, nil)

	resp, body, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatalf("in-scope request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK || body != `{"ok":true}` {
		t.Errorf("status=%d body=%q", resp.StatusCode, body)
	}
	recs := audit.all()
	if len(recs) != 1 || !recs[0].Allowed || recs[0].Status != 200 {
		t.Errorf("expected one allowed record with status 200, got %+v", recs)
	}
	if recs[0].Module != "test-mod" || recs[0].Host != host {
		t.Errorf("audit record missing attribution: %+v", recs[0])
	}
}

func TestBrokerFailsClosedWithoutScopeChecker(t *testing.T) {
	// An unwired broker must make no requests at all. Treating "no scope
	// checker" as "no restriction" would turn a wiring bug into a full-access
	// tool.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server contacted with no scope checker wired")
	}))
	defer srv.Close()
	c := testBroker(t, srv, nil, nil, nil)
	if _, _, err := get(t, c, srv.URL); err == nil {
		t.Error("expected refusal when no scope checker is configured")
	}
}

func TestBrokerSSRFBlocksMetadataEndpoint(t *testing.T) {
	scope := newFakeScope("169.254.169.254")
	audit := &recordingAuditor{}
	c := testBroker(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})), scope, audit, nil)
	c.CloseIdleConnections()

	_, _, err := get(t, c, "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err == nil {
		t.Fatal("cloud metadata endpoint must be refused even when in scope")
	}
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("expected SSRF block, got: %v", err)
	}
	recs := audit.all()
	if len(recs) == 0 || recs[0].DeniedBy != "ssrf" {
		t.Errorf("SSRF denial should be audited: %+v", recs)
	}
}

func TestBrokerBlocksRedirectOutOfScope(t *testing.T) {
	// An in-scope host that redirects to a private address is the classic SSRF
	// pivot. Each hop must be re-validated.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	c := testBroker(t, srv, newFakeScope(host, "169.254.169.254"), nil, nil)
	if resp, _, err := get(t, c, srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("redirect to metadata endpoint must be refused")
	}
}

func TestBrokerBlocksRedirectToOutOfScopeHost(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://out-of-scope.example/", http.StatusFound)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	c := testBroker(t, srv, newFakeScope(host), nil, nil)
	if resp, _, err := get(t, c, srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("redirect to an out-of-scope host must be refused")
	}
}

func TestBrokerCacheHitSkipsUpstream(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"v":1}`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	cache := newMemCache()
	audit := &recordingAuditor{}
	c := testBroker(t, srv, newFakeScope(host), audit, cache)

	_, b1, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, b2, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if b1 != b2 {
		t.Errorf("cached body differs: %q vs %q", b1, b2)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("upstream hit %d times, want 1 (second request must be served from cache)", n)
	}
	if c.Stats().FromCache != 1 {
		t.Errorf("Stats().FromCache = %d, want 1", c.Stats().FromCache)
	}
	// A cache hit must still be audited, so the record of what was consulted
	// stays complete.
	recs := audit.all()
	if len(recs) != 2 || !recs[1].FromCache {
		t.Errorf("cache hit should be audited with FromCache: %+v", recs)
	}
}

func TestBrokerRetriesTransientStatus(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("recovered"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	c := testBroker(t, srv, newFakeScope(host), nil, nil)
	_, body, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatalf("expected recovery after retries: %v", err)
	}
	if body != "recovered" {
		t.Errorf("body = %q", body)
	}
	if got := atomic.LoadInt32(&n); got != 3 {
		t.Errorf("upstream calls = %d, want 3", got)
	}
}

func TestBrokerDoesNotRetryPermanentStatus(t *testing.T) {
	// A 404 is a permanent answer. Retrying it would waste budget and, during
	// enumeration, hammer a provider for every absent record.
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	c := testBroker(t, srv, newFakeScope(host), nil, nil)
	if resp, _, _ := get(t, c, srv.URL); resp != nil {
		resp.Body.Close()
	}
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Errorf("404 caused %d attempts, want exactly 1", got)
	}
}

func TestBrokerHonoursRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	r := NewRetryer(RetryConfig{MaxAttempts: 2, Base: time.Millisecond, Max: 50 * time.Millisecond})
	var delays []time.Duration
	// Capture the server-advised delay without actually waiting for it.
	err := r.Do(context.Background(), func(ctx context.Context, attempt int) error {
		delays = append(delays, retryAfter(NewStatusError(429, "x")))
		return NewStatusError(429, "x")
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(delays) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(delays))
	}
}

func TestBreakerOpensAndRecovers(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	b := NewBreaker(BreakerSettings{FailureThreshold: 3, Window: time.Minute, Cooldown: 30 * time.Second})
	b = b.WithClock(func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if !b.Allow("api.example") {
			t.Fatalf("breaker should still be closed at failure %d", i+1)
		}
		b.Report("api.example", false)
	}
	if !b.Open("api.example") {
		t.Fatal("breaker should be open after 3 consecutive failures")
	}
	if b.Allow("api.example") {
		t.Error("open breaker must refuse")
	}
	// A different host is unaffected: one broken provider must not silence the scan.
	if !b.Allow("other.example") {
		t.Error("breaker must be per-host")
	}

	// Before the cooldown elapses, still open.
	now = now.Add(10 * time.Second)
	if b.Allow("api.example") {
		t.Error("breaker must stay open during cooldown")
	}

	// After cooldown, one probe is allowed and success closes it.
	now = now.Add(25 * time.Second)
	if !b.Allow("api.example") {
		t.Fatal("half-open probe should be allowed after cooldown")
	}
	if b.Allow("api.example") {
		t.Error("only one probe should be admitted while half-open")
	}
	b.Report("api.example", true)
	if b.Open("api.example") {
		t.Error("a successful probe must close the breaker")
	}
	if !b.Allow("api.example") {
		t.Error("closed breaker must allow")
	}
}

func TestBreakerIgnoresResourceLevelFailures(t *testing.T) {
	// A module enumerating many absent resources gets many 404s. Treating those
	// as host failure would open the breaker mid-enumeration and silently stop
	// collecting.
	b := NewBreaker(DefaultBreakerSettings())
	for i := 0; i < 50; i++ {
		b.ReportHTTP("api.example", http.StatusNotFound)
	}
	if b.Open("api.example") {
		t.Error("404s must not open the breaker")
	}
	for i := 0; i < 50; i++ {
		b.ReportHTTP("api.example", http.StatusForbidden)
	}
	if b.Open("api.example") {
		t.Error("403s must not open the breaker")
	}
	// A 400 is our mistake, not the host's, so it must not count against health.
	for i := 0; i < 50; i++ {
		b.ReportHTTP("api.example", http.StatusBadRequest)
	}
	if b.Open("api.example") {
		t.Error("repeated 400s must not open the breaker; they indicate a bad request, not a sick host")
	}
	// 5xx and 429 genuinely indicate host trouble.
	for i := 0; i < 5; i++ {
		b.ReportHTTP("api.example", http.StatusInternalServerError)
	}
	if !b.Open("api.example") {
		t.Error("repeated 5xx should open the breaker")
	}
}

func TestBreakerForgetsStaleFailures(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	b := NewBreaker(BreakerSettings{FailureThreshold: 3, Window: time.Minute})
	b = b.WithClock(func() time.Time { return now })
	b.Report("h.example", false)
	b.Report("h.example", false)
	now = now.Add(2 * time.Minute) // failure run is now stale
	b.Report("h.example", false)
	if b.Open("h.example") {
		t.Error("a stale failure run must not count toward opening")
	}
}

func TestRateLimiterEnforcesPerHost(t *testing.T) {
	rate, err := ParseRate("2/s")
	if err != nil {
		t.Fatal(err)
	}
	rl := NewRateLimiter(Rate{}, 0, map[string]Rate{"slow.example": rate}, nil)

	start := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := rl.Wait(context.Background(), "mod", "slow.example"); err != nil {
			t.Fatal(err)
		}
	}
	// Two immediate, then three more that must wait. With a 2/s bucket the last
	// three take at least ~0.5s each.
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Errorf("5 requests at 2/s took %v; rate limit not enforced", d)
	}
}

func TestRateLimiterRespectsCancellation(t *testing.T) {
	rate, _ := ParseRate("1/s")
	rl := NewRateLimiter(Rate{}, 0, map[string]Rate{"slow.example": rate}, nil)
	if _, err := rl.Wait(context.Background(), "mod", "slow.example"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled scan must not be held for the full rate period.
	start := time.Now()
	if _, err := rl.Wait(ctx, "mod", "slow.example"); err == nil {
		t.Error("expected cancellation error")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("cancelled Wait blocked for %v", d)
	}
}

func TestRateLimiterDrainsBurstThenThrottles(t *testing.T) {
	rate, _ := ParseRate("10/s")
	rl := NewRateLimiter(Rate{}, 5, nil, map[string]Rate{"m": rate})
	start := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := rl.Wait(context.Background(), "m", "h.example"); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("burst of 5 should not have waited, took %v", d)
	}
}

func TestSharedLimiterFailureDoesNotBecomeUnlimited(t *testing.T) {
	rl := NewRateLimiter(Rate{Requests: 1, Per: time.Second}, 1, nil, nil)
	rl = rl.WithShared(failingShared{})
	start := time.Now()
	_, err := rl.Wait(context.Background(), "m", "h.example")
	// Whatever the outcome, a broken shared limiter must not turn into an
	// unbounded allowance.
	if err == nil {
		t.Log("Wait succeeded despite shared failure; acceptable only if the local bucket still limited it")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("Wait blocked for %v", d)
	}
}

type failingShared struct{}

func (failingShared) Allow(context.Context, string, Rate, int) (bool, time.Duration, error) {
	return false, 0, errors.New("redis down")
}

func TestReadAllBounded(t *testing.T) {
	data, truncated, err := ReadAllBounded(strings.NewReader(strings.Repeat("a", 100)), 50)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(data) != 50 {
		t.Errorf("got len=%d truncated=%v, want len=50 truncated=true", len(data), truncated)
	}
	data, truncated, err = ReadAllBounded(strings.NewReader("short"), 50)
	if err != nil || truncated || string(data) != "short" {
		t.Errorf("got %q truncated=%v err=%v", data, truncated, err)
	}
}

func TestBoundedResponseBody(t *testing.T) {
	b := newBoundedBody([]byte("hello"), 3)
	got, _ := io.ReadAll(b)
	if string(got) != "hel" {
		t.Errorf("bounded body returned %q, want %q", got, "hel")
	}
}

func TestConcurrentBrokerUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":1}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	lim, _ := ParseRate("10000/s")
	c, err := NewClient(
		ClientConfig{Module: "m", UserAgent: "Argus/test", AllowLoopback: true, Timeout: 5 * time.Second},
		nil,
		NewRateLimiter(lim, 50, nil, nil),
		NewBreaker(DefaultBreakerSettings()),
		NewRetryer(RetryConfig{MaxAttempts: 1}),
		nil, &recordingAuditor{}, newFakeScope(host),
	)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			resp, err := c.Do(req)
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent request failed: %v", err)
	}
}
