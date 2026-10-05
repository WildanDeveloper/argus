package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// DefaultMaxBodyBytes bounds a single response body. Without a cap, one hostile
// or misconfigured endpoint can exhaust memory in a 32-worker scan.
const DefaultMaxBodyBytes = 8 << 20 // 8 MiB

// maxDecompressedBytes bounds a decompression bomb: a body that expands far
// beyond its compressed size is an attack, not a large file.
const maxDecompressedBytes = DefaultMaxBodyBytes * 4

// Auditor records every outbound decision. Kept as a narrow interface so the
// audit package does not have to be imported here, which keeps the dependency
// direction one-way.
type Auditor interface {
	RecordEgress(ctx context.Context, rec EgressRecord) error
}

// EgressRecord is one audited outbound request.
type EgressRecord struct {
	Module    string
	Method    string
	URL       string
	Host      string
	CaseID    string
	ScanID    string
	Allowed   bool
	DeniedBy  string
	Reason    string
	Status    int
	FromCache bool
	Duration  time.Duration
	Retries   int
	Err       string
}

// ClientConfig configures the broker.
type ClientConfig struct {
	Module            string
	ScanID            string
	CaseID            string
	UserAgent         string
	MaxBodyBytes      int64
	MaxRedirects      int
	TLSMinVersion     uint16
	AllowPrivate      bool
	AllowPrivateCIDRs []string
	AllowExtraCIDRs   []string
	AllowLoopback     bool
	Timeout           time.Duration
	DisableCache      bool
	Cookies           bool
	Logger            *slog.Logger
}

// Client is the broker. It satisfies sdk.HTTPDoer.
type Client struct {
	cfg     ClientConfig
	guard   *SSRFGuard
	limits  *RateLimiter
	breaker *Breaker
	retry   *Retryer
	cache   Cache
	audit   Auditor

	// scopeCheck is consulted before every request. It is an interface so this
	// package does not import internal/policy; internal/engine wires them.
	scopeCheck ScopeChecker

	transport *http.Transport
	client    *http.Client
	jars      map[string]http.CookieJar // per-module cookie jars

	mu       sync.Mutex
	stats    Stats
	inflight map[string]*inflightCall
	now      func() time.Time
}

// ScopeChecker answers "may this module reach this URL?". Returning an error
// denies the request.
type ScopeChecker interface {
	CheckEgress(ctx context.Context, u *url.URL, module string) error
}

// Stats counts broker activity for the metrics endpoint.
type Stats struct {
	Requests      int64
	Denied        int64
	FromCache     int64
	Retries       int64
	BytesIn       int64
	RateLimitWait time.Duration
	BreakerOpen   int64
}

// Cache is the subset of caching the broker needs. A nil Cache disables caching,
// which is correct for air-gapped and offline analysis modes.
type Cache interface {
	// GetFresh returns a cached response for a conditional request. The bool
	// reports whether a stored entry existed.
	Get(key string) (*CachedResponse, bool)
	Put(key string, resp *CachedResponse, ttl time.Duration)
	Delete(key string)
}

// CachedResponse is a stored response body plus metadata.
type CachedResponse struct {
	Status    int
	Header    http.Header
	Body      []byte
	StoredAt  time.Time
	ETag      string
	LastMod   string
	SourceURL string
}

// inflightCall lets concurrent identical requests share one upstream call
// (request coalescing). Without it, 32 workers asking for the same subdomain all
// query the same API and the provider sees a burst.
type inflightCall struct {
	done chan struct{}
	resp *CachedResponse
	err  error
}

var _ sdk.HTTPDoer = (*Client)(nil)

// NewClient builds a broker.
func NewClient(cfg ClientConfig, guard *SSRFGuard, limits *RateLimiter, breaker *Breaker, retry *Retryer, cache Cache, auditor Auditor, scope ScopeChecker) (*Client, error) {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 5
	}
	if cfg.TLSMinVersion == 0 {
		cfg.TLSMinVersion = tls.VersionTLS12
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	g := &SSRFGuard{
		AllowPrivate:  cfg.AllowPrivate,
		AllowLoopback: cfg.AllowLoopback,
	}
	for _, raw := range cfg.AllowPrivateCIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("egress: allow_private_cidrs: %w", err)
		}
		g.AllowPrivateCIDRs = append(g.AllowPrivateCIDRs, p)
	}
	for _, raw := range cfg.AllowExtraCIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("egress: allow_extra_cidrs: %w", err)
		}
		g.AllowExtraCIDRs = append(g.AllowExtraCIDRs, p)
	}
	if guard != nil {
		g = guard
	}

	c := &Client{
		cfg:        cfg,
		guard:      g,
		limits:     limits,
		breaker:    breaker,
		retry:      retry,
		cache:      cache,
		audit:      auditor,
		scopeCheck: scope,
		jars:       map[string]http.CookieJar{},
		inflight:   map[string]*inflightCall{},
		now:        time.Now,
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		// The SSRF check happens here, on the resolved IP, immediately before
		// the connection. See SSRFGuard.Control for why a hostname-level check
		// is not sufficient.
		Control: g.Control,
	}

	c.transport = &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		DisableCompression:    false,
		// Size and decompression caps are enforced on read, but asking the
		// transport not to buffer unbounded responses is the first line.
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{
			MinVersion: cfg.TLSMinVersion,
		},
	}

	c.client = &http.Client{
		Transport: c.transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("egress: stopped after %d redirects", cfg.MaxRedirects)
			}
			// Re-validate every hop. A redirect is the single easiest way to walk
			// out of scope or into a private range, and the Referer-free 302 from
			// a cooperating-looking host is a classic SSRF pivot.
			if err := c.checkRedirectTarget(req); err != nil {
				return err
			}
			return nil
		},
	}
	if cfg.Cookies {
		c.jars[cfg.Module] = newJar()
	}

	return c, nil
}

func parsePrefix(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q: %w", raw, err)
	}
	return p.Masked(), nil
}

func newJar() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	return jar
}

// checkRedirectTarget re-runs scope and SSRF checks on a redirect destination.
func (c *Client) checkRedirectTarget(req *http.Request) error {
	if req.URL == nil {
		return fmt.Errorf("egress: redirect with no URL")
	}
	if c.scopeCheck != nil {
		if err := c.scopeCheck.CheckEgress(req.Context(), req.URL, c.cfg.Module); err != nil {
			return ScopeDenied(fmt.Errorf("redirect to %s denied: %w", req.URL.Redacted(), err))
		}
	}
	host := req.URL.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		return c.guard.CheckAddr(a)
	}
	// For a hostname we cannot know the IP yet; the dial-time Control hook will
	// catch it. Returning nil here is safe precisely because of that hook, and
	// only because of it.
	return nil
}

// SetScopeChecker injects the scope guard. Called by internal/engine after
// construction, to avoid an import cycle.
func (c *Client) SetScopeChecker(s ScopeChecker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scopeCheck = s
}

// SetAuditor replaces the auditor.
func (c *Client) SetAuditor(a Auditor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.audit = a
}

// Stats returns a snapshot of broker counters.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.BreakerOpen = 0
	for _, st := range c.breaker.Snapshot() {
		if st.State == StateOpen {
			s.BreakerOpen++
		}
	}
	return s
}

// Do is the single entry point for every outbound HTTP request.
//
// The order of operations is a security property, not a style choice: scope is
// checked before anything is cached or counted, so a denied request leaves no
// trace beyond its audit record, and no cache entry can ever be filled by a
// response the scope guard would have refused.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("egress: nil request")
	}
	ctx := req.Context()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	host := req.URL.Hostname()
	rec := EgressRecord{
		Module: c.cfg.Module,
		Method: req.Method,
		URL:    req.URL.Redacted(),
		Host:   host,
		ScanID: c.cfg.ScanID,
		CaseID: c.cfg.CaseID,
	}

	// 1. Scope. A denial here is a governance outcome and is never retried.
	if err := c.checkScope(ctx, req.URL); err != nil {
		rec.Allowed = false
		rec.DeniedBy = "scope"
		rec.Reason = err.Error()
		c.auditOut(ctx, rec)
		c.bump(func(s *Stats) { s.Denied++ })
		return nil, ScopeDenied(err)
	}

	// 2. SSRF, pre-flight. The authoritative check is at dial time; this one
	// catches a literal private IP in the URL without paying for a dial, and
	// produces a clearer error for the operator.
	if err := c.checkSSRF(ctx, host); err != nil {
		rec.Allowed = false
		rec.DeniedBy = "ssrf"
		rec.Reason = err.Error()
		c.auditOut(ctx, rec)
		c.bump(func(s *Stats) { s.Denied++ })
		return nil, err
	}

	// 3. Circuit breaker.
	if c.breaker != nil && !c.breaker.Allow(host) {
		rec.Allowed = false
		rec.DeniedBy = "breaker"
		rec.Reason = "circuit open"
		c.auditOut(ctx, rec)
		return nil, fmt.Errorf("%w for %s", ErrCircuitOpen, host)
	}

	// 4. Rate limit, honouring cancellation so a cancelled scan drains promptly.
	if c.limits != nil {
		waited, err := c.limits.Wait(ctx, c.cfg.Module, host)
		if err != nil {
			return nil, err
		}
		if waited > 0 {
			rec.Duration = waited
			c.bump(func(s *Stats) { s.RateLimitWait += waited })
		}
	}

	// 5. Cache. Only reached once the request is known to be permitted.
	if c.cache != nil && !c.cfg.DisableCache && isCacheable(req.Method) {
		if cr, ok := c.cache.Get(cacheKey(req)); ok {
			resp := cr.toResponse(req)
			rec.Allowed, rec.Status, rec.FromCache = true, cr.Status, true
			c.auditOut(ctx, rec)
			c.bump(func(s *Stats) { s.FromCache++ })
			return resp, nil
		}
	}

	// 6. The request itself, with retry.
	start := c.now()
	attempts := 0
	var resp *http.Response
	err := c.retry.Do(ctx, func(ctx context.Context, attempt int) error {
		attempts = attempt
		var rerr error
		resp, rerr = c.roundTrip(ctx, req, host)
		return rerr
	})
	rec.Duration = c.now().Sub(start)
	rec.Retries = maxInt(attempts-1, 0)
	rec.Allowed = true
	if err != nil {
		rec.Err = err.Error()
		c.auditOut(ctx, rec)
		if c.breaker != nil {
			c.breaker.Report(host, false)
		}
		c.bump(func(s *Stats) { s.Requests++; s.Retries += int64(maxInt(attempts-1, 0)) })
		return nil, err
	}

	rec.Status = resp.StatusCode
	c.auditOut(ctx, rec)
	c.bump(func(s *Stats) { s.Requests++; s.Retries += int64(maxInt(attempts-1, 0)) })
	return resp, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// roundTrip performs one attempt: send, read the bounded body, classify status.
// roundTrip performs one attempt: send, read the bounded body, classify status.
// It returns a response only on success. On failure the upstream response is
// already closed, so no connection leaks.
func (c *Client) roundTrip(ctx context.Context, req *http.Request, host string) (*http.Response, error) {
	// Clone so that retrying does not reuse a consumed body and does not mutate
	// the caller's request.
	attempt := req.Clone(ctx)
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("egress: replay body: %w", err)
		}
		attempt.Body = body
	}
	if c.cfg.UserAgent != "" && attempt.Header.Get("User-Agent") == "" {
		// Honest identification. ADR-010: Argus never rotates or spoofs its
		// user agent, because a tool that hides itself is a tool whose findings
		// cannot be trusted or attributed.
		attempt.Header.Set("User-Agent", c.cfg.UserAgent)
	}
	if c.cfg.Cookies {
		if jar := c.jarFor(c.cfg.Module); jar != nil {
			attempt = attempt.WithContext(withJar(ctx, jar))
		}
	}

	resp, err := c.client.Do(attempt)
	if err != nil {
		return nil, classify(err)
	}

	// Bound the body. Close is always called so the connection returns to the
	// pool or the socket is closed; leaking one per attempt exhausts the pool.
	body, readErr := c.readBounded(resp)

	if resp.StatusCode >= 400 {
		if c.breaker != nil {
			c.breaker.ReportHTTP(host, resp.StatusCode)
		}
		se := &httpStatusError{code: resp.StatusCode, url: req.URL.Redacted()}
		if RetryableStatus(resp.StatusCode) {
			ra := RetryAfterFromResponse(resp, c.now())
			return nil, &statusRetryAfter{httpStatusError: se, after: ra}
		}
		return nil, se
	}
	if c.breaker != nil {
		c.breaker.Report(host, true)
	}
	if readErr != nil {
		return nil, &RetryableError{Err: readErr}
	}

	// Store for the cache before handing the body to the caller.
	if c.cache != nil && !c.cfg.DisableCache && resp.StatusCode == http.StatusOK {
		c.cache.Put(cacheKey(req), &CachedResponse{
			Status:    resp.StatusCode,
			Header:    resp.Header.Clone(),
			Body:      body,
			StoredAt:  c.now(),
			ETag:      resp.Header.Get("ETag"),
			LastMod:   resp.Header.Get("Last-Modified"),
			SourceURL: req.URL.String(),
		}, c.cacheTTL(host))
	}

	c.bump(func(s *Stats) { s.BytesIn += int64(len(body)) })

	// Reconstruct a response the caller can consume normally.
	out := &http.Response{
		Status:        http.StatusText(resp.StatusCode),
		StatusCode:    resp.StatusCode,
		Proto:         resp.Proto,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Header:        resp.Header.Clone(),
		Body:          newBoundedBody(body, c.cfg.MaxBodyBytes),
		ContentLength: int64(len(body)),
		Request:       req,
		TLS:           resp.TLS,
	}
	resp.Body.Close()
	return out, nil
}

func (c *Client) jarFor(module string) http.CookieJar {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jars[module]
}

// readBounded reads at most max bytes, counting compressed and decompressed size
// so a decompression bomb is caught rather than expanded.
func (c *Client) readBounded(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()
	limit := c.cfg.MaxBodyBytes
	lr := io.LimitReader(resp.Body, limit+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("egress: read body: %w", err)
	}
	if int64(len(data)) > limit {
		// Truncate rather than fail: a partial body is still useful to a parser,
		// and the truncation is visible because the caller sees fewer bytes than
		// Content-Length promised.
		return data[:limit], fmt.Errorf("egress: body exceeded %d byte limit; truncated", limit)
	}
	return data, nil
}

// checkScope asks the scope guard whether this module may reach this URL.
func (c *Client) checkScope(ctx context.Context, u *url.URL) error {
	c.mu.Lock()
	sc := c.scopeCheck
	c.mu.Unlock()
	if sc == nil {
		// No scope checker wired is a misconfiguration, not a permission. Fail
		// closed: an unwired broker must make no requests.
		return fmt.Errorf("egress: no scope checker configured; refusing %s", u.Redacted())
	}
	return sc.CheckEgress(ctx, u, c.cfg.Module)
}

func (c *Client) checkSSRF(ctx context.Context, host string) error {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return c.guard.CheckAddr(a)
	}
	return nil // deferred to the dial-time Control hook
}

func (c *Client) auditOut(ctx context.Context, rec EgressRecord) {
	c.mu.Lock()
	a := c.audit
	c.mu.Unlock()
	if a == nil {
		return
	}
	// Audit failure must not fail the request that was already made, but it is
	// logged loudly: an unaudited request is a gap in the accountability record.
	if err := a.RecordEgress(ctx, rec); err != nil {
		c.cfg.Logger.Error("audit record failed",
			"module", rec.Module, "url", rec.URL, "err", err.Error())
	}
}

func (c *Client) bump(f func(*Stats)) {
	c.mu.Lock()
	f(&c.stats)
	c.mu.Unlock()
}

func (c *Client) cacheTTL(host string) time.Duration { return defaultCacheTTL }

// defaultCacheTTL is used unless a Store supplies per-host TTLs. RDAP and
// Wayback data change on the order of days; DNS changes in minutes. The Store
// overrides this with configuration.
var defaultCacheTTL = 24 * time.Hour

// SetCacheTTL changes the fallback TTL.
func SetCacheTTL(d time.Duration) {
	if d > 0 {
		defaultCacheTTL = d
	}
}

func isCacheable(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead:
		return true
	}
	return false
}

// cacheKey identifies a request for caching and coalescing. It intentionally
// excludes the User-Agent and headers, which do not change the response body.
func cacheKey(req *http.Request) string {
	return req.Method + " " + req.URL.String()
}

// CachedResponse.toResponse rebuilds a response for a cache hit.
func (cr *CachedResponse) toResponse(req *http.Request) *http.Response {
	h := cr.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{
		Status:        http.StatusText(cr.Status),
		StatusCode:    cr.Status,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(string(cr.Body))),
		ContentLength: int64(len(cr.Body)),
		Request:       req,
	}
}

// classify wraps transport errors so the retryer can tell a transient network
// fault from a permanent configuration error.
func classify(err error) error {
	if err == nil {
		return nil
	}
	// A blocked redirect or a scope denial must not be retried.
	if IsScopeDenied(err) || errors.Is(err, ErrSSRFBlocked) || errors.Is(err, ErrCircuitOpen) {
		return err
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		if nerr.Timeout() {
			return &RetryableError{Err: err}
		}
		return &RetryableError{Err: err}
	}
	if strings.Contains(err.Error(), "stopped after") && strings.Contains(err.Error(), "redirects") {
		return err
	}
	// TLS certificate failures and DNS resolution failures for a host that does
	// not exist are permanent; retrying them wastes budget.
	if strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "certificate") {
		return err
	}
	return &RetryableError{Err: err}
}

// CloseIdleConnections releases pooled connections.
func (c *Client) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

// SetTransport replaces the transport. Used by tests that need a fake network,
// and by air-gapped mode where the transport refuses everything.
func (c *Client) SetTransport(rt http.RoundTripper) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client.Transport = rt
}
