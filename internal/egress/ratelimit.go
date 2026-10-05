package egress

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimiter applies token buckets at three levels: global, per module, and per
// host. All three must admit a request before it is sent, so a single module
// cannot spend the whole scan's budget and one noisy host cannot absorb the
// scan's concurrency.
type RateLimiter struct {
	mu sync.Mutex

	global     *bucket
	perModule  map[string]*bucket
	perHost    map[string]*bucket
	burstAllow int

	// shared, when non-nil, delegates accounting to a cluster-wide backend so
	// multiple workers do not collectively exceed a provider's quota.
	shared SharedLimiter

	// now is injectable for deterministic tests.
	now func() time.Time
}

// SharedLimiter is the cluster-wide rate-limit backend (Redis in production).
type SharedLimiter interface {
	// Allow reports whether a request to key may proceed, consuming one token.
	Allow(ctx context.Context, key string, limit Rate, burst int) (bool, time.Duration, error)
}

// Rate is a rate specification.
type Rate struct {
	Requests int
	Per      time.Duration
}

func (r Rate) zero() bool { return r.Requests <= 0 || r.Per <= 0 }

// rateUnits maps accepted suffixes to a period. A bare number (no suffix)
// means per second.
var rateUnits = []struct {
	suffix string
	per    time.Duration
}{
	{"/sec", time.Second},
	{"/second", time.Second},
	{"/s", time.Second},
	{"/min", time.Minute},
	{"/minute", time.Minute},
	{"/m", time.Minute},
	{"/hour", time.Hour},
	{"/hr", time.Hour},
	{"/h", time.Hour},
	{"/day", 24 * time.Hour},
	{"/d", 24 * time.Hour},
	{"/ms", time.Millisecond},
	{" per ", -1}, // handled below; marks the "N per minute" spelling
}

// ParseRate parses forms like "5/s", "20/m", "100/h", "2 per minute", or a bare
// "3" meaning 3 per second.
//
// An unrecognized suffix is an error rather than a silent fallback to
// per-second: a typo such as "5/mnute" must not quietly become five times the
// intended request rate against a provider.
func ParseRate(s string) (Rate, error) {
	raw := strings.TrimSpace(strings.ToLower(s))
	if raw == "" {
		return Rate{}, nil
	}
	// s is the function parameter; normalise it in place.
	s = raw

	per := time.Second
	num := s
	for _, u := range rateUnits {
		if strings.HasSuffix(s, u.suffix) {
			if u.per < 0 {
				continue
			}
			per = u.per
			num = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	// "N per minute" and friends.
	if i := strings.Index(s, " per "); i > 0 {
		num = strings.TrimSpace(s[:i])
		switch strings.TrimSpace(s[i+len(" per "):]) {
		case "second", "sec", "s":
			per = time.Second
		case "minute", "min", "m":
			per = time.Minute
		case "hour", "hr", "h":
			per = time.Hour
		case "day", "d":
			per = 24 * time.Hour
		default:
			return Rate{}, fmt.Errorf("egress: cannot parse rate %q: unknown time unit", raw)
		}
	}

	if strings.ContainsAny(num, "abcdefghijklmnopqrstuvwxyz") {
		return Rate{}, fmt.Errorf("egress: cannot parse rate %q (want N/s, N/m, N/h, or N/d)", raw)
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 0 {
		return Rate{}, fmt.Errorf("egress: cannot parse rate %q: expected a non-negative integer", raw)
	}
	return Rate{Requests: n, Per: per}, nil
}

// bucket is a token bucket with a monotonic clock.
type bucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	rate     float64 // tokens per second
	last     time.Time
}

func newBucket(r Rate, burst int, now func() time.Time) *bucket {
	capacity := float64(r.Requests)
	if burst > 0 {
		capacity = float64(burst)
	}
	if capacity < 1 {
		capacity = 1
	}
	b := &bucket{
		capacity: capacity,
		tokens:   capacity, // start full so the first request is immediate
		rate:     float64(r.Requests) / r.Per.Seconds(),
		last:     now(),
	}
	if b.rate <= 0 {
		b.rate = math.Inf(1)
	}
	return b
}

// reserve consumes one token, returning how long to wait if none is available.
func (b *bucket) reserve(now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	if now.After(b.last) {
		b.tokens = math.Min(b.capacity, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	need := 1 - b.tokens
	return time.Duration(need / b.rate * float64(time.Second))
}

func (b *bucket) available() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens
}

// NewRateLimiter builds a limiter. defaultRate applies to anything not
// explicitly configured; perHost and perModule override it.
func NewRateLimiter(defaultRate Rate, burst int, perHost, perModule map[string]Rate) *RateLimiter {
	now := time.Now
	rl := &RateLimiter{
		perModule:  map[string]*bucket{},
		perHost:    map[string]*bucket{},
		burstAllow: burst,
		now:        now,
	}
	if !defaultRate.zero() {
		rl.global = newBucket(defaultRate, burst, now)
	}
	for h, r := range perHost {
		if r.zero() {
			continue
		}
		b := burst
		if b <= 0 {
			b = r.Requests
		}
		rl.perHost[hostKey(h)] = newBucket(r, b, now)
	}
	for m, r := range perModule {
		if r.zero() {
			continue
		}
		b := burst
		if b <= 0 {
			b = r.Requests
		}
		rl.perModule[m] = newBucket(r, b, now)
	}
	return rl
}

// WithClock overrides the clock for deterministic tests.
func (rl *RateLimiter) WithClock(now func() time.Time) *RateLimiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.now = now
	return rl
}

// WithShared attaches a cluster-wide backend.
func (rl *RateLimiter) WithShared(s SharedLimiter) *RateLimiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.shared = s
	return rl
}

func hostKey(h string) string { return strings.ToLower(strings.TrimSpace(h)) }

// Wait blocks until a token is available for module+host, honouring cancellation
// and every configured level.
func (rl *RateLimiter) Wait(ctx context.Context, module, host string) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	start := rl.clock()

	for _, lvl := range rl.levels(module, host) {
		if lvl == nil {
			continue
		}
		d, ok, err := lvl.take(rl, module, host)
		if err != nil {
			return rl.clock().Sub(start), err
		}
		if !ok && d > 0 {
			if err := sleepCtx(ctx, d); err != nil {
				return rl.clock().Sub(start), err
			}
		}
	}
	return rl.clock().Sub(start), ctx.Err()
}

// level is one rate-limit dimension.
type level struct {
	bucket *bucket
	// sharedKey names the key to use in a cluster-wide backend. Empty means the
	// level is local-only.
	sharedKey func(module, host string) string
}

// take acquires a token for this level, consulting a shared backend when one is
// configured.
func (l *level) take(rl *RateLimiter, module, host string) (time.Duration, bool, error) {
	if l.bucket == nil {
		return 0, true, nil
	}
	rl.mu.Lock()
	shared := rl.shared
	rl.mu.Unlock()

	if shared != nil && l.sharedKey != nil {
		rate := Rate{Requests: int(l.bucket.rate), Per: time.Second}
		if l.bucket.rate <= 0 {
			rate = Rate{Requests: int(l.bucket.capacity), Per: time.Second}
		}
		ok, d, err := shared.Allow(context.Background(), l.sharedKey(module, host), rate, int(l.bucket.capacity))
		if err != nil {
			// A failing limiter must not silently become an unlimited one. Treating
			// the error as "deny and retry" degrades to slower scans rather than
			// unrestrained requests to a provider.
			return 0, false, fmt.Errorf("egress: shared rate limiter: %w", err)
		}
		return d, ok, nil
	}
	d := l.bucket.reserve(rl.clock())
	return d, d == 0, nil
}

func (rl *RateLimiter) levels(module, host string) []*level {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := []*level{
		{bucket: rl.global, sharedKey: func(_, _ string) string { return "global" }},
		{bucket: rl.perModule[module], sharedKey: func(m, _ string) string { return "module:" + m }},
		{bucket: rl.perHost[hostKey(host)], sharedKey: func(_, h string) string { return "host:" + hostKey(h) }},
	}
	return out
}

func (rl *RateLimiter) clock() time.Time {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.now == nil {
		return time.Now()
	}
	return rl.now()
}

func (rl *RateLimiter) globalBucket() *bucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.global
}

func (rl *RateLimiter) moduleBucket(module string) *bucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.perModule[module]
}

func (rl *RateLimiter) hostBucket(host string) *bucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.perHost[hostKey(host)]
}

// Stats reports remaining tokens, for `argus doctor` and the metrics endpoint.
func (rl *RateLimiter) Stats() map[string]float64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := map[string]float64{}
	if rl.global != nil {
		out["global"] = rl.global.available()
	}
	for k, b := range rl.perHost {
		out["host:"+k] = b.available()
	}
	for k, b := range rl.perModule {
		out["module:"+k] = b.available()
	}
	return out
}

// sleepCtx waits for d or until ctx is done, whichever comes first. A scan being
// cancelled must not be held hostage by a rate limiter for a full period.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
