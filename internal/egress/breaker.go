package egress

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when a host's breaker is open.
var ErrCircuitOpen = errors.New("egress: circuit breaker open")

// BreakerState is the breaker lifecycle.
type BreakerState int

const (
	StateClosed BreakerState = iota
	StateHalfOpen
	StateOpen
)

func (s BreakerState) String() string {
	switch s {
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "closed"
	}
}

// Breaker trips per host so that one failing provider cannot consume the whole
// scan's budget in failed retries.
//
// Opening early is the point: a provider that is refusing every request will
// fail the same way for the next hour, and the analyst gets partial results
// sooner plus an accurate audit trail of what was attempted.
type Breaker struct {
	mu       sync.Mutex
	perHost  map[string]*hostBreaker
	settings BreakerSettings
	now      func() time.Time
}

// BreakerSettings configures the breaker.
type BreakerSettings struct {
	// FailureThreshold consecutive failures before opening.
	FailureThreshold int
	// Window over which failures are counted.
	Window time.Duration
	// Cooldown before a half-open probe is allowed.
	Cooldown time.Duration
	// HalfOpenProbes is how many probes may run while half-open.
	HalfOpenProbes int
}

type hostBreaker struct {
	state      BreakerState
	failures   int
	openedAt   time.Time
	lastFail   time.Time
	probes     int
	successes  int
	totalCalls int
	totalFails int
}

// DefaultBreakerSettings returns conservative values.
func DefaultBreakerSettings() BreakerSettings {
	return BreakerSettings{
		FailureThreshold: 5,
		Window:           60 * time.Second,
		Cooldown:         60 * time.Second,
		HalfOpenProbes:   1,
	}
}

// NewBreaker builds a breaker map.
func NewBreaker(s BreakerSettings) *Breaker {
	if s.FailureThreshold <= 0 {
		s.FailureThreshold = 5
	}
	if s.Window <= 0 {
		s.Window = 60 * time.Second
	}
	if s.Cooldown <= 0 {
		s.Cooldown = 60 * time.Second
	}
	if s.HalfOpenProbes <= 0 {
		s.HalfOpenProbes = 1
	}
	return &Breaker{perHost: map[string]*hostBreaker{}, settings: s, now: time.Now}
}

// WithClock overrides the clock for tests.
func (b *Breaker) WithClock(now func() time.Time) *Breaker {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
	return b
}

// Allow reports whether a request to host may proceed, and consumes a probe slot
// when the breaker is half-open.
func (b *Breaker) Allow(host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	hb := b.get(host)
	now := b.now()

	switch hb.state {
	case StateClosed:
		return true
	case StateOpen:
		if now.Sub(hb.openedAt) < b.settings.Cooldown {
			return false
		}
		// Cooldown elapsed: let a limited number of probes through to see whether
		// the host recovered.
		hb.state = StateHalfOpen
		hb.probes = 0
		return b.takeProbe(hb)
	case StateHalfOpen:
		return b.takeProbe(hb)
	}
	return true
}

func (b *Breaker) takeProbe(hb *hostBreaker) bool {
	if hb.probes >= b.settings.HalfOpenProbes {
		return false
	}
	hb.probes++
	return true
}

// Report feeds a call outcome back to the breaker.
func (b *Breaker) Report(host string, success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	hb := b.get(host)
	now := b.now()
	hb.totalCalls++
	if success {
		hb.successes++
		hb.failures = 0
		hb.state = StateClosed
		hb.probes = 0
		hb.lastFail = time.Time{}
		return
	}
	hb.totalFails++
	// A stale run of failures should not count: a host that failed an hour ago
	// and has not been called since is not currently unhealthy.
	if !hb.lastFail.IsZero() && now.Sub(hb.lastFail) > b.settings.Window {
		hb.failures = 0
	}
	hb.lastFail = now
	hb.failures++

	if hb.state == StateHalfOpen {
		// The probe failed: back to open for another full cooldown.
		hb.state = StateOpen
		hb.openedAt = now
		hb.probes = 0
		return
	}
	if hb.failures >= b.settings.FailureThreshold {
		hb.state = StateOpen
		hb.openedAt = now
	}
}

// ReportHTTP feeds a status code to the breaker.
//
// Only 429 and 5xx count as host failure. Those are the provider telling us it is
// overloaded or broken. A 4xx says our request was wrong, or that one resource is
// missing or forbidden, and counting those would open the breaker mid-enumeration:
// a module walking thousands of absent records would be silenced while the host is
// in fact healthy.
func (b *Breaker) ReportHTTP(host string, statusCode int) {
	b.Report(host, !hostUnhealthy(statusCode))
}

func hostUnhealthy(code int) bool {
	switch code {
	case http.StatusTooManyRequests: // 429
		return true
	}
	return code >= 500
}

func (b *Breaker) get(host string) *hostBreaker {
	h := hostKey(host)
	hb, ok := b.perHost[h]
	if !ok {
		hb = &hostBreaker{state: StateClosed}
		b.perHost[h] = hb
	}
	return hb
}

// State returns a host's breaker state.
func (b *Breaker) State(host string) BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.get(host).state
}

// Open reports whether a host's breaker is open.
func (b *Breaker) Open(host string) bool { return b.State(host) == StateOpen }

// Reset closes every breaker. Exposed for tests and for `argus modules test`.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.perHost = map[string]*hostBreaker{}
}

// Snapshot returns per-host breaker state for the metrics endpoint.
func (b *Breaker) Snapshot() map[string]StateSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]StateSnapshot, len(b.perHost))
	for h, hb := range b.perHost {
		out[h] = StateSnapshot{
			State:     hb.state,
			Failures:  hb.failures,
			Calls:     hb.totalCalls,
			Fails:     hb.totalFails,
			OpenedAt:  hb.openedAt,
			OpenedFor: b.now().Sub(hb.openedAt),
		}
	}
	return out
}

// StateSnapshot is a point-in-time view of one host's breaker.
type StateSnapshot struct {
	State     BreakerState
	Failures  int
	Calls     int
	Fails     int
	OpenedAt  time.Time
	OpenedFor time.Duration
}

// RetryConfig configures retry behaviour.
type RetryConfig struct {
	MaxAttempts int
	Backoff     string // fixed | exponential | decorrelated_jitter
	Base        time.Duration
	Max         time.Duration
}

// DefaultRetryConfig returns the specification defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{MaxAttempts: 3, Backoff: "decorrelated_jitter", Base: 500 * time.Millisecond, Max: 30 * time.Second}
}

// Retryer runs an operation with backoff, honouring Retry-After.
type Retryer struct {
	cfg RetryConfig
	now func() time.Time
	rng *rand.Rand
	mu  sync.Mutex
}

// NewRetryer builds a Retryer.
func NewRetryer(cfg RetryConfig) *Retryer {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.Base <= 0 {
		cfg.Base = 500 * time.Millisecond
	}
	if cfg.Max <= 0 {
		cfg.Max = 30 * time.Second
	}
	return &Retryer{cfg: cfg, now: time.Now, rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

// WithClock overrides the clock for tests.
func (r *Retryer) WithClock(now func() time.Time) *Retryer {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
	return r
}

// Do runs op until it succeeds, the error is permanent, or attempts run out.
//
// Retrying a non-idempotent request is a real hazard: a POST that succeeded but
// whose response was lost would be sent again. Callers must therefore only pass
// requests whose method is idempotent, or whose body is a pure query.
func (r *Retryer) Do(ctx context.Context, op func(context.Context, int) error) error {
	var lastErr error
	for attempt := 1; attempt <= r.cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := op(ctx, attempt)
		if err == nil {
			return nil
		}
		lastErr = err

		if !retryable(err) {
			return err
		}
		if attempt == r.cfg.MaxAttempts {
			break
		}
		d := r.delay(attempt)
		// A provider that tells us when to come back is more authoritative than
		// our own backoff curve.
		if ra := retryAfter(err); ra > 0 {
			d = ra
			if d > r.cfg.Max {
				d = r.cfg.Max
			}
		}
		if err := sleepCtx(ctx, d); err != nil {
			return err
		}
	}
	return fmt.Errorf("egress: after %d attempts: %w", r.cfg.MaxAttempts, lastErr)
}

// delay computes the wait before the next attempt.
func (r *Retryer) delay(attempt int) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	var d time.Duration
	switch r.cfg.Backoff {
	case "fixed":
		d = r.cfg.Base
	case "exponential":
		d = time.Duration(float64(r.cfg.Base) * math.Pow(2, float64(attempt-1)))
	default: // decorrelated_jitter, the default
		// Decorrelated jitter (AWS architecture blog): sleep uniformly in
		// [base, prev*3]. Unlike plain exponential backoff it caps at prev*3
		// rather than doubling, and the jitter decorrelates retries from many
		// workers that all failed at the same instant.
		r.mu.Unlock()
		hi := float64(r.cfg.Base) * math.Pow(3, float64(attempt-1))
		r.mu.Lock()
		if hi > float64(r.cfg.Max) {
			hi = float64(r.cfg.Max)
		}
		if hi <= float64(r.cfg.Base) {
			return r.cfg.Base
		}
		d = r.cfg.Base + time.Duration(r.rng.Float64()*(hi-float64(r.cfg.Base)))
	}
	if d > r.cfg.Max {
		d = r.cfg.Max
	}
	return d
}

// RetryableError marks an error as worth retrying when the transport cannot tell
// (for example, a JSON API that returned a parseable 503 body).
type RetryableError struct{ Err error }

func (e *RetryableError) Error() string { return e.Err.Error() }
func (e *RetryableError) Unwrap() error { return e.Err }

// IsRetryable reports whether an error is worth retrying.
func IsRetryable(err error) bool { return retryable(err) }

func retryable(err error) bool {
	if err == nil {
		return false
	}
	// An explicit RetryableError wrapper is the strongest signal: the caller
	// knew better than any heuristic.
	var re *RetryableError
	if errors.As(err, &re) {
		return true
	}
	// Governance and safety decisions are permanent. Retrying them produces more
	// denials in the audit log and burns budget on requests that must not happen.
	if errors.Is(err, ErrSSRFBlocked) || errors.Is(err, ErrCircuitOpen) {
		return false
	}
	if errors.Is(err, errScopeDenied) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// A concrete HTTP status answers the question definitively. Without this
	// branch a 404 would be retried three times, because it is "not a network
	// error" and therefore falls through to the default.
	if code := StatusCode(err); code != 0 {
		return RetryableStatus(code)
	}
	// A redirect-limit stop is the client's own decision, not a fault.
	if strings.Contains(err.Error(), "stopped after") && strings.Contains(err.Error(), "redirects") {
		return false
	}
	// TLS and DNS-name failures are permanent: the name does not resolve and the
	// certificate will not become valid during the retry window.
	msg := err.Error()
	if strings.Contains(msg, "x509") || strings.Contains(msg, "certificate") {
		return false
	}
	if strings.Contains(msg, "no such host") {
		return false
	}
	return true
}

// errScopeDenied is set by the client when the scope guard refuses. Declared here
// to keep the policy package out of the retry decision logic.
var errScopeDenied = errors.New("egress: denied by scope")

// ScopeDenied marks a scope refusal so the retryer will not retry it.
func ScopeDenied(err error) error {
	return fmt.Errorf("%w: %v", errScopeDenied, err)
}

// IsScopeDenied reports whether an error came from the scope guard.
func IsScopeDenied(err error) bool { return errors.Is(err, errScopeDenied) }
