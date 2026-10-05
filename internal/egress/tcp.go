package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// DialChecker decides whether a module may open a TCP connection to a host.
//
// It is a separate interface from ScopeChecker because a TCP connection has no URL.
// Keeping them apart lets the HTTP guard keep validating a parsed URL, which is a
// stronger thing to validate than a bare host:port, rather than degrading both to the
// weaker of the two.
type DialChecker interface {
	CheckDial(ctx context.Context, host string, port int, module string) error
}

// TCPDialer is the broker for raw TCP.
//
// Every control the HTTP broker applies applies here too, and it matters more rather
// than less: an HTTP collector can only reach a host its manifest declares, but a
// module holding a raw socket could reach anything at all, including a database on a
// private address that the SSRF guard exists to keep it away from. The SSRF check
// therefore runs inside DialContext, before the socket is connected rather than after.
type TCPDialer struct {
	module  string
	guard   *SSRFGuard
	limits  *RateLimiter
	breaker *Breaker
	scope   DialChecker
	auditor Auditor
	timeout time.Duration
	maxRead int64
	logger  *slog.Logger

	mu    sync.Mutex
	stats TCPDialStats
}

// TCPDialStats counts broker activity so a scan can report what it opened.
type TCPDialStats struct {
	Dialed  int64
	Denied  int64
	Bytes   int64
	Failed  int64
	Refused int64
}

var _ sdk.Dialer = (*TCPDialer)(nil)

// TCPConfig configures the TCP broker.
type TCPConfig struct {
	Module string
	Guard  *SSRFGuard
	// Limits and Breaker may be nil, in which case no rate limit or breaker is
	// applied. They are optional because a module that makes one connection per task
	// has nothing to rate limit.
	Limits  *RateLimiter
	Breaker *Breaker
	Scope   DialChecker
	Auditor Auditor
	Timeout time.Duration
	MaxRead int64
	Logger  *slog.Logger
}

// NewTCPDialer builds the TCP broker.
func NewTCPDialer(cfg TCPConfig) (*TCPDialer, error) {
	if cfg.Module == "" {
		return nil, fmt.Errorf("egress: TCP dialer requires a module name")
	}
	if cfg.Scope == nil {
		// Fail closed. An unwired broker must make no connections, exactly as the HTTP
		// broker does.
		return nil, fmt.Errorf("egress: TCP dialer for %s has no scope checker; refusing to open connections", cfg.Module)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRead <= 0 {
		// WHOIS records run to tens of kilobytes. A megabyte is generous and still
		// small enough that a hostile server cannot exhaust memory by answering.
		cfg.MaxRead = 1 << 20
	}
	d := &TCPDialer{
		module:  cfg.Module,
		guard:   cfg.Guard,
		limits:  cfg.Limits,
		breaker: cfg.Breaker,
		scope:   cfg.Scope,
		auditor: cfg.Auditor,
		timeout: cfg.Timeout,
		maxRead: cfg.MaxRead,
		logger:  cfg.Logger,
	}
	if d.logger == nil {
		d.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return d, nil
}

// Stats returns the activity counters.
func (d *TCPDialer) Stats() TCPDialStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// DialText opens a connection, writes the query, and returns a bounded reader.
func (d *TCPDialer) DialText(ctx context.Context, address string, q sdk.DialQuery) (sdk.TextConn, error) {
	host, port, err := splitAddress(address)
	if err != nil {
		return nil, err
	}

	if err := d.scope.CheckDial(ctx, host, port, d.module); err != nil {
		d.bump(func(s *TCPDialStats) { s.Denied++ })
		d.audit(ctx, host, port, "", 0, err)
		return nil, fmt.Errorf("egress: denied by scope: %w", err)
	}

	if d.limits != nil {
		// The module name is part of the limiter key so one collector's budget cannot
		// be spent by another's requests to the same host.
		if _, err := d.limits.Wait(ctx, d.module, host); err != nil {
			d.bump(func(s *TCPDialStats) { s.Refused++ })
			return nil, err
		}
	}
	if d.breaker != nil && !d.breaker.Allow(host) {
		d.bump(func(s *TCPDialStats) { s.Refused++ })
		return nil, fmt.Errorf("egress: circuit breaker open for %s", host)
	}

	timeout := q.Timeout
	if timeout <= 0 {
		timeout = d.timeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The SSRF check is attached to the dial itself rather than run before it. A
	// separate check-then-connect would leave a window in which a resolvable name
	// resolves differently the second time, which is the entire class of attack the
	// guard exists to close.
	conn, err := d.dial(dialCtx, host, port)
	if err != nil {
		d.bump(func(s *TCPDialStats) { s.Failed++ })
		if d.breaker != nil {
			d.breaker.Report(host, false)
		}
		d.audit(ctx, host, port, "", 0, err)
		return nil, err
	}

	if q.Query != "" {
		if deadline, ok := dialCtx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if _, err := conn.Write([]byte(q.Query + "\r\n")); err != nil {
			conn.Close()
			d.bump(func(s *TCPDialStats) { s.Failed++ })
			return nil, fmt.Errorf("egress: write to %s: %w", host, err)
		}
	}

	max := q.MaxBytes
	if max <= 0 {
		max = d.maxRead
	}

	d.bump(func(s *TCPDialStats) { s.Dialed++ })
	d.audit(ctx, host, port, q.Query, 0, nil)
	return &textConn{
		conn:   conn,
		host:   host,
		module: d.module,
		max:    max,
		dialer: d,
	}, nil
}

// dial opens the socket with the SSRF check wired into the dialer.
func (d *TCPDialer) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: d.timeout}

	if d.guard != nil {
		guard := d.guard
		dialer.Control = func(network, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("egress: unparseable dial address %q", address)
			}
			// CheckAddr validates against the blocked ranges. A name has already been
			// resolved by the time Control runs, which is what makes this the right
			// place: the check applies to the address actually being connected to.
			return guard.CheckAddr(ap.Addr())
		}
	}

	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "blocked") {
			return nil, fmt.Errorf("egress: refused: %w", err)
		}
		return nil, fmt.Errorf("egress: connect to %s: %w", target, err)
	}
	return conn, nil
}

// textConn is a bounded reader over a brokered connection.
type textConn struct {
	conn   net.Conn
	host   string
	module string
	max    int64
	dialer *TCPDialer

	mu        sync.Mutex
	read      int64
	truncated bool
}

func (c *textConn) Read(p []byte) (int, error) { //nolint:errcheck
	c.mu.Lock()
	// The limit is enforced here rather than by the caller. One byte past the limit is
	// read so the caller can tell "the server stopped" from "the server is still
	// talking", and returning the limit as an error is deliberate: a truncated
	// protocol response parses into a plausible-looking but incomplete record.
	room := c.max - c.read
	c.mu.Unlock()

	if room < 0 {
		return 0, fmt.Errorf("egress: response from %s exceeded %d bytes; the response is truncated", c.host, c.max)
	}
	if int64(len(p)) > room+1 {
		p = p[:room+1]
	}

	n, err := c.conn.Read(p)
	c.mu.Lock()
	c.read += int64(n)
	if c.read > c.max {
		c.truncated = true
	}
	c.mu.Unlock()

	if n > 0 && c.dialer != nil {
		c.dialer.bump(func(s *TCPDialStats) { s.Bytes += int64(n) })
	}
	return n, err
}

func (c *textConn) Close() error { return c.conn.Close() }

// splitAddress validates and splits a host:port pair.
func splitAddress(address string) (string, int, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", 0, fmt.Errorf("egress: empty address")
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("egress: address %q must be host:port: %w", address, err)
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return "", 0, fmt.Errorf("egress: address %q has no host", address)
	}
	port := 0
	for i := 0; i < len(portStr); i++ {
		if portStr[i] < '0' || portStr[i] > '9' {
			return "", 0, fmt.Errorf("egress: port %q is not a number", portStr)
		}
		port = port*10 + int(portStr[i]-'0')
		if port > 65535 {
			return "", 0, fmt.Errorf("egress: port %d is out of range", port)
		}
	}
	if port <= 0 {
		return "", 0, fmt.Errorf("egress: address %q has no port", address)
	}
	return strings.ToLower(host), port, nil
}

func (d *TCPDialer) bump(f func(*TCPDialStats)) {
	d.mu.Lock()
	f(&d.stats)
	d.mu.Unlock()
}

func (d *TCPDialer) audit(ctx context.Context, host string, port int, query string, _ int64, err error) {
	if d.auditor == nil {
		return
	}
	method := "tcp.dial"
	if query != "" {
		method = "tcp.query"
	}
	_ = d.auditor.RecordEgress(ctx, EgressRecord{
		Module:  d.module,
		Method:  method,
		Host:    host,
		URL:     "tcp://" + net.JoinHostPort(host, strconv.Itoa(port)),
		Allowed: err == nil,
	})
}

// ReadAllConn reads a brokered connection to its limit.
//
// A truncated response is an error rather than a short read. Every parser in this
// build would happily turn half a record into a plausible one, and a WHOIS record with
// its contact block cut off is exactly the shape that invents or loses data.
func ReadAllConn(r io.Reader, limit int64) ([]byte, error) {
	data, truncated, err := ReadAllBounded(r, limit)
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("egress: response exceeded %d bytes; refusing to parse a truncated record", limit)
	}
	return data, nil
}
