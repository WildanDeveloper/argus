package egress

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

type dialScope struct {
	mu      sync.Mutex
	allowed map[string]bool
	calls   []string
}

func (s *dialScope) CheckDial(_ context.Context, host string, port int, module string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, host+":"+itoa(port))
	if s.allowed == nil {
		return nil
	}
	if s.allowed[host] {
		return nil
	}
	return errDenied(host)
}

// errDenied stands in for the real scope guard's refusal.
func errDenied(host string) error {
	return fmt.Errorf("module may not reach %s", host)
}

// whoisEcho stands in for a WHOIS server on the loopback interface.
type whoisEcho struct {
	ln    net.Listener
	reply string
	delay time.Duration
	// flood answers without end, to exercise the read bound.
	flood bool
}

func newEcho(t *testing.T, reply string) *whoisEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &whoisEcho{ln: ln, reply: reply}
	go e.serve()
	t.Cleanup(func() { ln.Close() })
	return e
}

func (e *whoisEcho) addr() string { return e.ln.Addr().String() }

func (e *whoisEcho) host() string {
	h, _, _ := net.SplitHostPort(e.addr())
	return h
}

func (e *whoisEcho) serve() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 256)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _ := c.Read(buf)
			if e.delay > 0 {
				time.Sleep(e.delay)
			}
			if e.flood {
				chunk := strings.Repeat("x", 4096)
				for i := 0; i < 10000; i++ {
					if _, err := c.Write([]byte(chunk)); err != nil {
						return
					}
				}
				return
			}
			_ = n
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write([]byte(e.reply))
		}(c)
	}
}

func newTCP(t *testing.T, scope DialChecker) *TCPDialer {
	t.Helper()
	d, err := NewTCPDialer(TCPConfig{
		Module: "whois",
		Scope:  scope,
		// Loopback has to be reachable for the test server to exist at all, so the
		// guard is configured to permit it here and nowhere else.
		Guard: &SSRFGuard{AllowLoopback: true},
		// Loopback has to be reachable for the test server to exist at all.
		Timeout: 5 * time.Second,
		MaxRead: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDialTextSendsTheQueryAndReadsTheAnswer(t *testing.T) {
	srv := newEcho(t, "Domain Name: EXAMPLE.COM\r\nRegistrar: Test\r\n")
	d := newTCP(t, &dialScope{allowed: map[string]bool{srv.host(): true}})

	conn, err := d.DialText(context.Background(), srv.addr(), query("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	data, err := ReadAllConn(conn, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "EXAMPLE.COM") {
		t.Errorf("read %q", data)
	}
	if got := d.Stats().Dialed; got != 1 {
		t.Errorf("dialed = %d, want 1", got)
	}
}

func TestDialIsDeniedWithoutManifestDeclaration(t *testing.T) {
	// A module holding a raw socket could reach anything at all, so the scope check
	// has to be the same gate the HTTP path uses. An unwired dialer must not connect.
	srv := newEcho(t, "should never be read")
	d := newTCP(t, &dialScope{allowed: map[string]bool{}})

	if _, err := d.DialText(context.Background(), srv.addr(), query("example.com")); err == nil {
		t.Fatal("a denied host must not produce a connection")
	} else if !strings.Contains(err.Error(), "denied by scope") {
		t.Errorf("error = %v, want a scope denial", err)
	}
	if got := d.Stats().Dialed; got != 0 {
		t.Errorf("dialed = %d; nothing should have been connected", got)
	}
	if got := d.Stats().Denied; got != 1 {
		t.Errorf("denied = %d, want 1", got)
	}
}

func TestDialerWithoutAScopeCheckerFailsToBuild(t *testing.T) {
	// Failing closed at construction means no configuration can produce a dialer that
	// opens connections without asking anyone.
	if _, err := NewTCPDialer(TCPConfig{Module: "whois"}); err == nil {
		t.Error("a dialer with no scope checker must not be constructible")
	}
}

func TestDialerRequiresAModuleName(t *testing.T) {
	if _, err := NewTCPDialer(TCPConfig{Scope: &dialScope{}}); err == nil {
		t.Error("a dialer with no module name must not be constructible")
	}
}

func TestFloodingServerIsRefusedNotTruncated(t *testing.T) {
	// A WHOIS record with its contact block cut off is exactly the shape that invents
	// or loses data, so a response past the limit is an error rather than a short read.
	srv := &whoisEcho{ln: mustListen(t), flood: true}
	go srv.serve()
	t.Cleanup(func() { srv.ln.Close() })

	d := newTCP(t, &dialScope{allowed: map[string]bool{srv.host(): true}})

	conn, err := d.DialText(context.Background(), srv.addr(), query("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	data, err := ReadAllConn(conn, 16<<10)
	if err == nil {
		t.Fatalf("expected an error, got %d bytes", len(data))
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error = %v, want it to name the truncation", err)
	}
}

func TestReadLimitIsEnforcedPerConnection(t *testing.T) {
	srv := &whoisEcho{ln: mustListen(t), reply: strings.Repeat("A", 5000)}
	go srv.serve()
	t.Cleanup(func() { srv.ln.Close() })

	d := newTCP(t, &dialScope{allowed: map[string]bool{srv.host(): true}})
	conn, err := d.DialText(context.Background(), srv.addr(), query("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := ReadAllConn(conn, 1024); err == nil {
		t.Error("a 5000-byte response against a 1024-byte limit must fail")
	}
}

func TestAddressMustBeHostPort(t *testing.T) {
	d := newTCP(t, &dialScope{})
	for _, bad := range []string{"", "whois.example", "whois.example:", ":43", "host:notaport", "host:0", "host:99999"} {
		if _, err := d.DialText(context.Background(), bad, query("example.com")); err == nil {
			t.Errorf("DialText(%q) was accepted", bad)
		}
	}
}

func TestAddressHostIsNormalized(t *testing.T) {
	host, port, err := splitAddress("Whois.VERISIGN-Registrar.com:43")
	if err != nil {
		t.Fatal(err)
	}
	if host != "whois.verisign-registrar.com" {
		t.Errorf("host = %q, want lower case", host)
	}
	if port != 43 {
		t.Errorf("port = %d", port)
	}
}

func TestSSRFGuardBlocksPrivateAddresses(t *testing.T) {
	// The check runs inside the dialer rather than before it, so a resolvable name
	// cannot resolve differently between the check and the connect.
	d, err := NewTCPDialer(TCPConfig{
		Module:  "whois",
		Scope:   &dialScope{allowed: map[string]bool{"10.0.0.1": true}},
		Guard:   &SSRFGuard{},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialText(context.Background(), "10.0.0.1:43", query("example.com")); err == nil {
		t.Error("a private address was dialed despite the guard")
	}
}

func TestScopeCheckerIsAskedPerDial(t *testing.T) {
	srv := newEcho(t, "ok")
	scope := &dialScope{allowed: map[string]bool{srv.host(): true}}
	d := newTCP(t, scope)

	for i := 0; i < 3; i++ {
		conn, err := d.DialText(context.Background(), srv.addr(), query("example.com"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = ReadAllConn(conn, 1<<20)
		conn.Close()
	}
	if len(scope.calls) != 3 {
		t.Errorf("scope asked %d times, want 3: %v", len(scope.calls), scope.calls)
	}
}

// query builds an exchange description for the tests.
func query(q string) sdk.DialQuery { return sdk.DialQuery{Query: q} }

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
