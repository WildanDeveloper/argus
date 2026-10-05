package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGrantDerivesHostsFromBootstrap(t *testing.T) {
	g := NewBootstrapGrant()
	doc := `{"services": [ [ ["com"], ["https://rdap.verisign.example/v1/"] ] ]}`
	added := g.Absorb("rdap", []byte(doc))
	if len(added) != 1 || added[0] != "rdap.verisign.example" {
		t.Fatalf("added = %v", added)
	}
	if !g.Allows("rdap", "rdap.verisign.example") {
		t.Error("granted host is not permitted")
	}
}

func TestGrantIsPerModule(t *testing.T) {
	// One collector's bootstrap must never widen another's reach. Without this, any
	// module could authorize a host for every other module.
	g := NewBootstrapGrant()
	g.Absorb("rdap", []byte(`{"services":[[["com"],["https://granted.example/"]]]}`))

	if g.Allows("dns-records", "granted.example") {
		t.Error("a host granted to rdap was also permitted for dns-records")
	}
	if !g.Allows("rdap", "granted.example") {
		t.Error("the grant should still apply to its own module")
	}
	if got := g.Hosts("dns-records"); len(got) != 0 {
		t.Errorf("dns-records sees granted hosts %v", got)
	}
}

func TestGrantRefusesPlaintext(t *testing.T) {
	// An on-path attacker could forge an http endpoint's answer, and this module's
	// whole purpose is to treat registry answers as authoritative. Only https is taken.
	g := NewBootstrapGrant()
	g.Absorb("m", []byte(`{"services":[[["com"],["http://plaintext.example/","https://secure.example/"]]]}`))

	if g.Allows("m", "plaintext.example") {
		t.Error("an http endpoint was granted")
	}
	if !g.Allows("m", "secure.example") {
		t.Error("the https endpoint should be granted")
	}
}

func TestGrantRefusesInternalHosts(t *testing.T) {
	// A document naming a private or metadata endpoint must not be able to steer
	// egress there, even though the SSRF guard would catch it later.
	g := NewBootstrapGrant()
	doc := `{"services":[[["x"],[
	  "https://127.0.0.1/",
	  "https://169.254.169.254/",
	  "https://localhost/",
	  "https://10.0.0.5/",
	  "https://metadata.google.internal/",
	  "https://[::1]/"
	]]]}`
	g.Absorb("m", []byte(doc))
	if hosts := g.Hosts("m"); len(hosts) != 0 {
		t.Errorf("internal hosts were granted: %v", hosts)
	}
}

func TestGrantIgnoresGarbage(t *testing.T) {
	// A document that does not parse grants nothing rather than something
	// surprising. Note that a bare JSON array naming an https URL *would* grant,
	// because the walk is deliberately liberal about structure: only the broker can
	// call this, and only for a host the module already declared.
	g := NewBootstrapGrant()
	for _, doc := range []string{``, `not json`, `{`, `{"services":null}`} {
		g.Absorb("m", []byte(doc))
	}
	if hosts := g.Hosts("m"); len(hosts) != 0 {
		t.Errorf("garbage granted hosts: %v", hosts)
	}
}

func TestGrantIsBounded(t *testing.T) {
	// A hostile or broken document must not grow the allow-list without limit.
	g := &BootstrapGrant{granted: map[string]map[string]bool{}, maxHosts: 5}
	var b strings.Builder
	b.WriteString(`{"urls":[`)
	for i := 0; i < 500; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"https://h`)
		b.WriteString(strings.Repeat("x", i%7+1))
		b.WriteString(itoaHost(i))
		b.WriteString(`.example/"`)
	}
	b.WriteString(`]}`)

	added := g.Absorb("m", []byte(b.String()))
	if len(added) != 5 {
		t.Errorf("granted %d hosts, want the cap of 5", len(added))
	}
}

func itoaHost(i int) string {
	if i == 0 {
		return ""
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}

func TestGrantCoversNestedShapes(t *testing.T) {
	// The parser walks generically rather than assuming the published structure, so a
	// future reordering by IANA does not silently stop the module from working.
	g := NewBootstrapGrant()
	g.Absorb("m", []byte(`{"a":{"b":[["https://deep.example/x"]]},"c":["https://other.example/"]}`))
	for _, h := range []string{"deep.example", "other.example"} {
		if !g.Allows("m", h) {
			t.Errorf("nested https URL %s was not granted", h)
		}
	}
}

// --- end-to-end through the broker ---

type grantScope struct {
	mu     sync.Mutex
	calls  []string
	grant  *BootstrapGrant
	module string
}

func (g *grantScope) CheckEgress(_ context.Context, u *neturl.URL, module string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, u.Hostname())
	return nil
}

func TestBrokerGrantsHostsOnlyFromADeclaredBootstrap(t *testing.T) {
	// The mechanism must require the bootstrap to be declared. A module that merely
	// fetches a JSON document naming URLs gains nothing.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bootstrap.json":
			w.Write([]byte(`{"services":[[["com"],["https://discovered.example/v1/"]]]}`))
		case "/notbootstrap.json":
			w.Write([]byte(`{"services":[[["com"],["https://sneaky.example/"]]]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	grant := NewBootstrapGrant()
	lim, _ := ParseRate("1000/s")
	c, err := NewClient(ClientConfig{
		Module:          "rdap",
		AllowLoopback:   true,
		AllowExtraCIDRs: []string{"127.0.0.0/8"},
		Timeout:         5 * time.Second,
		BootstrapHosts:  []string{srv.URL + "/bootstrap.json"},
		Grant:           grant,
	},
		nil, NewRateLimiter(lim, 10, nil, nil),
		NewBreaker(DefaultBreakerSettings()),
		NewRetryer(RetryConfig{MaxAttempts: 1}),
		nil, nil, &grantScope{})
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
	}

	get("/bootstrap.json")
	if !grant.Allows("rdap", "discovered.example") {
		t.Error("the declared bootstrap did not grant the host it named")
	}

	// A document served from the same host but a different path grants nothing, even
	// though it has exactly the same shape. Matching the host alone would let any
	// JSON on a registry host hand the module a grant.
	get("/notbootstrap.json")
	if grant.Allows("rdap", "sneaky.example") {
		t.Error("a non-bootstrap path granted a host; the grant is not tied to the declared URL")
	}
}

func TestNoGrantWithoutBootstrapDeclaration(t *testing.T) {
	// A client with no BootstrapHosts must never grant, whatever it fetches.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"services":[[["com"],["https://discovered.example/"]]]}`))
	}))
	defer srv.Close()

	grant := NewBootstrapGrant()
	lim, _ := ParseRate("1000/s")
	c, err := NewClient(ClientConfig{
		Module: "m", AllowLoopback: true, AllowExtraCIDRs: []string{"127.0.0.0/8"},
		Timeout: 5 * time.Second, Grant: grant,
	}, nil, NewRateLimiter(lim, 10, nil, nil), NewBreaker(DefaultBreakerSettings()),
		NewRetryer(RetryConfig{MaxAttempts: 1}), nil, nil, &grantScope{})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/x.json", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if hosts := grant.Hosts("m"); len(hosts) != 0 {
		t.Errorf("hosts granted without a BootstrapHosts declaration: %v", hosts)
	}
}

func TestNilGrantIsSafe(t *testing.T) {
	// BootstrapHosts declared but no grant table must not panic.
	g := NewBootstrapGrant()
	added := g.Absorb("m", []byte(`{"services":[[["com"],["https://a.example/"]]]}`))
	if len(added) != 1 {
		t.Errorf("added = %v", added)
	}
	var nilGrant *BootstrapGrant
	if nilGrant.Allows("m", "a.example") {
		t.Error("a nil grant permitted a host")
	}
	if hosts := nilGrant.Hosts("m"); len(hosts) != 0 {
		t.Errorf("a nil grant reported hosts %v", hosts)
	}
	nilGrant.Absorb("m", []byte(`{"services":[[["com"],["https://a.example/"]]]}`))
}
