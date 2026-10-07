package sdk

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Rate is a suggested rate hint for a host. The egress broker enforces its own
// configured limits; hints let it pick sane defaults for a host nobody has
// configured explicitly.
type Rate struct {
	Requests int
	Per      time.Duration
	Burst    int
}

// SecretSpec declares a secret a module needs. The secret reader hands back only
// what a manifest declares (least privilege, ADR-003).
type SecretSpec struct {
	Name     string
	Required bool
}

// Manifest is a module's self-declaration. It is validated at registration
// (argus modules doctor) and enforced by the orchestrator and policy engine.
//
// A module that understates Mode or Sensitivity is a bug, not a preference:
// sensitive modules must declare themselves so purpose binding and approval are
// enforced before any request leaves the machine.
type Manifest struct {
	Name        string
	Version     string
	Category    string
	Description string
	Consumes    []EntityType
	Produces    []EntityType
	Mode        Mode
	Sensitivity Sensitivity
	Secrets     []SecretSpec
	// EgressHosts is the enforced allow-list for this module. A module may reach a
	// host only if it appears here or was granted from a bootstrap document.
	EgressHosts []string
	// ReadsLocalFiles declares that this module reads files from disk and makes no
	// network request at all. It exists so an empty EgressHosts can be legitimate
	// rather than merely unexplained: without it, a metadata reader either lies about
	// hosts it never contacts or is reported as broken.
	ReadsLocalFiles bool

	// BootstrapHosts names URLs the broker may fetch in order to authorize further
	// hosts. A module that must discover its endpoints cannot enumerate them in a
	// static list without going stale, and simply trusting it to reach whatever it
	// likes would remove the boundary entirely.
	//
	// The grant is derived by the broker from the document it fetched, never asserted
	// by the module: a collector would have to forge the response of a host it was
	// already allowed to contact. The trust this places in a bootstrap host is the
	// whole content of the grant, so only declare a bootstrap you trust.
	BootstrapHosts []string
	RateHints      map[string]Rate // host -> suggested rate
	CostPerCall    float64         // USD estimate; 0 if free
	Tags           []string
}

// SecretNames lists declared secret names.
func (m Manifest) SecretNames() []string {
	out := make([]string, len(m.Secrets))
	for i, s := range m.Secrets {
		out[i] = s.Name
	}
	return out
}

// AllowsHost reports whether the manifest's egress allow-list permits host.
// An empty list means the module declares no egress requirement, which is only
// valid for purely local modules; the doctor flags that as suspicious.
func (m Manifest) AllowsHost(host string) bool {
	if len(m.EgressHosts) == 0 {
		return false
	}
	h := lowerASCII(host)
	for _, allowed := range m.EgressHosts {
		if h == lowerASCII(allowed) {
			return true
		}
		// Support "*.example.com" wildcards so a provider CDN can be declared
		// without enumerating hosts.
		if len(allowed) > 2 && allowed[0] == '*' && allowed[1] == '.' {
			if strings.HasSuffix(h, lowerASCII(allowed[1:])) {
				return true
			}
		}
	}
	return false
}

// Module is the collector contract. Implementations must be safe for concurrent
// use: one instance serves many tasks in parallel.
type Module interface {
	Manifest() Manifest
	Init(ctx context.Context, d Deps) error
	Run(ctx context.Context, t Task, e Emitter) error
	Close() error
}

// HTTPDoer is the egress-broker-backed HTTP client. Its Do method enforces
// scope, SSRF protection, rate limits, caching, circuit breaking, retry, and
// audit in one place. Modules must not construct their own clients.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DNSRecord is one resource record in presentation format.
type DNSRecord struct {
	Name string
	Type string // "A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", ...
	TTL  uint32
	Data string
	Pref uint16 // MX preference / SRV priority
}

// DNSResolver resolves names through the broker's resolver pool, which applies
// multi-resolver consensus and poisoning cross-checks.
type DNSResolver interface {
	Lookup(ctx context.Context, name, rrType string) ([]DNSRecord, error)
}

// Dialer opens a TCP connection through the broker.
//
// It exists because a collector must not be able to reach the network except
// through the same controls the HTTP path gets: the SSRF check at dial time, the
// rate limiter, the circuit breaker, the scope guard, and the audit log. WHOIS needs
// port 43 and a module holding its own net.Dialer would be the one component in the
// process with no such controls on it.
//
// The connection is deliberately text-oriented. Every protocol that needs raw TCP in
// this build is line-based, and exposing byte streams would mean every module
// reimplementing its own read deadlines and size bounds.
type Dialer interface {
	// DialText connects, optionally sends a query line, and returns a reader over the
	// response. Closing it releases the connection.
	DialText(ctx context.Context, address string, q DialQuery) (TextConn, error)
}

// DialQuery describes one line-oriented exchange.
type DialQuery struct {
	// Query is written immediately after the connection is established, with CRLF
	// appended. An empty Query reads without writing, for servers that greet first.
	Query string
	// MaxBytes bounds the response. Zero means the broker default.
	MaxBytes int64
	// Timeout bounds the whole exchange. Zero means the broker default.
	Timeout time.Duration
}

// TextConn is a brokered connection being read.
type TextConn interface {
	io.Reader
	Close() error
}

// Cache is a layered cache. Get returns false on miss. Implementations coalesce
// concurrent identical requests.
type Cache interface {
	Get(key string) (any, bool)
	Put(key string, val any, ttl time.Duration)
	Delete(key string)
}

// SecretReader returns only secrets declared in the manifest, and every call is
// audited. Values are redacted from logs, traces, and errors by a central
// redactor.
type SecretReader interface {
	Secret(ctx context.Context, name string) (string, error)
}

// BlobWriter stores an evidence artifact and returns its content-addressed
// reference.
type BlobWriter interface {
	Put(ctx context.Context, meta EvidenceMeta, raw []byte) (EvidenceRef, error)
}

// EvidenceMeta describes an artifact before it is stored.
type EvidenceMeta struct {
	Source     string // URL or API endpoint
	Method     string // "http.get", "api.shodan.host", "screenshot", "import"
	Collector  string // module@version
	MediaType  string
	CapturedAt time.Time
}

// Deps is the only way a module reaches the outside world. Everything here is
// brokered and audited.
type Deps struct {
	HTTP HTTPDoer
	DNS  DNSResolver
	// Dial opens brokered TCP connections. Nil for modules that do not need one, and
	// a module that needs it must fail Init rather than fall back to net.Dial, which
	// would be the only unmediated egress in the process.
	Dial    Dialer
	Cache   Cache
	Secrets SecretReader
	Blobs   BlobWriter
	Log     *slog.Logger
	Config  map[string]any
	Now     func() time.Time
	// InScope reports whether an entity may be investigated, with a human-readable
	// reason. A module that is about to contact an asset directly must ask first:
	// third-party data about an out-of-scope asset may be recorded, but the asset
	// itself may not be probed.
	InScope func(Entity) (bool, string)
}

// CanInvestigate is a convenience wrapper that treats a missing InScope checker as
// a denial. Failing closed is the only safe default: a module must never conclude
// "no guard configured, therefore allowed".
func (d Deps) CanInvestigate(e Entity) (bool, string) {
	if d.InScope == nil {
		return false, "no scope checker is available; refusing to treat the entity as in scope"
	}
	return d.InScope(e)
}

// Now returns the injected clock. Modules must use this rather than time.Now so
// that tests can be deterministic.
func (d Deps) NowTime() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Logger returns the injected logger, never nil. Named Logger (not Log) so it
// does not collide with the Log field of the same struct.
func (d Deps) Logger() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// Task is one unit of work assigned to a module.
type Task struct {
	ScanID   string
	CaseID   string
	Target   Entity
	Depth    int
	Params   map[string]string
	Deadline time.Time
}

// ParamFilePath names the task parameter carrying the filesystem path of a local file
// target.
//
// It exists because a file entity is content-addressed: the SDK's canonical identity
// for a file is the SHA-256 of its bytes, which is correct for deduplication and
// useless for opening the file. A metadata collector therefore cannot learn where to
// read from the target alone, and without a documented channel for it there is no way
// to write a local-file module at all.
//
// The path is a locator, not an identity. Two names for the same content are the same
// entity, and either path may be used to read it.
const ParamFilePath = "file.path"

// Param returns a task parameter, or def when absent.
func (t Task) Param(key, def string) string {
	if v, ok := t.Params[key]; ok {
		return v
	}
	return def
}

// ParamBool parses a boolean task parameter.
func (t Task) ParamBool(key string, def bool) bool {
	v, ok := t.Params[key]
	if !ok {
		return def
	}
	return v == "1" || v == "true" || v == "yes"
}

// Emitter is how a module reports findings and progress. Emit must be safe for
// concurrent use and must not be called after Run returns.
type Emitter interface {
	// Emit reports one finding. It returns an error when the scan is being
	// cancelled or the pipeline is shutting down, which modules must propagate.
	Emit(f Finding) error
	// PutEvidence stores a raw artifact and returns its content-addressed ref.
	PutEvidence(ctx context.Context, meta EvidenceMeta, raw []byte) (EvidenceRef, error)
	// Progress reports completion counters for user-facing feedback.
	Progress(done, total int)
	// Warn reports a non-fatal problem. Never include secrets or personal data.
	Warn(msg string, kv ...any)
}

// ModuleFunc adapts a plain function to the Module interface for tests and
// throwaway collectors.
type ModuleFunc struct {
	M     Manifest
	InitF func(ctx context.Context, d Deps) error
	RunF  func(ctx context.Context, t Task, e Emitter) error
}

func (m *ModuleFunc) Manifest() Manifest { return m.M }

func (m *ModuleFunc) Init(ctx context.Context, d Deps) error {
	if m.InitF == nil {
		return nil
	}
	return m.InitF(ctx, d)
}

func (m *ModuleFunc) Run(ctx context.Context, t Task, e Emitter) error {
	if m.RunF == nil {
		return nil
	}
	return m.RunF(ctx, t, e)
}

func (m *ModuleFunc) Close() error { return nil }

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
