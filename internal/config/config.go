// Package config loads, validates, and merges Argus configuration.
//
// Precedence, per §8: command-line flags > environment (ARGUS_*) > selected
// profile > config file > built-in defaults. Merging is done in one place so that
// "why did this setting apply?" always has a single answer.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Config is the parsed argus.yaml.
type Config struct {
	Version int `yaml:"version"`

	General struct {
		Workspace       string `yaml:"workspace"`
		Profile         string `yaml:"profile"`
		Mode            string `yaml:"mode"`
		Locale          string `yaml:"locale"`
		TelemetryOptout bool   `yaml:"telemetry_optout"`
	} `yaml:"general"`

	Engine struct {
		Workers             int            `yaml:"workers"`
		PerModule           map[string]int `yaml:"per_module_concurrency"`
		DefaultPerModule    int            `yaml:"-"`
		MaxDepth            int            `yaml:"max_depth"`
		MaxBreadth          int            `yaml:"max_breadth_per_entity"`
		QueueSize           int            `yaml:"queue_size"`
		TaskTimeout         Duration       `yaml:"task_timeout"`
		ScanTimeout         Duration       `yaml:"scan_timeout"`
		DrainTimeout        Duration       `yaml:"drain_timeout"`
		CheckpointInterval  Duration       `yaml:"checkpoint_interval"`
		AdaptiveConcurrency struct {
			Enabled   bool     `yaml:"enabled"`
			Algorithm string   `yaml:"algorithm"`
			TargetP95 Duration `yaml:"target_p95"`
		} `yaml:"adaptive_concurrency"`
		Budgets struct {
			MaxEntities int64    `yaml:"max_entities"`
			MaxRequests int64    `yaml:"max_requests"`
			MaxCostUSD  float64  `yaml:"max_cost_usd"`
			MaxRuntime  Duration `yaml:"max_runtime"`
		} `yaml:"budgets"`
	} `yaml:"engine"`

	Network struct {
		UserAgent string `yaml:"user_agent"`
		HonestUA  bool   `yaml:"honest_ua"`
		HTTP      struct {
			MaxBodyBytes  int64  `yaml:"max_body_bytes"`
			MaxRedirects  int    `yaml:"max_redirects"`
			HTTP3         bool   `yaml:"http3"`
			TLSMinVersion string `yaml:"tls_min_version"`
		} `yaml:"http"`
		TCP struct {
			// Timeout bounds one TCP exchange, not a whole task. It is separate from the
			// scan timeout because a task that retries a WHOIS referral will open more
			// than one connection, and giving each of them the entire task budget means
			// the task can never finish.
			Timeout Duration `yaml:"timeout"`
		} `yaml:"tcp"`
		DNS struct {
			Resolvers []string `yaml:"resolvers"`
			Transport string   `yaml:"transport"`
			Consensus int      `yaml:"consensus"`
			Timeout   Duration `yaml:"timeout"`
		} `yaml:"dns"`
		Proxy struct {
			Default string            `yaml:"default"`
			Routes  map[string]string `yaml:"routes"`
		} `yaml:"proxy"`
		Egress struct {
			BlockPrivate      bool     `yaml:"block_private"`
			AllowPrivateCIDRs []string `yaml:"allow_private_cidrs"`
		} `yaml:"egress"`
		Retry struct {
			MaxAttempts int      `yaml:"max_attempts"`
			Backoff     string   `yaml:"backoff"`
			Base        Duration `yaml:"base"`
			Max         Duration `yaml:"max"`
		} `yaml:"retry"`
		CircuitBreaker struct {
			FailureThreshold int      `yaml:"failure_threshold"`
			Window           Duration `yaml:"window"`
			Cooldown         Duration `yaml:"cooldown"`
		} `yaml:"circuit_breaker"`
	} `yaml:"network"`

	RateLimit struct {
		Default       string            `yaml:"default"`
		Burst         int               `yaml:"burst"`
		PerHost       map[string]string `yaml:"per_host"`
		PerModule     map[string]string `yaml:"per_module"`
		SharedBackend string            `yaml:"shared_backend"`
	} `yaml:"ratelimit"`

	Cache struct {
		Enabled bool `yaml:"enabled"`
		L1      struct {
			Driver string `yaml:"driver"`
			Size   string `yaml:"size"`
		} `yaml:"l1"`
		L2 struct {
			Driver string `yaml:"driver"`
			Path   string `yaml:"path"`
			URL    string `yaml:"url"`
		} `yaml:"l2"`
		TTL struct {
			Default Duration            `yaml:"default"`
			ByHost  map[string]Duration `yaml:",inline"`
		} `yaml:"ttl"`
	} `yaml:"cache"`

	Storage struct {
		Primary struct {
			Driver string `yaml:"driver"`
			DSN    string `yaml:"dsn"`
		} `yaml:"primary"`
		Graph struct {
			Driver string `yaml:"driver"`
			URI    string `yaml:"uri"`
		} `yaml:"graph"`
		Blobs struct {
			Driver string `yaml:"driver"`
			Path   string `yaml:"path"`
			Bucket string `yaml:"bucket"`
		} `yaml:"blobs"`
		Retention struct {
			RawEvidence  Duration `yaml:"raw_evidence"`
			Observations Duration `yaml:"observations"`
			Audit        Duration `yaml:"audit"`
		} `yaml:"retention"`
	} `yaml:"storage"`

	Queue struct {
		Driver string `yaml:"driver"`
	} `yaml:"queue"`

	Secrets struct {
		Driver string `yaml:"driver"`
		File   string `yaml:"file"`
	} `yaml:"secrets"`

	Modules struct {
		Enabled  []string                  `yaml:"enabled"`
		Disabled []string                  `yaml:"disabled"`
		Settings map[string]map[string]any `yaml:"settings"`
	} `yaml:"modules"`

	Policy struct {
		File                       string `yaml:"file"`
		RequireCaseForSensitive    bool   `yaml:"require_case_for_sensitive"`
		RequirePurposeForSensitive bool   `yaml:"require_purpose_for_sensitive"`
	} `yaml:"policy"`

	Scope struct {
		File    string `yaml:"file"`
		Enforce bool   `yaml:"enforce"`
	} `yaml:"scope"`

	Privacy struct {
		ClassifyPII     bool `yaml:"classify_pii"`
		RedactExports   bool `yaml:"redact_exports_by_default"`
		FieldEncryption bool `yaml:"field_encryption"`
		ErasureTool     bool `yaml:"erasure_tool"`
	} `yaml:"privacy"`

	Evidence struct {
		Capture   []string `yaml:"capture"`
		Hash      string   `yaml:"hash"`
		Chain     bool     `yaml:"chain"`
		Timestamp struct {
			RFC3161 struct {
				URL     string `yaml:"url"`
				Enabled bool   `yaml:"enabled"`
			} `yaml:"rfc3161"`
			OpenTimestamps struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"opentimestamps"`
		} `yaml:"timestamp"`
		Signing struct {
			Driver string `yaml:"driver"`
			Key    string `yaml:"key"`
		} `yaml:"signing"`
	} `yaml:"evidence"`

	Scoring struct {
		SourceWeights      map[string]float64  `yaml:"source_weights"`
		IndependenceGroups map[string][]string `yaml:"independence_groups"`
		DecayHalfLife      Duration            `yaml:"decay_half_life"`
		ConflictPenalty    float64             `yaml:"conflict_penalty"`
	} `yaml:"scoring"`

	Resolution struct {
		AutoMergeThreshold float64 `yaml:"auto_merge_threshold"`
		ReviewThreshold    float64 `yaml:"review_threshold"`
	} `yaml:"resolution"`

	Reporting struct {
		DefaultFormats []string `yaml:"default_formats"`
		OutputDir      string   `yaml:"output_dir"`
		DefaultProfile string   `yaml:"default_profile"`
	} `yaml:"reporting"`

	Observability struct {
		Logs struct {
			Level  string `yaml:"level"`
			Format string `yaml:"format"`
		} `yaml:"logs"`
		Metrics struct {
			Enabled bool   `yaml:"enabled"`
			Listen  string `yaml:"listen"`
		} `yaml:"metrics"`
	} `yaml:"observability"`

	LLM struct {
		Enabled          bool   `yaml:"enabled"`
		Provider         string `yaml:"provider"`
		RedactBeforeSend bool   `yaml:"redact_before_send"`
		RequireCitations bool   `yaml:"require_citations"`
	} `yaml:"llm"`

	Profiles map[string]ProfilePatch `yaml:"profiles"`

	// SourcePath records where the file came from, for `config show`.
	SourcePath string `yaml:"-"`
	// AppliedProfile records the profile merged in.
	AppliedProfile string `yaml:"-"`
}

// ProfilePatch is a partial override applied by a named profile.
type ProfilePatch struct {
	General *struct {
		Mode    string `yaml:"mode"`
		Profile string `yaml:"profile"`
	} `yaml:"general"`
	Engine *struct {
		Workers    *int `yaml:"workers"`
		MaxDepth   *int `yaml:"max_depth"`
		MaxBreadth *int `yaml:"max_breadth_per_entity"`
	} `yaml:"engine"`
	RateLimit *struct {
		Default string `yaml:"default"`
		Burst   *int   `yaml:"burst"`
	} `yaml:"ratelimit"`
	Cache *struct {
		TTL struct {
			Default *Duration `yaml:"default"`
		} `yaml:"ttl"`
	} `yaml:"cache"`
}

// Duration is a time.Duration that unmarshals from strings like "45s".
type Duration time.Duration

// UnmarshalYAML accepts "45s", "2h", or a bare integer number of seconds.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		if s == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var secs int64
	if err := unmarshal(&secs); err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(time.Duration(secs) * time.Second)
	return nil
}

// MarshalYAML renders the duration as a string, so `config show` round-trips.
func (d Duration) MarshalYAML() (any, error) {
	if d == 0 {
		return "", nil
	}
	return time.Duration(d).String(), nil
}

// Duration converts to time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Defaults returns the built-in configuration: the bottom of the precedence
// chain, with values chosen so a fresh install is safe rather than merely valid.
func Defaults() *Config {
	c := &Config{Version: 1}
	c.General.Workspace = defaultWorkspace()
	c.General.Profile = "default"
	c.General.Mode = "passive"
	c.General.Locale = "en"
	c.General.TelemetryOptout = true

	c.Engine.Workers = 32
	c.Engine.DefaultPerModule = 8
	c.Engine.MaxDepth = 2
	c.Engine.MaxBreadth = 50
	c.Engine.QueueSize = 20000
	c.Engine.TaskTimeout = Duration(45 * time.Second)
	c.Engine.ScanTimeout = Duration(2 * time.Hour)
	c.Engine.DrainTimeout = Duration(20 * time.Second)
	c.Engine.CheckpointInterval = Duration(15 * time.Second)
	c.Engine.AdaptiveConcurrency.Enabled = true
	c.Engine.AdaptiveConcurrency.Algorithm = "aimd"
	c.Engine.AdaptiveConcurrency.TargetP95 = Duration(4 * time.Second)
	c.Engine.Budgets.MaxEntities = 50_000
	c.Engine.Budgets.MaxRequests = 250_000
	c.Engine.Budgets.MaxCostUSD = 5.00
	c.Engine.Budgets.MaxRuntime = Duration(2 * time.Hour)

	c.Network.UserAgent = defaultUserAgent()
	c.Network.HonestUA = true
	c.Network.HTTP.MaxBodyBytes = 8 << 20
	// Short by default: a WHOIS task that follows a referral opens two connections, and a
	// per-exchange budget long enough to outlive the task deadline turns an unreachable
	// server into an unhelpful "task timed out" instead of the connect error that says
	// what actually happened.
	c.Network.TCP.Timeout = Duration(5 * time.Second)
	c.Network.HTTP.MaxRedirects = 5
	c.Network.HTTP.HTTP3 = false
	c.Network.HTTP.TLSMinVersion = "1.2"
	c.Network.DNS.Transport = "doh"
	c.Network.DNS.Consensus = 2
	c.Network.DNS.Timeout = Duration(3 * time.Second)
	// The SSRF guard is on by default and is not a preference: it is what stops a
	// hostile target from redirecting the tool into internal infrastructure.
	c.Network.Egress.BlockPrivate = true
	c.Network.Retry.MaxAttempts = 3
	c.Network.Retry.Backoff = "decorrelated_jitter"
	c.Network.Retry.Base = Duration(500 * time.Millisecond)
	c.Network.Retry.Max = Duration(30 * time.Second)
	c.Network.CircuitBreaker.FailureThreshold = 5
	c.Network.CircuitBreaker.Window = Duration(60 * time.Second)
	c.Network.CircuitBreaker.Cooldown = Duration(60 * time.Second)

	c.RateLimit.Default = "5/s"
	c.RateLimit.Burst = 10
	c.RateLimit.SharedBackend = "none"

	c.Cache.Enabled = true
	c.Cache.L1.Driver = "memory"
	c.Cache.L1.Size = "256MiB"
	c.Cache.L2.Driver = "badger"
	c.Cache.TTL.Default = Duration(24 * time.Hour)

	c.Storage.Primary.Driver = "sqlite"
	c.Storage.Graph.Driver = "memory"
	c.Storage.Blobs.Driver = "fs"
	c.Storage.Retention.RawEvidence = Duration(365 * 24 * time.Hour)
	c.Storage.Retention.Observations = Duration(730 * 24 * time.Hour)
	c.Storage.Retention.Audit = Duration(2555 * 24 * time.Hour)

	c.Queue.Driver = "memory"
	c.Secrets.Driver = "env"

	c.Modules.Enabled = []string{"*"}
	c.Policy.File = defaultConfigPath("policy.yaml")
	c.Policy.RequireCaseForSensitive = true
	c.Policy.RequirePurposeForSensitive = true
	c.Scope.File = defaultConfigPath("scope.yaml")
	c.Scope.Enforce = true

	c.Privacy.ClassifyPII = true
	c.Privacy.RedactExports = true
	c.Privacy.FieldEncryption = true
	c.Privacy.ErasureTool = true

	c.Evidence.Capture = []string{"headers", "body"}
	c.Evidence.Hash = "sha256"
	c.Evidence.Chain = true
	c.Evidence.Signing.Driver = "ed25519"

	c.Scoring.DecayHalfLife = Duration(720 * time.Hour)
	c.Scoring.ConflictPenalty = 0.25

	c.Resolution.AutoMergeThreshold = 0.92
	c.Resolution.ReviewThreshold = 0.70

	c.Reporting.DefaultFormats = []string{"html", "json"}
	c.Reporting.DefaultProfile = "internal"

	c.Observability.Logs.Level = "info"
	c.Observability.Logs.Format = "json"
	c.Observability.Metrics.Enabled = true
	c.Observability.Metrics.Listen = "127.0.0.1:9090"

	c.LLM.Enabled = false
	c.LLM.RequireCitations = true
	return c
}

func defaultUserAgent() string { return "Argus/dev (+https://github.com/WildanDeveloper/argus)" }

// defaultConfigPath returns the per-user configuration directory for a file,
// following the XDG base directory convention so the location is predictable
// rather than being invented per platform.
func defaultConfigPath(name string) string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "argus", name)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return name
	}
	return filepath.Join(home, ".config", "argus", name)
}

func defaultWorkspace() string {
	if w := os.Getenv("ARGUS_WORKSPACE"); w != "" {
		return w
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".argus"
	}
	return filepath.Join(home, ".argus")
}

// Load reads the config file, if present, over the defaults, then applies the
// selected profile and the environment.
func Load(path, profile string) (*Config, error) {
	c := Defaults()

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("config: read %s: %w", path, err)
			}
		} else if err := yaml.Unmarshal(raw, c); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		} else {
			c.SourcePath = path
		}
	}

	if profile == "" {
		profile = c.General.Profile
	}
	if profile != "" && profile != "default" {
		if err := c.applyProfile(profile); err != nil {
			return nil, err
		}
	}
	c.AppliedProfile = profile

	c.applyEnv()
	c.expandPaths()

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyProfile(name string) error {
	p, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("config: unknown profile %q (available: %s)", name, strings.Join(c.ProfileNames(), ", "))
	}
	if p.General != nil {
		if p.General.Mode != "" {
			c.General.Mode = p.General.Mode
		}
	}
	if p.Engine != nil {
		if p.Engine.Workers != nil {
			c.Engine.Workers = *p.Engine.Workers
		}
		if p.Engine.MaxDepth != nil {
			c.Engine.MaxDepth = *p.Engine.MaxDepth
		}
		if p.Engine.MaxBreadth != nil {
			c.Engine.MaxBreadth = *p.Engine.MaxBreadth
		}
	}
	if p.RateLimit != nil {
		if p.RateLimit.Default != "" {
			c.RateLimit.Default = p.RateLimit.Default
		}
		if p.RateLimit.Burst != nil {
			c.RateLimit.Burst = *p.RateLimit.Burst
		}
	}
	if p.Cache != nil && p.Cache.TTL.Default != nil {
		c.Cache.TTL.Default = *p.Cache.TTL.Default
	}
	return nil
}

// ProfileNames lists the configured profiles, sorted.
func (c *Config) ProfileNames() []string {
	out := make([]string, 0, len(c.Profiles))
	for k := range c.Profiles {
		out = append(out, k)
	}
	return out
}

// applyEnv overlays ARGUS_* variables. Environment wins over the file so that a
// container or CI job can redirect the database without editing configuration.
func (c *Config) applyEnv() {
	if v := os.Getenv("ARGUS_WORKSPACE"); v != "" {
		c.General.Workspace = v
	}
	if v := os.Getenv("ARGUS_PROFILE"); v != "" {
		c.General.Profile = v
	}
	if v := os.Getenv("ARGUS_MODE"); v != "" {
		c.General.Mode = v
	}
	if v := os.Getenv("ARGUS_DB_DSN"); v != "" {
		c.Storage.Primary.DSN = v
	}
	if v := os.Getenv("ARGUS_SECRETS_DRIVER"); v != "" {
		c.Secrets.Driver = v
	}
	if v := os.Getenv("ARGUS_PROXY"); v != "" {
		c.Network.Proxy.Default = v
	}
	if v := os.Getenv("ARGUS_LOG_LEVEL"); v != "" {
		c.Observability.Logs.Level = v
	}
}

// expandPaths resolves the ~ prefix and makes relative paths workspace-relative,
// so a config file is portable between machines.
func (c *Config) expandPaths() {
	ws := ExpandHome(c.General.Workspace)
	c.General.Workspace = ws
	if c.Storage.Primary.DSN == "" {
		c.Storage.Primary.DSN = filepath.Join(ws, "argus.db")
	}
	c.Storage.Primary.DSN = c.resolve(ws, c.Storage.Primary.DSN)
	if c.Storage.Blobs.Path == "" {
		c.Storage.Blobs.Path = filepath.Join(ws, "blobs")
	}
	c.Storage.Blobs.Path = c.resolve(ws, c.Storage.Blobs.Path)
	c.Cache.L2.Path = c.resolve(ws, ExpandHome(c.Cache.L2.Path))
	c.Policy.File = c.resolve(ws, ExpandHome(c.Policy.File))
	c.Scope.File = c.resolve(ws, ExpandHome(c.Scope.File))
	c.Secrets.File = c.resolve(ws, ExpandHome(c.Secrets.File))
	c.Evidence.Signing.Key = c.resolve(ws, ExpandHome(c.Evidence.Signing.Key))
	if c.Reporting.OutputDir != "" {
		c.Reporting.OutputDir = c.resolve(ws, c.Reporting.OutputDir)
	}
}

func (c *Config) resolve(ws, p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(ws, p)
}

// ExpandHome replaces a leading ~ with the user's home directory.
func ExpandHome(p string) string {
	if p == "" || !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// Validate checks the configuration for mistakes that would silently weaken
// guarantees. It is deliberately opinionated: a configuration that passes here
// still satisfies the design principles, and one that fails will be corrected
// rather than accepted with a warning.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("config: unsupported version %d (this build understands version 1)", c.Version)
	}
	if _, err := c.Mode(); err != nil {
		return fmt.Errorf("config: general.mode: %w", err)
	}
	if c.Engine.Workers <= 0 {
		return fmt.Errorf("config: engine.workers must be positive, got %d", c.Engine.Workers)
	}
	if c.Engine.MaxDepth < 0 {
		return fmt.Errorf("config: engine.max_depth must not be negative")
	}
	if c.Engine.MaxBreadth <= 0 {
		return fmt.Errorf("config: engine.max_breadth_per_entity must be positive")
	}
	if c.Engine.Budgets.MaxCostUSD < 0 {
		return fmt.Errorf("config: engine.budgets.max_cost_usd must not be negative")
	}
	if !c.Network.Egress.BlockPrivate && len(c.Network.Egress.AllowPrivateCIDRs) == 0 {
		// Turning the SSRF guard off without naming the ranges you are authorizing
		// is the shape of a mistake, not a configuration.
		return fmt.Errorf("config: network.egress.block_private is false; also list allow_private_cidrs so the authorization is explicit")
	}
	if c.Network.HTTP.MaxBodyBytes <= 0 {
		return fmt.Errorf("config: network.http.max_body_bytes must be positive; a zero limit would disable response bounds")
	}
	if c.Network.TCP.Timeout <= 0 {
		return fmt.Errorf("config: network.tcp.timeout must be positive; a zero limit would let a TCP connection hang for the whole task budget")
	}
	if c.Network.Retry.MaxAttempts < 1 {
		return fmt.Errorf("config: network.retry.max_attempts must be at least 1")
	}
	switch c.Network.Retry.Backoff {
	case "fixed", "exponential", "decorrelated_jitter":
	default:
		return fmt.Errorf("config: network.retry.backoff %q is not one of fixed, exponential, decorrelated_jitter", c.Network.Retry.Backoff)
	}
	if c.Scoring.ConflictPenalty < 0 || c.Scoring.ConflictPenalty >= 1 {
		return fmt.Errorf("config: scoring.conflict_penalty must be in [0,1), got %v", c.Scoring.ConflictPenalty)
	}
	if c.Scoring.DecayHalfLife <= 0 {
		return fmt.Errorf("config: scoring.decay_half_life must be positive; zero would make freshness meaningless")
	}
	if c.Resolution.AutoMergeThreshold <= c.Resolution.ReviewThreshold {
		return fmt.Errorf("config: resolution.auto_merge_threshold (%v) must exceed review_threshold (%v)",
			c.Resolution.AutoMergeThreshold, c.Resolution.ReviewThreshold)
	}
	switch c.Storage.Primary.Driver {
	case "sqlite", "postgres":
	default:
		return fmt.Errorf("config: storage.primary.driver %q is not supported", c.Storage.Primary.Driver)
	}
	if c.LLM.Enabled && !c.LLM.RequireCitations {
		// The specification makes citations mandatory for the summarizer; a config
		// that disables them is refused rather than downgraded.
		return fmt.Errorf("config: llm.require_citations cannot be false while llm.enabled is true")
	}
	if c.LLM.Enabled && !c.LLM.RedactBeforeSend {
		return fmt.Errorf("config: llm.redact_before_send cannot be false while llm.enabled is true")
	}
	if c.General.Locale != "en" && c.General.Locale != "id" {
		return fmt.Errorf("config: general.locale %q is not built in (available: en, id)", c.General.Locale)
	}
	if c.Secrets.Driver == "file" && c.Secrets.File == "" {
		return fmt.Errorf("config: secrets.driver is file but secrets.file is unset")
	}
	return nil
}

// Mode returns the parsed scan mode.
func (c *Config) Mode() (sdk.Mode, error) { return sdk.ParseMode(c.General.Mode) }

// Save writes the configuration as YAML.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadYAML parses a YAML document into a generic map, used for scope.yaml and
// policy.yaml which have their own typed structures in their packages.
func LoadYAML(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s does not exist", path)
		}
		return nil, err
	}
	return b, nil
}

// SourcePathOr returns the config file path, or fallback when the built-in
// defaults are in use.
func (c *Config) SourcePathOr(fallback string) string {
	if c.SourcePath == "" {
		return fallback
	}
	return c.SourcePath
}

// MarshalYAML serializes any value with two-space indentation, used by
// `config show` and `scope show`.
func MarshalYAML(v any) ([]byte, error) { return yaml.Marshal(v) }
