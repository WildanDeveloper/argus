// Package policy implements scope-as-code and the policy engine.
//
// The scope guard is the component that makes "fail closed" real: no packet
// leaves the machine without passing Check, and Check denies by default. A
// bug elsewhere in Argus that bypasses the guard still produces no traffic,
// because the guard sits on the single egress path rather than in the callers.
package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// RuleOfEngagement limits what an engagement may do, agreed with the asset
// owner up front. These are hard ceilings: configuration cannot raise them.
type RulesOfEngagement struct {
	MaxRequestRate  string           `yaml:"max_request_rate"`
	BlackoutWindows []BlackoutWindow `yaml:"blackout_windows"`
}

// BlackoutWindow is a recurring period during which no request may be sent.
type BlackoutWindow struct {
	Cron   string `yaml:"cron"`
	TZ     string `yaml:"tz"`
	Reason string `yaml:"reason"`
}

// Authorization records the permission the scan relies on. Without it, active
// modes are refused outright.
type Authorization struct {
	EngagementID      string            `yaml:"engagement_id"`
	AuthorizedBy      string            `yaml:"authorized_by"`
	Contact           string            `yaml:"contact"`
	ValidFrom         time.Time         `yaml:"valid_from"`
	ValidUntil        time.Time         `yaml:"valid_until"`
	AllowedModes      []string          `yaml:"allowed_modes"`
	RulesOfEngagement RulesOfEngagement `yaml:"rules_of_engagement"`
}

// Allows reports whether the authorization is valid at time t and permits mode.
//
// Passive collection queries third-party datasets and never touches the
// target's infrastructure, so it needs no engagement record — it is the
// default posture and gating it would just teach operators to disable the gate.
// Semi-active and active both contact the target, so they require written
// authorization.
func (a Authorization) Allows(mode sdk.Mode, t time.Time) (bool, string) {
	if mode == sdk.ModePassive {
		// Passive still respects an explicit validity window. An operator who
		// wrote valid_from/valid_until stated the engagement period; work outside
		// it is outside the engagement, and treating the window as advisory would
		// turn a forgotten scope file into a permanent licence.
		if !a.ValidFrom.IsZero() && t.Before(a.ValidFrom) {
			return false, fmt.Sprintf("engagement %s does not begin until %s", orUnknown(a.EngagementID), a.ValidFrom.Format(time.RFC3339))
		}
		if !a.ValidUntil.IsZero() && t.After(a.ValidUntil) {
			return false, fmt.Sprintf("engagement %s expired at %s", orUnknown(a.EngagementID), a.ValidUntil.Format(time.RFC3339))
		}
		return true, ""
	}
	if a.EngagementID == "" {
		return false, "scope.yaml has no authorization.engagement_id; " + mode.String() + " work contacts the target and needs written permission"
	}
	if a.AuthorizedBy == "" {
		return false, "scope.yaml has no authorization.authorized_by"
	}
	if !a.ValidFrom.IsZero() && t.Before(a.ValidFrom) {
		return false, fmt.Sprintf("authorization is not valid until %s", a.ValidFrom.Format(time.RFC3339))
	}
	if !a.ValidUntil.IsZero() && t.After(a.ValidUntil) {
		return false, fmt.Sprintf("authorization expired at %s", a.ValidUntil.Format(time.RFC3339))
	}
	if len(a.AllowedModes) == 0 {
		// An empty allow list means "nothing beyond passive", not "anything".
		return false, "authorization.allowed_modes is empty; it must name " + mode.String() + " explicitly"
	}
	for _, m := range a.AllowedModes {
		parsed, err := sdk.ParseMode(strings.TrimSpace(m))
		if err != nil {
			continue
		}
		if mode <= parsed {
			return true, ""
		}
	}
	return false, "authorization.allowed_modes does not include " + mode.String()
}

// ActivePermitted reports whether written permission exists for active probing.
// ADR-007 and §2 require both the scope authorization and an explicit
// --allow-active flag; this method covers the first half.
func (a Authorization) ActivePermitted() bool {
	for _, m := range a.AllowedModes {
		if p, err := sdk.ParseMode(strings.TrimSpace(m)); err == nil && p == sdk.ModeActive {
			return true
		}
	}
	return false
}

// Scope is the parsed scope.yaml.
type Scope struct {
	Version int `yaml:"version"`

	Authorization Authorization `yaml:"authorization"`

	Allow struct {
		Domains      []string `yaml:"domains"`
		CIDRs        []string `yaml:"cidrs"`
		ASNs         []string `yaml:"asns"`
		URLPrefixes  []string `yaml:"url_prefixes"`
		Orgs         []string `yaml:"orgs"`
		EmailDomains []string `yaml:"email_domains"`
	} `yaml:"allow"`

	Deny struct {
		Domains []string `yaml:"domains"`
		CIDRs   []string `yaml:"cidrs"`
		Regex   []string `yaml:"regex"`
	} `yaml:"deny"`

	ThirdPartyData struct {
		RecordOutOfScope bool `yaml:"record_out_of_scope"`
	} `yaml:"third_party_data"`
}

// compiled caches parsed matchers so the hot path does no regex compilation.
type compiled struct {
	exactDomains  map[string]bool
	suffixDomains map[string]bool // ".acme.example" matches any subdomain
	denyDomains   map[string]bool
	denySuffix    map[string]bool
	allowCIDRs    []netip.Prefix
	denyCIDRs     []netip.Prefix
	allowASNs     map[uint32]bool
	denyRegex     []*regexp.Regexp
	urlPrefixes   []string
	emailDomains  map[string]bool
	orgs          []string
}

// Guard answers scope questions. It is immutable after Compile and therefore
// safe for concurrent use.
type Guard struct {
	scope *Scope
	c     *compiled
	// bypassAll is only ever true when an operator passed the explicit
	// --i-know-what-i-am-doing flag, and it is recorded in the audit log.
	bypassAll bool
	now       func() time.Time
}

// NewGuard compiles a scope for use. It rejects malformed patterns up front
// rather than at request time, so a typo cannot silently widen access.
func NewGuard(s *Scope) (*Guard, error) {
	if s == nil {
		s = &Scope{}
	}
	c := &compiled{
		exactDomains:  map[string]bool{},
		suffixDomains: map[string]bool{},
		denyDomains:   map[string]bool{},
		denySuffix:    map[string]bool{},
		allowASNs:     map[uint32]bool{},
		emailDomains:  map[string]bool{},
	}

	for _, d := range s.Allow.Domains {
		if err := c.addDomain(d); err != nil {
			return nil, fmt.Errorf("allow.domains: %w", err)
		}
	}
	for _, d := range s.Deny.Domains {
		if err := c.addDenyDomain(d); err != nil {
			return nil, fmt.Errorf("deny.domains: %w", err)
		}
	}
	for _, raw := range s.Allow.CIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("allow.cidrs: %w", err)
		}
		c.allowCIDRs = append(c.allowCIDRs, p)
	}
	for _, raw := range s.Deny.CIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("deny.cidrs: %w", err)
		}
		c.denyCIDRs = append(c.denyCIDRs, p)
	}
	for _, raw := range s.Allow.ASNs {
		n, err := parseASN(raw)
		if err != nil {
			return nil, fmt.Errorf("allow.asns: %w", err)
		}
		c.allowASNs[n] = true
	}
	for _, raw := range s.Deny.Regex {
		re, err := regexp.Compile(raw)
		if err != nil {
			return nil, fmt.Errorf("deny.regex %q: %w", raw, err)
		}
		c.denyRegex = append(c.denyRegex, re)
	}
	for _, raw := range s.Allow.URLPrefixes {
		u, err := sdk.Canonicalize(sdk.TypeURL, raw)
		if err != nil {
			return nil, fmt.Errorf("allow.url_prefixes %q: %w", raw, err)
		}
		c.urlPrefixes = append(c.urlPrefixes, u)
	}
	for _, d := range s.Allow.EmailDomains {
		canon, err := sdk.Canonicalize(sdk.TypeDomain, d)
		if err != nil {
			return nil, fmt.Errorf("allow.email_domains %q: %w", d, err)
		}
		c.emailDomains[canon] = true
	}
	for _, o := range s.Allow.Orgs {
		c.orgs = append(c.orgs, strings.ToLower(strings.TrimSpace(o)))
	}

	return &Guard{scope: s, c: c, now: time.Now}, nil
}

// WithClock overrides the clock for tests.
func (g *Guard) WithClock(now func() time.Time) *Guard {
	g.now = now
	return g
}

// WithBypassAll enables the escape hatch. It exists because air-gapped analysis
// of imported artifacts legitimately has no scope file, but it must never be
// reachable except through an explicit flag, and callers are expected to audit
// every use.
func (g *Guard) WithBypassAll(on bool) *Guard {
	g.bypassAll = on
	return g
}

// Scope returns the underlying scope.
func (g *Guard) Scope() *Scope { return g.scope }

// Decision is the outcome of a scope check.
type Decision struct {
	Allowed    bool
	Reason     string
	Rule       string // which rule decided, for the audit log and --explain
	EntityID   sdk.EntityID
	OutOfScope bool // discovered outside scope: record, never contact
}

// Deny builds a denying decision.
func deny(rule, format string, args ...any) Decision {
	return Decision{Allowed: false, Rule: rule, Reason: fmt.Sprintf(format, args...)}
}

// Check evaluates an entity against scope. Deny always wins over allow, so a
// specific denial can carve an exception out of a broad grant.
func (g *Guard) Check(e sdk.Entity) Decision {
	if e.ID == "" {
		return deny("invalid", "entity has no ID (canonicalization failed)")
	}
	if g.bypassAll {
		return Decision{Allowed: true, Rule: "bypass", Reason: "scope enforcement bypassed by explicit operator flag", EntityID: e.ID}
	}

	switch e.Type {
	case sdk.TypeDomain, sdk.TypeSubdomain:
		return g.checkDomain(e)
	case sdk.TypeIP:
		return g.checkIP(e)
	case sdk.TypeCIDR:
		return g.checkCIDR(e)
	case sdk.TypeASN:
		return g.checkASN(e)
	case sdk.TypeURL:
		return g.checkURL(e)
	case sdk.TypeEmail:
		return g.checkEmail(e)
	case sdk.TypeOrg:
		return g.checkOrg(e)
	case sdk.TypePerson, sdk.TypeUsername, sdk.TypeAccount, sdk.TypePhone,
		sdk.TypeWallet, sdk.TypeLocation, sdk.TypeGeo, sdk.TypeFile,
		sdk.TypeImage, sdk.TypeHash, sdk.TypeCert, sdk.TypeCVE, sdk.TypeTx,
		sdk.TypeApp, sdk.TypeRepo, sdk.TypePackage, sdk.TypeIOC,
		sdk.TypeText, sdk.TypeFinding:
		// These types carry no directly probeable network target. Modules that
		// consume them are still subject to mode, sensitivity, and the egress
		// allow-list, so there is nothing to scope-check at the target level.
		return Decision{Allowed: true, Rule: "not-network-target", EntityID: e.ID}
	}
	return deny("unknown-type", "cannot determine scope for entity type %q", e.Type)
}

func (g *Guard) checkDomain(e sdk.Entity) Decision {
	name := e.Value

	for _, re := range g.c.denyRegex {
		if re.MatchString(name) {
			return Decision{Allowed: false, Rule: "deny.regex", Reason: "matched deny.regex " + re.String(), EntityID: e.ID, OutOfScope: true}
		}
	}
	if g.c.denyDomains[name] {
		return Decision{Allowed: false, Rule: "deny.domains", Reason: name + " is listed in deny.domains", EntityID: e.ID, OutOfScope: true}
	}
	for suffix := range g.c.denySuffix {
		if strings.HasSuffix(name, suffix) {
			return Decision{Allowed: false, Rule: "deny.domains", Reason: name + " matches deny pattern " + suffix + "*", EntityID: e.ID, OutOfScope: true}
		}
	}

	if g.c.exactDomains[name] {
		return Decision{Allowed: true, Rule: "allow.domains", Reason: name + " is listed in allow.domains", EntityID: e.ID}
	}
	for suffix := range g.c.suffixDomains {
		if strings.HasSuffix(name, suffix) {
			return Decision{Allowed: true, Rule: "allow.domains", Reason: name + " matches allow pattern " + suffix + "*", EntityID: e.ID}
		}
	}
	return Decision{
		Allowed:    false,
		Rule:       "no-allow-rule",
		Reason:     name + " is not covered by allow.domains; recorded as out of scope and never contacted",
		EntityID:   e.ID,
		OutOfScope: true,
	}
}

func (g *Guard) checkIP(e sdk.Entity) Decision {
	addr, err := netip.ParseAddr(e.Value)
	if err != nil {
		return deny("invalid", "not an IP: %v", err)
	}
	for _, p := range g.c.denyCIDRs {
		if p.Contains(addr) {
			return Decision{Allowed: false, Rule: "deny.cidrs", Reason: addr.String() + " is in deny.cidrs " + p.String(), EntityID: e.ID, OutOfScope: true}
		}
	}
	for _, p := range g.c.allowCIDRs {
		if p.Contains(addr) {
			return Decision{Allowed: true, Rule: "allow.cidrs", Reason: addr.String() + " is in allow.cidrs " + p.String(), EntityID: e.ID}
		}
	}
	return Decision{Allowed: false, Rule: "no-allow-rule", Reason: addr.String() + " is not covered by allow.cidrs", EntityID: e.ID, OutOfScope: true}
}

func (g *Guard) checkCIDR(e sdk.Entity) Decision {
	p, err := netip.ParsePrefix(e.Value)
	if err != nil {
		return deny("invalid", "not a CIDR: %v", err)
	}
	for _, d := range g.c.denyCIDRs {
		if d.Overlaps(p) {
			return Decision{Allowed: false, Rule: "deny.cidrs", Reason: p.String() + " overlaps deny.cidrs " + d.String(), EntityID: e.ID, OutOfScope: true}
		}
	}
	// Containment, not mere overlap: a generous allow-list entry must not be
	// widened into a supernet probe by supplying a larger prefix as the target.
	for _, a := range g.c.allowCIDRs {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return Decision{Allowed: true, Rule: "allow.cidrs", Reason: p.String() + " is inside allow.cidrs " + a.String(), EntityID: e.ID}
		}
	}
	return Decision{Allowed: false, Rule: "no-allow-rule", Reason: p.String() + " is not inside any allow.cidrs entry", EntityID: e.ID, OutOfScope: true}
}

func (g *Guard) checkASN(e sdk.Entity) Decision {
	n, err := parseASN(e.Value)
	if err != nil {
		return deny("invalid", "not an ASN: %v", err)
	}
	if g.c.allowASNs[n] {
		return Decision{Allowed: true, Rule: "allow.asns", Reason: e.Value + " is listed in allow.asns", EntityID: e.ID}
	}
	return Decision{Allowed: false, Rule: "no-allow-rule", Reason: e.Value + " is not covered by allow.asns", EntityID: e.ID, OutOfScope: true}
}

func (g *Guard) checkURL(e sdk.Entity) Decision {
	// Scope a URL by its host. If the host is in scope, only the declared path
	// prefixes are reachable; anything else under an in-scope host is out of
	// scope, because an allow rule for a domain is not permission to crawl
	// every path on it.
	u := parseHostPort(e.Value)
	hostDecision := g.checkDomain(sdk.Entity{ID: sdk.NewEntityID(sdk.TypeDomain, u), Type: sdk.TypeDomain, Value: u})
	if !hostDecision.Allowed {
		hostDecision.Rule = "allow.domains (via url host)"
		return hostDecision
	}
	if len(g.c.urlPrefixes) == 0 {
		// No path restriction declared: the whole in-scope host is reachable.
		hostDecision.Reason += "; no allow.url_prefixes declared"
		return hostDecision
	}
	for _, p := range g.c.urlPrefixes {
		if strings.HasPrefix(e.Value, p) {
			return Decision{Allowed: true, Rule: "allow.url_prefixes", Reason: e.Value + " matches " + p, EntityID: e.ID}
		}
	}
	return Decision{Allowed: false, Rule: "no-url-prefix", Reason: e.Value + " is not under any allow.url_prefixes entry", EntityID: e.ID, OutOfScope: true}
}

func (g *Guard) checkEmail(e sdk.Entity) Decision {
	at := strings.LastIndex(e.Value, "@")
	if at < 0 {
		return deny("invalid", "not an email address")
	}
	dom := e.Value[at+1:]
	if g.c.emailDomains[dom] {
		return Decision{Allowed: true, Rule: "allow.email_domains", Reason: dom + " is listed in allow.email_domains", EntityID: e.ID}
	}
	return Decision{Allowed: false, Rule: "no-allow-rule", Reason: "email domain " + dom + " is not in allow.email_domains", EntityID: e.ID, OutOfScope: true}
}

func (g *Guard) checkOrg(e sdk.Entity) Decision {
	needle := strings.ToLower(strings.TrimSpace(e.Value))
	if len(g.c.orgs) == 0 {
		return Decision{Allowed: false, Rule: "no-allow-rule", Reason: "no allow.orgs entries; cannot confirm " + e.Value + " is in scope", EntityID: e.ID, OutOfScope: true}
	}
	for _, o := range g.c.orgs {
		if o == needle || strings.Contains(needle, o) || strings.Contains(o, needle) {
			return Decision{Allowed: true, Rule: "allow.orgs", Reason: e.Value + " matches " + o, EntityID: e.ID}
		}
	}
	return Decision{Allowed: false, Rule: "no-allow-rule", Reason: e.Value + " is not covered by allow.orgs", EntityID: e.ID, OutOfScope: true}
}

// CheckModule verifies that a module's mode is permitted for this engagement at
// the given time. It is separate from target scope: a module may be in scope
// and still not be allowed to run because the authorization does not cover its
// mode.
func (g *Guard) CheckModule(name string, m sdk.Manifest, ceiling sdk.Mode, t time.Time) Decision {
	if ok, reason := g.scope.Authorization.Allows(ceiling, t); !ok {
		return deny("authorization", "module %s: %s", name, reason)
	}
	if !m.Mode.Satisfies(ceiling) {
		return deny("mode", "module %s requires %s mode but the scan ceiling is %s", name, m.Mode, ceiling)
	}
	if m.Mode == sdk.ModeActive && !g.scope.Authorization.ActivePermitted() {
		return deny("active-not-authorized", "module %s is active-mode; add `active` to authorization.allowed_modes with written permission", name)
	}
	return Decision{Allowed: true, Rule: "mode-ok", Reason: m.Mode.String() + " permitted by engagement " + g.scope.Authorization.EngagementID}
}

// Now returns the guard's clock reading.
func (g *Guard) Now() time.Time { return g.now() }

// addDomain registers an allow rule. "*.acme.example" and ".acme.example" both
// mean "any subdomain of acme.example" and deliberately do NOT match the apex:
// an operator who writes a wildcard means the subdomains, and if they meant the
// apex too they must list it.
func (c *compiled) addDomain(d string) error {
	d = strings.TrimSpace(strings.ToLower(d))
	if d == "" {
		return fmt.Errorf("empty domain entry")
	}
	canon, err := sdk.Canonicalize(sdk.TypeDomain, d)
	if err != nil {
		return fmt.Errorf("%q: %w", d, err)
	}
	if strings.HasPrefix(canon, "*.") {
		c.suffixDomains["."+canon[2:]] = true
		return nil
	}
	if strings.HasPrefix(canon, ".") {
		c.suffixDomains[canon] = true
		return nil
	}
	c.exactDomains[canon] = true
	return nil
}

func (c *compiled) addDenyDomain(d string) error {
	d = strings.TrimSpace(strings.ToLower(d))
	if d == "" {
		return fmt.Errorf("empty domain entry")
	}
	canon, err := sdk.Canonicalize(sdk.TypeDomain, d)
	if err != nil {
		return fmt.Errorf("%q: %w", d, err)
	}
	if strings.HasPrefix(canon, "*.") {
		c.denySuffix["."+canon[2:]] = true
		return nil
	}
	if strings.HasPrefix(canon, ".") {
		c.denySuffix[canon] = true
		return nil
	}
	c.denyDomains[canon] = true
	return nil
}

func parsePrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q: %w", raw, err)
	}
	return p.Masked(), nil
}

func parseASN(raw string) (uint32, error) {
	canon, err := sdk.Canonicalize(sdk.TypeASN, raw)
	if err != nil {
		return 0, fmt.Errorf("%q: %w", raw, err)
	}
	var n uint64
	if _, err := fmt.Sscanf(canon, "AS%d", &n); err != nil {
		return 0, fmt.Errorf("%q: %w", raw, err)
	}
	return uint32(n), nil
}

func parseHostPort(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if strings.HasPrefix(u, "[") {
		if j := strings.IndexByte(u, ']'); j > 0 {
			return u[1:j]
		}
	}
	if i := strings.LastIndexByte(u, ':'); i > 0 {
		// Only strip a port, not part of a bare IPv6 literal.
		if isAllDigits(u[i+1:]) {
			return u[:i]
		}
	}
	return strings.ToLower(u)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func orUnknown(id string) string {
	if id == "" {
		return "(unnumbered)"
	}
	return id
}
