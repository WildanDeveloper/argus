package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// SensitivityClass configures what a data class requires before it may be
// collected. The keys are the strings used by ClassOf below.
type SensitivityClass struct {
	Require  []string `yaml:"require"` // any of: case, purpose, approval
	Approval struct {
		Required     bool     `yaml:"required"`
		Approvers    []string `yaml:"approvers"`
		ExpiresAfter Duration `yaml:"expires_after"`
	} `yaml:"approval"`
	Retention Duration `yaml:"retention"`
	Export    string   `yaml:"export"` // redacted_only | full
}

// Duration is a time.Duration that unmarshals from YAML strings like "72h".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
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

func (d Duration) String() string {
	if d == 0 {
		return ""
	}
	return time.Duration(d).String()
}

// AsDuration converts to time.Duration.
func (d Duration) AsDuration() time.Duration { return time.Duration(d) }

// Policy is the parsed policy.yaml.
type Policy struct {
	Version int `yaml:"version"`

	Sensitivity struct {
		High   SensitivityClass `yaml:"high"`
		Medium SensitivityClass `yaml:"medium"`
		Low    SensitivityClass `yaml:"low"`
	} `yaml:"sensitivity"`

	Transport struct {
		MinDelay Duration `yaml:"min_delay"`
	} `yaml:"transport"`

	DenyModules     []string `yaml:"deny_modules"`
	AllowedPurposes []string `yaml:"allowed_purposes"`

	// CaseID and Purpose are supplied per scan rather than in the file.
	caseID  string
	purpose string
}

// SetCase binds the scan to a case and purpose.
func (p *Policy) SetCase(caseID, purpose string) { p.caseID, p.purpose = caseID, purpose }

// CaseID returns the bound case.
func (p *Policy) CaseID() string { return p.caseID }

// Purpose returns the bound purpose.
func (p *Policy) Purpose() string { return p.purpose }

// ClassOf maps a module sensitivity to its configured class.
func (p *Policy) ClassOf(s sdk.Sensitivity) SensitivityClass {
	switch s {
	case sdk.SensHigh:
		return p.Sensitivity.High
	case sdk.SensMedium:
		return p.Sensitivity.Medium
	default:
		return p.Sensitivity.Low
	}
}

// NewPolicy returns a Policy with defaults that are safe without a policy file:
// no purposes are pre-approved, and every high-sensitivity class needs a case, a
// purpose, and approval. An operator must widen this deliberately.
func NewPolicy() *Policy {
	p := &Policy{Version: 1}
	p.Sensitivity.High.Require = []string{"case", "purpose", "approval"}
	p.Sensitivity.High.Approval.Required = true
	p.Sensitivity.High.Approval.Approvers = []string{"lead", "admin"}
	p.Sensitivity.High.Approval.ExpiresAfter = Duration(72 * time.Hour)
	p.Sensitivity.High.Retention = Duration(90 * 24 * time.Hour)
	p.Sensitivity.High.Export = "redacted_only"
	p.Sensitivity.Medium.Require = []string{"case"}
	p.Transport.MinDelay = Duration(24 * time.Hour)
	return p
}

// Request describes one proposed module execution.
type Request struct {
	Module      string
	Manifest    sdk.Manifest
	CaseID      string
	Purpose     string
	Actor       string
	ActorRoles  []string
	AllowActive bool
	// Approval carries the recorded approval state for this request, if any.
	Approval *Approval
	// Mode is the scan's mode ceiling: the highest mode the operator permitted for
	// this run. It must be supplied, because a collector's own declared mode can
	// never serve as its own ceiling.
	Mode sdk.Mode
	Now  time.Time
}

// Approval is a recorded four-eyes approval.
type Approval struct {
	RequestID string
	GrantedBy []string
	GrantedAt time.Time
	ExpiresAt time.Time
	Purpose   string
	Revoked   bool
}

// Active reports whether the approval is currently valid.
func (a *Approval) Active(now time.Time) bool {
	if a == nil || a.Revoked || a.GrantedAt.IsZero() {
		return false
	}
	if !a.ExpiresAt.IsZero() && now.After(a.ExpiresAt) {
		return false
	}
	return len(a.GrantedBy) > 0
}

// Engine evaluates policy requests and produces allow/deny decisions.
type Engine struct {
	policy *Policy
	guard  *Guard
	now    func() time.Time
}

// NewEngine binds a policy to a scope guard.
func NewEngine(p *Policy, g *Guard) (*Engine, error) {
	if p == nil {
		p = NewPolicy()
	}
	if g == nil {
		var err error
		g, err = NewGuard(nil)
		if err != nil {
			return nil, err
		}
	}
	return &Engine{policy: p, guard: g, now: time.Now}, nil
}

// WithClock overrides the clock for tests.
func (e *Engine) WithClock(now func() time.Time) *Engine {
	e.now = now
	return e
}

// Policy returns the bound policy.
func (e *Engine) Policy() *Policy { return e.policy }

// Guard returns the bound scope guard.
func (e *Engine) Guard() *Guard { return e.guard }

func (e *Engine) requires(class SensitivityClass, what string) bool {
	for _, r := range class.Require {
		if r == what {
			return true
		}
	}
	return false
}

// Authorize decides whether a module may run for a target. It applies, in order:
// organization-wide module bans, purpose allow-listing, case binding, mode
// gating, and four-eyes approval.
//
// The order matters: a denied purpose is reported as a purpose problem even when
// a case is also missing, because fixing the case would not help.
func (e *Engine) Authorize(target sdk.Entity, req Request) Decision {
	now := req.Now
	if now.IsZero() {
		now = e.now()
	}
	m := req.Manifest

	if deniedModule(e.policy.DenyModules, req.Module) {
		return deny("deny_modules", "module %s is hard-banned by policy.yaml", req.Module)
	}

	// Purpose limitation comes first: without a lawful purpose nothing else is
	// worth checking.
	if e.requires(e.policy.ClassOf(m.Sensitivity), "purpose") {
		p := strings.TrimSpace(firstNonEmpty(req.Purpose, e.policy.Purpose()))
		if p == "" {
			return deny("missing-purpose", "module %s processes personal data; declare a purpose (--purpose) or bind a case with a purpose", req.Module)
		}
		if len(e.policy.AllowedPurposes) > 0 && !purposeAllowed(e.policy.AllowedPurposes, p) {
			return deny("purpose-not-allowed", "purpose %q is not in policy.yaml allowed_purposes", p)
		}
	}

	if e.requires(e.policy.ClassOf(m.Sensitivity), "case") {
		c := firstNonEmpty(req.CaseID, e.policy.caseID)
		if strings.TrimSpace(c) == "" {
			return deny("missing-case", "module %s requires a case binding (--case)", req.Module)
		}
	}

	class := e.policy.ClassOf(m.Sensitivity)

	if e.requires(class, "approval") || class.Approval.Required {
		if !req.Approval.Active(now) {
			return deny("approval-required", "module %s is high-sensitivity; a four-eyes approval by one of %v is required (approvals expire after %s)",
				req.Module, class.Approval.Approvers, class.Approval.ExpiresAfter)
		}
		// Four eyes: the approver must not be the operator requesting the run.
		for _, g := range req.Approval.GrantedBy {
			if g == req.Actor {
				return deny("four-eyes", "approval for %s was granted by the requesting actor (%s); a second person must approve", req.Module, req.Actor)
			}
		}
		if len(req.Approval.GrantedBy) > 0 && len(class.Approval.Approvers) > 0 {
			if !anyIn(req.Approval.GrantedBy, class.Approval.Approvers) {
				return deny("approver-role", "approval for %s was granted by %v; policy requires one of %v",
					req.Module, req.Approval.GrantedBy, class.Approval.Approvers)
			}
		}
	}

	// Mode gating: the scan ceiling, then the authorization, then the explicit
	// flag. All three must agree, and the ceiling comes from the operator's request
	// rather than from the module: a module that supplied its own ceiling could
	// authorize itself.
	if !m.Mode.Satisfies(req.Mode) {
		return deny("mode-ceiling", "module %s requires %s mode but this scan runs at %s; raise --mode to permit it",
			req.Module, m.Mode, req.Mode)
	}
	if ok, reason := e.guard.scope.Authorization.Allows(req.Mode, now); !ok {
		return deny("authorization", "module %s: %s", req.Module, reason)
	}
	if m.Mode == sdk.ModeActive && !req.AllowActive {
		return deny("active-flag", "module %s is active-mode; pass --allow-active to permit it", req.Module)
	}
	if m.Mode == sdk.ModeActive && !e.guard.scope.Authorization.ActivePermitted() {
		return deny("active-not-authorized", "module %s is active-mode; add `active` to authorization.allowed_modes with written permission", req.Module)
	}

	return Decision{
		Allowed: true,
		Rule:    "policy-ok",
		Reason: fmt.Sprintf("%s permitted: mode=%s sensitivity=%s case=%q purpose=%q",
			req.Module, m.Mode, m.Sensitivity, firstNonEmpty(req.CaseID, e.policy.caseID), firstNonEmpty(req.Purpose, e.policy.Purpose())),
		EntityID: target.ID,
	}
}

// CheckTarget verifies an operator-supplied scan root against scope.
//
// This is deliberately separate from Authorize. An asset Argus *discovered* may
// be recorded as out of scope and still be described by third-party passive
// data; a target an operator *typed on the command line* is a statement that
// this is the asset under assessment, and if scope does not cover it the whole
// engagement is misconfigured. The orchestrator calls this once, on the root,
// before scheduling anything (§4.2 step 4).
func (e *Engine) CheckTarget(target sdk.Entity, ceiling sdk.Mode) Decision {
	if target.ID == "" {
		return deny("invalid-target", "target could not be canonicalized as %s", target.Type)
	}
	d := e.guard.Check(target)
	if !d.Allowed {
		return d
	}
	// Scope covers the asset; authorization covers the interaction with it.
	if ok, reason := e.guard.scope.Authorization.Allows(ceiling, e.now()); !ok {
		return deny("authorization", "%s", reason)
	}
	return d
}

// FilterAllowedModules returns the subset of modules permitted for a target,
// preserving order and recording the reason for each rejection.
func (e *Engine) FilterAllowedModules(target sdk.Entity, modules []sdk.Module, reqFor func(sdk.Module) Request) ([]sdk.Module, []Decision) {
	var allowed []sdk.Module
	var denied []Decision
	for _, m := range modules {
		d := e.Authorize(target, reqFor(m))
		if d.Allowed {
			allowed = append(allowed, m)
		} else {
			denied = append(denied, d)
		}
	}
	return allowed, denied
}

// ValidatePurpose reports whether p is acceptable, for early CLI feedback
// instead of a per-module denial at run time.
func (e *Engine) ValidatePurpose(p string) error {
	if len(e.policy.AllowedPurposes) == 0 {
		return nil
	}
	if !purposeAllowed(e.policy.AllowedPurposes, p) {
		return fmt.Errorf("purpose %q is not in policy.yaml allowed_purposes", p)
	}
	return nil
}

func deniedModule(list []string, name string) bool {
	return containsFold(list, name)
}

// purposeAllowed compares purposes case-insensitively and tolerates a purpose
// that names an allowed purpose plus additional detail, so an analyst can record
// a specific case without editing policy.yaml.
func purposeAllowed(allowed []string, p string) bool {
	p = strings.ToLower(strings.TrimSpace(p))
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if p == a || strings.HasPrefix(p, a+" ") || strings.HasPrefix(p, a+":") || strings.HasPrefix(p, a+",") {
			return true
		}
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, e := range list {
		if strings.EqualFold(strings.TrimSpace(e), v) {
			return true
		}
	}
	return false
}

func anyIn(have, want []string) bool {
	for _, h := range have {
		if containsFold(want, h) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Purposes returns the configured purposes, sorted, for display and completion.
func (p *Policy) Purposes() []string {
	out := append([]string(nil), p.AllowedPurposes...)
	sort.Strings(out)
	return out
}
