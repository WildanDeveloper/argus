package policy

import (
	"testing"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

func testScope() *Scope {
	s := &Scope{}
	s.Authorization = Authorization{
		EngagementID: "ACME-2026-01",
		AuthorizedBy: "Jane Doe, CISO",
		Contact:      "security@acme.example",
		ValidFrom:    time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil:   time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC),
		AllowedModes: []string{"passive", "semi-active"},
	}
	s.Allow.Domains = []string{"acme.example", "*.acme.example", "acme-cdn.example"}
	s.Allow.CIDRs = []string{"203.0.113.0/24", "2001:db8:100::/48"}
	s.Allow.ASNs = []string{"AS64500"}
	s.Allow.EmailDomains = []string{"acme.example"}
	s.Allow.Orgs = []string{"ACME Corp"}
	s.Deny.Domains = []string{"*.gov", "*.mil", "partner-portal.acme.example"}
	s.Deny.CIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	s.Deny.Regex = []string{`^hr\..*\.acme\.example$`}
	return s
}

func TestScopeAllowRules(t *testing.T) {
	g, err := NewGuard(testScope())
	if err != nil {
		t.Fatal(err)
	}

	allowed := []string{
		"acme.example",
		"dev.acme.example",
		"a.b.c.acme.example",
		"acme-cdn.example",
	}
	for _, name := range allowed {
		e := sdk.NewEntity(sdk.TypeDomain, name)
		if d := g.Check(e); !d.Allowed {
			t.Errorf("Check(%s) denied: %s (%s)", name, d.Reason, d.Rule)
		}
	}

	denied := []string{
		"evil.com",
		"acme.example.evil.com",
		"partner-portal.acme.example", // explicit deny beats the *.acme.example allow
		"hr.portal.acme.example",      // deny.regex
		"foo.gov",
		"www.mil",
		// A look-alike that merely contains an in-scope name must not match:
		// suffix matching is anchored at a label boundary, not a substring test.
		"partner-portal.acme.example.evil.com",
		"notacme.example",
	}
	for _, name := range denied {
		e := sdk.NewEntity(sdk.TypeDomain, name)
		if d := g.Check(e); d.Allowed {
			t.Errorf("Check(%s) allowed but should be denied", name)
		}
	}
}

func TestDenyBeatsAllow(t *testing.T) {
	// The precedence that matters most for safety: a specific denial must carve
	// an exception out of a broad grant. "hr.portal.acme.example" satisfies the
	// *.acme.example allow rule AND the deny.regex, so only correct precedence
	// can deny it.
	g, _ := NewGuard(testScope())
	d := g.Check(sdk.NewEntity(sdk.TypeDomain, "hr.portal.acme.example"))
	if d.Allowed {
		t.Fatal("deny.regex must override allow.domains")
	}
	if d.Rule != "deny.regex" {
		t.Errorf("rule = %q, want deny.regex", d.Rule)
	}

	// And the inverse: a sibling the regex does not match stays in scope, which
	// confirms this test exercises precedence and not a blanket denial.
	if d := g.Check(sdk.NewEntity(sdk.TypeDomain, "eng.portal.acme.example")); !d.Allowed {
		t.Errorf("non-matching sibling should stay in scope: %s", d.Reason)
	}
}

func TestOutOfScopeIsRecordedNotContacted(t *testing.T) {
	g, _ := NewGuard(testScope())
	d := g.Check(sdk.NewEntity(sdk.TypeDomain, "unrelated.example"))
	if d.Allowed {
		t.Fatal("expected denial")
	}
	if !d.OutOfScope {
		t.Error("a discovered-but-out-of-scope asset must be flagged so it can be recorded without being contacted")
	}
}

func TestDenyByDefaultWithEmptyScope(t *testing.T) {
	// An operator who forgets to write scope.yaml must get no access, not full
	// access. This is the single most important default in the system.
	g, err := NewGuard(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"acme.example", "8.8.8.8", "example.com"} {
		if d := g.Check(sdk.NewEntity(sdk.TypeDomain, name)); d.Allowed {
			t.Errorf("empty scope allowed %s", name)
		}
	}
}

func TestScopeCIDRs(t *testing.T) {
	g, _ := NewGuard(testScope())

	if d := g.Check(sdk.NewEntity(sdk.TypeIP, "203.0.113.42")); !d.Allowed {
		t.Errorf("allowed CIDR member denied: %s", d.Reason)
	}
	if d := g.Check(sdk.NewEntity(sdk.TypeIP, "2001:db8:100::5")); !d.Allowed {
		t.Errorf("allowed IPv6 member denied: %s", d.Reason)
	}
	for _, bad := range []string{"10.1.2.3", "192.168.1.1", "172.16.5.5", "169.254.169.254"} {
		if d := g.Check(sdk.NewEntity(sdk.TypeIP, bad)); d.Allowed {
			t.Errorf("denied range %s was allowed (SSRF metadata endpoint must never pass)", bad)
		}
	}
	if d := g.Check(sdk.NewEntity(sdk.TypeIP, "8.8.8.8")); d.Allowed {
		t.Error("IP outside allow.cidrs must be denied")
	}

	// A /16 target must not be permitted merely because it overlaps an allowed
	// /24: overlap must not widen authorization.
	if d := g.Check(sdk.NewEntity(sdk.TypeCIDR, "203.0.113.0/16")); d.Allowed {
		t.Error("a supernet of an allowed prefix must not be authorized")
	}
	if d := g.Check(sdk.NewEntity(sdk.TypeCIDR, "203.0.113.0/25")); !d.Allowed {
		t.Error("a subnet of an allowed prefix should be allowed")
	}
}

func TestScopeURLPrefixGatesPaths(t *testing.T) {
	g, _ := NewGuard(testScope())
	g.c.urlPrefixes = []string{"https://portal.acme.example/public/"}

	if d := g.Check(sdk.NewEntity(sdk.TypeURL, "https://portal.acme.example/public/doc")); !d.Allowed {
		t.Errorf("declared prefix denied: %s", d.Reason)
	}
	// An in-scope host is not blanket permission to crawl every path on it.
	d := g.Check(sdk.NewEntity(sdk.TypeURL, "https://portal.acme.example/admin/keys"))
	if d.Allowed {
		t.Error("path outside allow.url_prefixes must be denied even on an in-scope host")
	}
	// Out-of-scope host regardless of path.
	if d := g.Check(sdk.NewEntity(sdk.TypeURL, "https://evil.example/public/x")); d.Allowed {
		t.Error("out-of-scope host with a matching path prefix must be denied")
	}
}

func TestScopeEmailAndOrg(t *testing.T) {
	g, _ := NewGuard(testScope())
	if d := g.Check(sdk.NewEntity(sdk.TypeEmail, "jane@acme.example")); !d.Allowed {
		t.Errorf("in-scope email domain denied: %s", d.Reason)
	}
	if d := g.Check(sdk.NewEntity(sdk.TypeEmail, "jane@gmail.com")); d.Allowed {
		t.Error("out-of-scope email domain allowed")
	}
	if d := g.Check(sdk.NewEntity(sdk.TypeOrg, "ACME Corp")); !d.Allowed {
		t.Errorf("in-scope org denied: %s", d.Reason)
	}
	if d := g.Check(sdk.NewEntity(sdk.TypeOrg, "Unrelated Holdings")); d.Allowed {
		t.Error("out-of-scope org allowed")
	}
}

func TestAuthorizationModeGating(t *testing.T) {
	sc := testScope()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

	if ok, _ := sc.Authorization.Allows(sdk.ModePassive, now); !ok {
		t.Error("passive should be allowed")
	}
	if ok, _ := sc.Authorization.Allows(sdk.ModeSemiActive, now); !ok {
		t.Error("semi-active should be allowed")
	}
	if ok, reason := sc.Authorization.Allows(sdk.ModeActive, now); ok {
		t.Error("active must NOT be allowed: allowed_modes omits it")
	} else if reason == "" {
		t.Error("denial must carry a reason")
	}

	// Outside the validity window.
	if ok, _ := sc.Authorization.Allows(sdk.ModePassive, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)); ok {
		t.Error("authorization must not apply before valid_from")
	}
	if ok, _ := sc.Authorization.Allows(sdk.ModePassive, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)); ok {
		t.Error("expired authorization must not apply")
	}
}

func TestAuthorizationMissingEngagementBlocksActive(t *testing.T) {
	// A scope file with allow rules but no authorization block must still
	// refuse active work.
	s := &Scope{}
	s.Allow.Domains = []string{"acme.example"}
	if ok, _ := s.Authorization.Allows(sdk.ModeActive, time.Now()); ok {
		t.Error("active work must be refused without an engagement_id")
	}
	if ok, _ := s.Authorization.Allows(sdk.ModeSemiActive, time.Now()); ok {
		t.Error("semi-active work contacts the target and must be refused without an engagement_id")
	}
	// Passive reads third-party datasets and never touches the target, so it
	// must remain available; gating it would only push operators to disable the
	// gate entirely.
	if ok, _ := s.Authorization.Allows(sdk.ModePassive, time.Now()); !ok {
		t.Error("passive should remain possible without an engagement")
	}
}

func TestPassiveStopsAtEngagementExpiry(t *testing.T) {
	// An expired engagement must stop passive work too, or a forgotten scope
	// file becomes a permanent licence.
	sc := testScope()
	if ok, reason := sc.Authorization.Allows(sdk.ModePassive, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); ok {
		t.Errorf("passive must stop after valid_until: %s", reason)
	}
}

func TestCheckModuleModeCeiling(t *testing.T) {
	g, _ := NewGuard(testScope())
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

	passive := sdk.Manifest{Name: "p", Mode: sdk.ModePassive}
	active := sdk.Manifest{Name: "a", Mode: sdk.ModeActive}

	if d := g.CheckModule("p", passive, sdk.ModeSemiActive, now); !d.Allowed {
		t.Errorf("passive module in semi-active scan denied: %s", d.Reason)
	}
	if d := g.CheckModule("a", active, sdk.ModeSemiActive, now); d.Allowed {
		t.Error("active module must not run in a semi-active scan")
	}
}

// --- policy engine ---

func testPolicy() *Policy {
	p := NewPolicy()
	p.AllowedPurposes = []string{
		"Authorized attack-surface assessment",
		"Brand protection",
		"Due diligence (consented or public-interest)",
	}
	return p
}

func highManifest() sdk.Manifest {
	return sdk.Manifest{Name: "email-validate", Mode: sdk.ModeSemiActive, Sensitivity: sdk.SensHigh}
}

func TestPolicySensitiveNeedsPurposeCaseApproval(t *testing.T) {
	e, err := NewEngine(testPolicy(), mustGuard(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	target := sdk.NewEntity(sdk.TypeEmail, "jane@acme.example")

	// Nothing supplied: the first failure reported is the missing purpose.
	d := e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive, Now: now})
	if d.Allowed || d.Rule != "missing-purpose" {
		t.Fatalf("expected missing-purpose, got allowed=%v rule=%s", d.Allowed, d.Rule)
	}

	// Purpose but no case.
	d = e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Purpose: "Authorized attack-surface assessment", Now: now})
	if d.Allowed || d.Rule != "missing-case" {
		t.Fatalf("expected missing-case, got allowed=%v rule=%s", d.Allowed, d.Rule)
	}

	// Case and purpose but no approval.
	d = e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive,
		CaseID: "CASE-42", Purpose: "Authorized attack-surface assessment", Now: now})
	if d.Allowed || d.Rule != "approval-required" {
		t.Fatalf("expected approval-required, got allowed=%v rule=%s", d.Allowed, d.Rule)
	}

	// Approved by a second person with the right role.
	d = e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive,
		CaseID: "CASE-42", Purpose: "Authorized attack-surface assessment", Now: now,
		Approval: &Approval{GrantedBy: []string{"lead"}, GrantedAt: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour)}})
	if !d.Allowed {
		t.Fatalf("expected allow with valid approval, got %s: %s", d.Rule, d.Reason)
	}
}

func TestPolicyFourEyes(t *testing.T) {
	e, _ := NewEngine(testPolicy(), mustGuard(t))
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	target := sdk.NewEntity(sdk.TypeEmail, "jane@acme.example")

	// Self-approval must fail: that is the whole point of four eyes.
	d := e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive,
		CaseID: "CASE-42", Purpose: "Authorized attack-surface assessment", Now: now,
		Approval: &Approval{GrantedBy: []string{"analyst"}, GrantedAt: now, ExpiresAt: now.Add(time.Hour)}})
	if d.Allowed || d.Rule != "four-eyes" {
		t.Fatalf("self-approval must be refused; got allowed=%v rule=%s", d.Allowed, d.Rule)
	}

	// Approver without the required role.
	d = e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive,
		CaseID: "CASE-42", Purpose: "Authorized attack-surface assessment", Now: now,
		Approval: &Approval{GrantedBy: []string{"intern"}, GrantedAt: now, ExpiresAt: now.Add(time.Hour)}})
	if d.Allowed || d.Rule != "approver-role" {
		t.Fatalf("approver without role must be refused; got allowed=%v rule=%s", d.Allowed, d.Rule)
	}
}

func TestPolicyExpiredAndRevokedApproval(t *testing.T) {
	e, _ := NewEngine(testPolicy(), mustGuard(t))
	target := sdk.NewEntity(sdk.TypeEmail, "jane@acme.example")
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	base := Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive,
		CaseID: "CASE-42", Purpose: "Authorized attack-surface assessment", Now: now}

	expired := base
	expired.Approval = &Approval{GrantedBy: []string{"lead"}, GrantedAt: now.Add(-100 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if d := e.Authorize(target, expired); d.Allowed {
		t.Error("expired approval must not authorize")
	}

	revoked := base
	revoked.Approval = &Approval{GrantedBy: []string{"lead"}, GrantedAt: now, Revoked: true}
	if d := e.Authorize(target, revoked); d.Allowed {
		t.Error("revoked approval must not authorize")
	}
}

func TestPolicyPurposeMustBeOnAllowList(t *testing.T) {
	e, _ := NewEngine(testPolicy(), mustGuard(t))
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	target := sdk.NewEntity(sdk.TypeEmail, "jane@acme.example")

	d := e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst",
		CaseID: "CASE-42", Purpose: "because I felt like it", Now: now})
	if d.Allowed || d.Rule != "purpose-not-allowed" {
		t.Fatalf("expected purpose-not-allowed, got allowed=%v rule=%s", d.Allowed, d.Rule)
	}

	// An allowed purpose plus case detail is accepted without editing policy.
	d = e.Authorize(target, Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive,
		CaseID: "CASE-42", Purpose: "Brand protection: ACME Q4 campaign", Now: now,
		Approval: &Approval{GrantedBy: []string{"lead"}, GrantedAt: now, ExpiresAt: now.Add(time.Hour)}})
	if !d.Allowed {
		t.Errorf("purpose with detail should be allowed: %s: %s", d.Rule, d.Reason)
	}
}

func TestPolicyDenyModules(t *testing.T) {
	p := testPolicy()
	p.DenyModules = []string{"email-validate"}
	e, _ := NewEngine(p, mustGuard(t))
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	d := e.Authorize(sdk.NewEntity(sdk.TypeEmail, "jane@acme.example"),
		Request{Module: "email-validate", Manifest: highManifest(), Actor: "analyst", Mode: sdk.ModeSemiActive,
			CaseID: "CASE-42", Purpose: "Authorized attack-surface assessment", Now: now,
			Approval: &Approval{GrantedBy: []string{"lead"}, GrantedAt: now, ExpiresAt: now.Add(time.Hour)}})
	if d.Allowed || d.Rule != "deny_modules" {
		t.Fatalf("hard ban must win over every other gate; got allowed=%v rule=%s", d.Allowed, d.Rule)
	}
}

func TestPolicyActiveRequiresFlagAndAuthorization(t *testing.T) {
	active := sdk.Manifest{Name: "axfr-check", Mode: sdk.ModeActive}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	target := sdk.NewEntity(sdk.TypeDomain, "acme.example")

	// Scope authorization permits only passive and semi-active.
	e, _ := NewEngine(testPolicy(), mustGuard(t))
	d := e.Authorize(target, Request{Module: "axfr-check", Manifest: active, Actor: "analyst", Mode: sdk.ModeActive, AllowActive: true, Now: now})
	if d.Allowed || d.Rule != "authorization" {
		t.Fatalf("active without scope authorization must be refused; got allowed=%v rule=%s", d.Allowed, d.Rule)
	}

	// With `active` in allowed_modes but without the flag.
	s := testScope()
	s.Authorization.AllowedModes = []string{"passive", "semi-active", "active"}
	e2, _ := NewEngine(testPolicy(), guardFrom(t, s))
	d = e2.Authorize(target, Request{Module: "axfr-check", Manifest: active, Actor: "analyst", Mode: sdk.ModeActive, AllowActive: false, Now: now})
	if d.Allowed || d.Rule != "active-flag" {
		t.Fatalf("active without --allow-active must be refused; got allowed=%v rule=%s", d.Allowed, d.Rule)
	}

	// Both present: allowed.
	d = e2.Authorize(target, Request{Module: "axfr-check", Manifest: active, Actor: "analyst", Mode: sdk.ModeActive, AllowActive: true, Now: now})
	if !d.Allowed {
		t.Errorf("active with authorization and flag should be allowed: %s: %s", d.Rule, d.Reason)
	}
}

func TestPolicyLowSensitivityNeedsNothing(t *testing.T) {
	// Passive, low-sensitivity collection against public data must not be
	// gated behind ceremony, or operators will route around the gate entirely.
	p := testPolicy()
	p.Sensitivity.Low.Require = nil
	p.AllowedPurposes = nil
	e, _ := NewEngine(p, mustGuard(t))
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	m := sdk.Manifest{Name: "rdap", Mode: sdk.ModePassive, Sensitivity: sdk.SensLow}
	if d := e.Authorize(sdk.NewEntity(sdk.TypeDomain, "acme.example"),
		Request{Module: "rdap", Manifest: m, Actor: "analyst", Now: now}); !d.Allowed {
		t.Errorf("passive low-sensitivity module should be allowed: %s: %s", d.Rule, d.Reason)
	}
}

func TestCheckTargetGatesTheScanRoot(t *testing.T) {
	// Module policy and target scope are separate gates. An approved purpose and
	// a permitted module must not turn an out-of-scope root target into a
	// reachable one.
	e, _ := NewEngine(testPolicy(), mustGuard(t))
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	e = e.WithClock(func() time.Time { return now })

	if d := e.CheckTarget(sdk.NewEntity(sdk.TypeDomain, "unrelated.example"), sdk.ModePassive); d.Allowed {
		t.Fatal("out-of-scope root target must be refused")
	}
	if d := e.CheckTarget(sdk.NewEntity(sdk.TypeDomain, "dev.acme.example"), sdk.ModePassive); !d.Allowed {
		t.Errorf("in-scope root target refused: %s: %s", d.Rule, d.Reason)
	}
	if d := e.CheckTarget(sdk.NewEntity(sdk.TypeDomain, "acme.example"), sdk.ModeSemiActive); !d.Allowed {
		t.Errorf("semi-active within allowed_modes should pass: %s: %s", d.Rule, d.Reason)
	}
}

func TestDiscoveredOutOfScopeAssetIsRecordedNotContacted(t *testing.T) {
	// Contrast with CheckTarget: a *discovered* out-of-scope asset is a normal
	// outcome. The guard denies it, and the caller records it as out_of_scope
	// rather than dropping it or chasing it.
	g := mustGuard(t)
	d := g.Check(sdk.NewEntity(sdk.TypeDomain, "cdn.vendor.example"))
	if d.Allowed {
		t.Fatal("third-party asset must not be in scope")
	}
	if !d.OutOfScope {
		t.Error("must be flagged OutOfScope so it is recorded but never contacted")
	}
}

func TestScopeCompileRejectsMalformedRules(t *testing.T) {
	// A typo in a pattern must fail at load time. Accepting it silently would
	// mean a rule the operator believes is active is not.
	for name, mutate := range map[string]func(*Scope){
		"bad regex":      func(s *Scope) { s.Deny.Regex = []string{"([unclosed"} },
		"bad allow cidr": func(s *Scope) { s.Allow.CIDRs = []string{"not-a-cidr"} },
		"bad deny cidr":  func(s *Scope) { s.Deny.CIDRs = []string{"999.0.0.0/8"} },
		"bad allow asn":  func(s *Scope) { s.Allow.ASNs = []string{"ASN1"} },
		"bad url prefix": func(s *Scope) { s.Allow.URLPrefixes = []string{"://bad"} },
		"empty domain":   func(s *Scope) { s.Allow.Domains = []string{"  "} },
	} {
		s := testScope()
		mutate(s)
		if _, err := NewGuard(s); err == nil {
			t.Errorf("%s: expected a compile error", name)
		}
	}
}

func TestBypassIsExplicit(t *testing.T) {
	g, _ := NewGuard(testScope())
	d := g.Check(sdk.NewEntity(sdk.TypeDomain, "anything.example"))
	if d.Allowed {
		t.Fatal("precondition: should be denied without bypass")
	}
	g = g.WithBypassAll(true)
	d = g.Check(sdk.NewEntity(sdk.TypeDomain, "anything.example"))
	if !d.Allowed || d.Rule != "bypass" {
		t.Errorf("bypass should allow with rule=bypass, got %+v", d)
	}
}

func mustGuard(t *testing.T) *Guard {
	t.Helper()
	g, err := NewGuard(testScope())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func guardFrom(t *testing.T, s *Scope) *Guard {
	t.Helper()
	g, err := NewGuard(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
