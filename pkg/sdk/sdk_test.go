package sdk

import (
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCanonicalizeDomains(t *testing.T) {
	// Values that all denote the same real-world host must agree. If these ever
	// diverge, two analysts on two machines produce two entities and the graph
	// silently forks.
	same := []string{
		"example.com",
		"EXAMPLE.com",
		"example.com.",
		"  example.com  ",
		"https://example.com",
		"example.com/path?q=1",
		"example.com:443",
	}
	for _, v := range same {
		got, err := Canonicalize(TypeDomain, v)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", v, err)
		}
		if got != "example.com" {
			t.Errorf("Canonicalize(%q) = %q, want example.com", v, got)
		}
	}

	// IDNA: an A-label and its U-label must collapse to one entity.
	u := "münchen.example"
	a := "xn--mnchen-3ya.example"
	cu, err1 := Canonicalize(TypeDomain, u)
	ca, err2 := Canonicalize(TypeDomain, a)
	if err1 != nil || err2 != nil {
		t.Fatalf("IDNA canonicalize: %v %v", err1, err2)
	}
	if cu != ca {
		t.Errorf("IDNA mismatch: %q != %q", cu, ca)
	}
	if NewEntityID(TypeDomain, cu) != NewEntityID(TypeDomain, ca) {
		t.Error("IDNA forms produced different IDs")
	}

	// A subdomain is a distinct entity type from its parent: they are related by
	// subdomain_of, never merged.
	sub := NewEntity(TypeSubdomain, "dev.example.com")
	dom := NewEntity(TypeDomain, "example.com")
	if sub.ID == dom.ID {
		t.Error("subdomain and domain collided; they must be separate entities")
	}
}

func TestCanonicalizeIP(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":    "1.1.1.1",
		"  1.1.1.1 ": "1.1.1.1",
		"2001:0db8:0000:0000:0000:0000:0000:0001": "2001:db8::1", // RFC 5952
		"2001:db8::1":       "2001:db8::1",
		"[2001:db8::1]":     "2001:db8::1",
		"[2001:db8::1]:443": "2001:db8::1",
		"2001:db8::1%eth0":  "2001:db8::1",
	}
	for in, want := range cases {
		got, err := Canonicalize(TypeIP, in)
		if err != nil {
			t.Fatalf("Canonicalize(ip,%q): %v", in, err)
		}
		if got != want {
			t.Errorf("Canonicalize(ip,%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := Canonicalize(TypeIP, "999.1.1.1"); err == nil {
		t.Error("expected error for malformed IP")
	}
}

func TestCanonicalizeURLStripsTracking(t *testing.T) {
	got, err := Canonicalize(TypeURL, "HTTPS://Example.COM:443/p?utm_source=x&id=7#frag")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.com/p?id=7"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeEmailPreservesLocalPart(t *testing.T) {
	got, err := Canonicalize(TypeEmail, "User.Name+tag@Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if got != "User.Name+tag@example.com" {
		t.Errorf("got %q; local part must be preserved per Appendix A", got)
	}
}

func TestCanonicalizeEIP55(t *testing.T) {
	// EIP-55 test vector.
	got, err := Canonicalize(TypeWallet, "eth:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ethereum:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" {
		t.Errorf("EIP-55 checksum wrong: %q", got)
	}
	// A lowercase input must checksum to the same canonical value.
	again, _ := Canonicalize(TypeWallet, "ethereum:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
	if again != got {
		t.Error("EIP-55 canonicalization is not idempotent")
	}
}

func TestCanonicalizeHashInfersAlgorithm(t *testing.T) {
	// 5d41402abc4b2a76b9719d911017c592 is the MD5 of "hello"; the bare form must
	// infer the algorithm from the digest length so the same bytes never split
	// into two entities.
	a, err := Canonicalize(TypeHash, "5D41402ABC4B2A76B9719D911017C592")
	if err != nil {
		t.Fatal(err)
	}
	if want := "md5:5d41402abc4b2a76b9719d911017c592"; a != want {
		t.Errorf("bare digest: got %q, want %q", a, want)
	}

	// aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d is the SHA-1 of "hello".
	b, err := Canonicalize(TypeHash, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Canonicalize(TypeHash, "sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
	if err != nil {
		t.Fatal(err)
	}
	if b != c {
		t.Errorf("bare and prefixed SHA-1 must agree: %q vs %q", b, c)
	}
	if b != "sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" {
		t.Errorf("SHA-1 digest canonical form: %q", b)
	}
}

func TestCanonicalizeCVE(t *testing.T) {
	got, err := Canonicalize(TypeCVE, "cve-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	if got != "CVE-2021-44228" {
		t.Errorf("got %q", got)
	}
	if _, err := Canonicalize(TypeCVE, "CVE-21-1"); err == nil {
		t.Error("expected rejection of malformed CVE")
	}
}

func TestCanonicalizeAccount(t *testing.T) {
	got, err := Canonicalize(TypeAccount, "GitHub:octocat")
	if err != nil {
		t.Fatal(err)
	}
	if got != "github:octocat" {
		t.Errorf("got %q", got)
	}
	if _, err := Canonicalize(TypeAccount, "no-platform-prefix"); err == nil {
		t.Error("expected rejection of handle without platform")
	}
}

func TestNewEntityIDStabilityAndDomainSeparation(t *testing.T) {
	// The zero-byte domain separator must prevent (type,value) pairs with
	// different splits from hashing to the same ID.
	id1 := NewEntityID(TypeText, "ab")
	id2 := NewEntityID(TypeText, "a")
	id3 := NewEntityID(TypeDomain, "ab")
	if id1 == id2 || id1 == id3 {
		t.Error("entity ID domain separation failed")
	}
	if got := len(id1); got != 26 {
		t.Errorf("entity ID length = %d, want 26", got)
	}
	if strings.ToLower(string(id1)) != string(id1) {
		t.Error("entity ID must be lower case")
	}
}

func TestObservationIDDeterministic(t *testing.T) {
	now := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	src := Source{Module: "ct-search", Provider: "crtsh", Method: "api.search"}
	subj := NewEntityID(TypeSubdomain, "dev.example.com")

	a := NewObservation(now, subj, "exists", nil, src, 'B', '2')
	b := NewObservation(now.Add(time.Hour), subj, "exists", nil, src, 'B', '2')
	if a.ID != b.ID {
		t.Error("observation ID must not depend on observed_at, otherwise at-least-once redelivery creates duplicates")
	}

	// Different providers must produce different observations: rescellers need to
	// be distinguishable before independence-group scoring collapses them.
	c := NewObservation(now, subj, "exists", nil, Source{Module: "passive-dns", Provider: "securitytrails"}, 'B', '2')
	if a.ID == c.ID {
		t.Error("observations from different sources must differ")
	}

	// Map-valued objects must hash deterministically despite Go's randomized map
	// iteration order. This is the classic source of non-reproducible IDs.
	m1 := NewObservation(now, subj, "attr:x", map[string]any{"b": 2, "a": 1, "c": 3}, src, 'B', '2')
	for i := 0; i < 200; i++ {
		m2 := NewObservation(now, subj, "attr:x", map[string]any{"c": 3, "a": 1, "b": 2}, src, 'B', '2')
		if m1.ID != m2.ID {
			t.Fatalf("map-valued observation ID is unstable on iteration %d", i)
		}
	}
}

func TestObservationBitemporalIdentity(t *testing.T) {
	now := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	src := Source{Module: "rdap", Provider: "rdap.org", Method: "domain"}
	subj := NewEntityID(TypeDomain, "example.com")

	plain := NewObservation(now, subj, "exists", nil, src, 'A', '1')
	withValid := plain.WithValidFrom(now, now.Add(365*24*time.Hour))
	if plain.ID == withValid.ID {
		t.Error("a validity window must produce a distinct observation")
	}
	if withValid.ValidFrom == nil || withValid.ValidTo == nil {
		t.Error("validity window not recorded")
	}
}

func TestRelationIdentityAndHeuristicFlag(t *testing.T) {
	from := NewEntityID(TypeDomain, "example.com")
	to := NewEntityID(TypeSubdomain, "dev.example.com")

	r1 := Rel(from, to, RelResolvesTo)
	r2 := Rel(from, to, RelResolvesTo)
	if r1.ID != r2.ID {
		t.Error("relation ID must be deterministic for idempotent upserts")
	}
	r3 := HeuristicRel(from, to, RelOwnedBy)
	if !r3.Heuristic {
		t.Error("heuristic relation must be flagged so reports never present an inference as verified")
	}
	if r1.Heuristic {
		t.Error("direct relation must not be flagged heuristic")
	}
	// The relation type is part of identity: a different edge type is a
	// different relation even between the same pair of entities.
	if Rel(from, to, RelCNAMETo).ID == r1.ID {
		t.Error("relation type must participate in relation identity")
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !SeverityAtLeast(SevCritical, SevHigh) {
		t.Error("critical >= high expected")
	}
	if SeverityAtLeast(SevLow, SevMedium) {
		t.Error("low >= medium must be false")
	}
	// An unrecognized severity must never escalate.
	if SeverityRank("catastrophic") >= SeverityRank(SevHigh) {
		t.Error("unknown severity must not outrank high")
	}
	if !SeverityAtLeast("bogus", SevInfo) {
		t.Error("unknown severity should rank with info")
	}
}

func TestModeSatisfies(t *testing.T) {
	if !ModePassive.Satisfies(ModeActive) {
		t.Error("a passive collector may run in an active scan")
	}
	if ModeSemiActive.Satisfies(ModePassive) {
		t.Error("a semi-active collector must not run in a passive scan")
	}
	if ModeActive.Satisfies(ModeSemiActive) {
		t.Error("an active collector must not run in a semi-active scan")
	}
}

func TestManifestHostAllowList(t *testing.T) {
	m := Manifest{EgressHosts: []string{"crt.sh", "*.example.com"}}
	for _, ok := range []string{"crt.sh", "CRT.SH", "api.example.com"} {
		if !m.AllowsHost(ok) {
			t.Errorf("AllowsHost(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"evil.com", "crt.sh.evil.com", "notexample.com"} {
		if m.AllowsHost(bad) {
			t.Errorf("AllowsHost(%q) = true, want false", bad)
		}
	}
	if (Manifest{}).AllowsHost("anything") {
		t.Error("a module with an empty allow-list must reach no hosts")
	}
}

func TestValidateManifestCatchesGovernanceMistakes(t *testing.T) {
	// The failure that matters most: a networked collector that forgets to
	// declare egress. It would be allowed to reach anything because there is no
	// allow-list to check against.
	problems := ValidateManifest(Manifest{Name: "x", Version: "1", Consumes: []EntityType{TypeDomain}})
	found := false
	for _, p := range problems {
		if strings.Contains(p, "EgressHosts") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an egress-allow-list problem, got %v", problems)
	}

	good := Manifest{
		Name: "dns-records", Version: "1.0.0", Category: "domain",
		Consumes:    []EntityType{TypeDomain},
		Produces:    []EntityType{TypeIP},
		EgressHosts: []string{"1.1.1.1"},
		Secrets:     []SecretSpec{{Name: "SHODAN"}, {Name: "SHODAN"}},
	}
	problems = ValidateManifest(good)
	for _, p := range problems {
		if strings.Contains(p, "duplicate secret") {
			return // expected
		}
	}
	t.Errorf("expected duplicate secret to be reported, got %v", problems)
}

// selftestName returns a name unique to this run. The registry deliberately panics
// on a duplicate name, so a test that registers must be safe under -count=N.
var selftestSeq atomic.Int64

func selftestName(prefix string) string {
	return prefix + "-" + strconv.FormatInt(selftestSeq.Add(1), 10)
}

func TestRegistry(t *testing.T) {
	name := selftestName("sdk-selftest-module")
	if _, dup := New(name); dup {
		t.Fatal("name already registered")
	}
	Register(func() Module {
		return &ModuleFunc{M: Manifest{Name: name, Version: "1", Consumes: []EntityType{TypeDomain}}}
	})
	if _, ok := New(name); !ok {
		t.Fatal("registered module not found")
	}
	var found bool
	for _, n := range Registered() {
		if n == name {
			found = true
		}
	}
	if !found {
		t.Error("registered module missing from Registered()")
	}
	if m, _ := New(name); m.Manifest().Name != name {
		t.Error("instantiated manifest name mismatch")
	}
}

func TestSelectModulesByConsumedType(t *testing.T) {
	domainOnly := selftestName("selftest-domain-only")
	ipOnly := selftestName("selftest-ip-only")
	Register(func() Module {
		return &ModuleFunc{M: Manifest{Name: domainOnly, Version: "1", Consumes: []EntityType{TypeDomain}, EgressHosts: []string{"example.org"}}}
	})
	Register(func() Module {
		return &ModuleFunc{M: Manifest{Name: ipOnly, Version: "1", Consumes: []EntityType{TypeIP}, EgressHosts: []string{"example.org"}}}
	})

	got := SelectModules([]EntityType{TypeIP}, nil)
	found := false
	for _, n := range got {
		if n == ipOnly {
			found = true
		}
		if n == domainOnly {
			t.Errorf("SelectModules(ip) included a domain-only module: %v", got)
		}
	}
	if !found {
		t.Errorf("SelectModules(ip) = %v, want to include %s", got, ipOnly)
	}

	if got := SelectModules([]EntityType{TypeIP}, map[string]bool{ipOnly: true}); contains(got, ipOnly) {
		t.Errorf("exclusion not honoured: %v", got)
	}
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func TestEntityAttrProvenance(t *testing.T) {
	e := NewEntity(TypeDomain, "example.com")
	e.SetAttr("registrar", "Example Registrar", "obs-1")
	e.SetAttr("registrar", "Example Registrar", "obs-1") // duplicate must not grow the list
	e.SetAttr("registrar", "Example Registrar", "obs-2")
	a := e.Attrs["registrar"]
	if len(a.Obs) != 2 {
		t.Errorf("expected 2 supporting observations, got %v", a.Obs)
	}
	if !e.AddTag("cloud") || e.AddTag("cloud") {
		t.Error("AddTag must report whether the tag was new")
	}
	if !e.HasTag("cloud") {
		t.Error("HasTag failed")
	}
}
