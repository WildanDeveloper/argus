package canon

import (
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

func TestClassifyDomainVersusSubdomain(t *testing.T) {
	// The distinction that makes subdomain_of meaningful and stops a scope rule for
	// "example.com" from silently covering a look-alike.
	cases := map[string]sdk.EntityType{
		"example.com":              sdk.TypeDomain,
		"example.co.uk":            sdk.TypeDomain,
		"acme.co.id":               sdk.TypeDomain,
		"www.example.com":          sdk.TypeSubdomain,
		"a.b.c.example.com":        sdk.TypeSubdomain,
		"portal.acme.example":      sdk.TypeSubdomain,
		"deep.portal.acme.example": sdk.TypeSubdomain,
	}
	for name, want := range cases {
		if got := Classify(name); got != want {
			t.Errorf("Classify(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.example.com":   "example.com",
		"example.com":       "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"co.uk":             "co.uk", // no SLD: returned unchanged
		"localhost":         "localhost",
		"1.1.1.1":           "1.1.1.1",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEntityTypesAreDistinct(t *testing.T) {
	// The apex and a subdomain must be separate entities with a real edge between
	// them, not two names for one thing.
	apex := Entity("example.com")
	www := Entity("www.example.com")
	if apex.ID == www.ID {
		t.Fatal("apex and subdomain collapsed into one entity")
	}
	if apex.Type != sdk.TypeDomain || www.Type != sdk.TypeSubdomain {
		t.Errorf("types = %q and %q", apex.Type, www.Type)
	}
}

func TestIsInScopeDomain(t *testing.T) {
	yes := []string{"example.com", "www.example.com", "a.b.example.com"}
	for _, c := range yes {
		if !IsInScopeDomain(c, "example.com") {
			t.Errorf("%q should be in scope of example.com", c)
		}
	}
	no := []string{
		"evil.com",
		"example.com.evil.com", // suffix spoof
		"notexample.com",       // substring, not a label boundary
		"example.commercial",   // different TLD
		"example.org",
	}
	for _, c := range no {
		if IsInScopeDomain(c, "example.com") {
			t.Errorf("%q must NOT be in scope of example.com", c)
		}
	}
}

func TestPublicSuffix(t *testing.T) {
	if got := PublicSuffix("www.example.co.uk"); got != "co.uk" {
		t.Errorf("PublicSuffix = %q, want co.uk", got)
	}
}

func TestEntityRejectsGarbage(t *testing.T) {
	if _, err := EntityOrErr(""); err == nil {
		t.Error("an empty name should not produce an entity")
	}
}
