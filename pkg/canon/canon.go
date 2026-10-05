// Package canon resolves registrable domains and classifies a name as a domain or
// a subdomain.
//
// This lives outside pkg/sdk on purpose: the SDK must stay dependency-light, and
// eTLD+1 resolution needs the Public Suffix List, which is a data set rather than
// a language facility. Getting this wrong is not cosmetic: "example.com" and
// "www.example.com" must be two entities related by subdomain_of, and the whole
// scope allow-list is written in terms of registrable domains.
package canon

import (
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// eTLDPlus1 returns the registrable domain of a name and its public suffix.
//
// A single-label suffix such as "localhost" or a bare IP has no registrable form;
// the name is returned unchanged so callers can decide what to do rather than
// receiving an empty string and silently mis-scoping.
func eTLDPlus1(name string) (domain, suffix string, ok bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return "", "", false
	}
	if _, err := sdk.Canonicalize(sdk.TypeIP, name); err == nil {
		return "", "", false
	}
	l, err := publicsuffix.Parse(name)
	if err != nil || l == nil || l.TLD == "" || l.SLD == "" {
		// No second-level label means there is no registrable domain: "com" and
		// "localhost" are suffixes, not domains an engagement can own.
		return "", "", false
	}
	// The registrable domain is SLD + TLD. TRD is everything above it.
	return l.SLD + "." + l.TLD, l.TLD, true
}

// RegistrableDomain returns the eTLD+1 of name, or name itself when it has none.
func RegistrableDomain(name string) string {
	if d, _, ok := eTLDPlus1(name); ok {
		return d
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// PublicSuffix returns the suffix of name.
func PublicSuffix(name string) string {
	if _, s, ok := eTLDPlus1(name); ok {
		return s
	}
	return ""
}

// Classify returns the entity type for a host name: TypeDomain for a
// registrable domain, TypeSubdomain for anything below it.
//
// The distinction is what makes subdomain_of a meaningful edge. Collapsing the two
// would make a scope rule for "example.com" silently cover every host on a
// third-party CDN that happens to share the name.
func Classify(name string) sdk.EntityType {
	domain, _, ok := eTLDPlus1(name)
	if !ok {
		return sdk.TypeSubdomain
	}
	if strings.EqualFold(domain, name) {
		return sdk.TypeDomain
	}
	return sdk.TypeSubdomain
}

// IsSubdomain reports whether name sits strictly below a registrable domain.
func IsSubdomain(name string) bool {
	return Classify(name) == sdk.TypeSubdomain
}

// Entity builds a correctly typed entity for a host name.
func Entity(name string) sdk.Entity {
	return sdk.NewEntity(Classify(name), name)
}

// EntityOrErr is Entity with the canonicalization error surfaced.
func EntityOrErr(name string) (sdk.Entity, error) {
	t := Classify(name)
	e, err := sdk.NewEntityOrErr(t, name)
	if err != nil {
		return sdk.Entity{}, err
	}
	return e, nil
}

// IsInScopeDomain reports whether candidate is the same registrable domain as
// scopeDomain, or a subdomain of it. It is the test used to decide whether a
// discovered host belongs to the engagement's asset.
func IsInScopeDomain(candidate, scopeDomain string) bool {
	c := RegistrableDomain(candidate)
	s := RegistrableDomain(scopeDomain)
	if c == "" || s == "" {
		return false
	}
	if c == s {
		return true
	}
	// The dot-prefixed suffix test is what keeps "notexample.com" and
	// "example.com.evil.com" out of scope: matching must be anchored at a label
	// boundary, not a substring test.
	return strings.HasSuffix(c, "."+s)
}
