package whois

import "testing"

// Registries and privacy services mask contact addresses in ways that still look like
// addresses. If one of those becomes an email entity, the graph carries a fabricated
// contact.
func TestMaskedEmailsMasked(t *testing.T) {
	for _, v := range []string{
		"XXXXX@privacy.xxxx.xxx",
		"xxxxx@privacyprotect.org",
		"redacted@redacted.for.privacy",
		"a***b@example.com",
		"1234567890@shielded.com",
		"xxxx@example.com",
		"***@example.com",
		"ab***cd@example.org",
	} {
		r := parseRecord("Registrant Email: " + v + "\n")
		for _, e := range r.emails {
			t.Errorf("parseRecord emitted %q from masked input %q as an email entity", e.address, v)
		}
		if len(r.redacted) == 0 {
			t.Errorf("masked input %q was not recorded as withheld", v)
		}
	}
}

// A partial match inside a decorated field must never be emitted. "abuse@example.com
// (registrar)" carries a real address, but so does "a***b@example.com" and the two are
// indistinguishable to a regex.
func TestOnlyBareAddressesAreEmitted(t *testing.T) {
	for _, v := range []string{
		"abuse@example.com (registrar)",
		"Email: abuse@example.com",
		"<abuse@example.com>",
	} {
		r := parseRecord("Registrar Abuse Contact Email: " + v + "\n")
		if len(r.emails) != 0 {
			t.Errorf("%q produced %v; only a bare address may be emitted", v, r.emails)
		}
	}
	// A plain address is still taken.
	r := parseRecord("Registrar Abuse Contact Email: abuse@example-registrar.test\n")
	if len(r.emails) != 1 || r.emails[0].address != "abuse@example-registrar.test" {
		t.Errorf("a plain address was not accepted: %v", r.emails)
	}
}

// Two addresses in one field must not be reduced to one arbitrarily.
func TestMultipleAddressesInOneFieldAreNotPickedApart(t *testing.T) {
	r := parseRecord("Registrant Email: first@example.com second@example.com\n")
	if len(r.emails) != 0 {
		t.Errorf("a field with two addresses produced %v; picking one arbitrarily is a guess", r.emails)
	}
}
