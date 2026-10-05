package whois

import (
	"strings"
	"testing"
	"time"
)

func TestParseThinRegistryRecord(t *testing.T) {
	r := parseRecord(thinCom)
	if r.registrarName != "RESERVED-Internet Assigned Numbers Authority" {
		t.Errorf("registrar = %q", r.registrarName)
	}
	if got := r.nameServers; len(got) != 2 ||
		got[0] != "a.iana-servers.net" || got[1] != "b.iana-servers.net" {
		t.Errorf("name servers = %v", got)
	}
	if d, ok := r.date("creation"); !ok || !d.Equal(time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC)) {
		t.Errorf("creation = %v ok=%v", d, ok)
	}
	if d, ok := r.date("expiry"); !ok || d.Year() != 2027 {
		t.Errorf("expiry = %v ok=%v", d, ok)
	}
	if !r.isThick() {
		t.Error("a record with nameservers and dates is not thin")
	}
}

func TestParseRegistrarRecord(t *testing.T) {
	r := parseRecord(registrarThick)
	if r.registrarName != "Example Registrar Inc." {
		t.Errorf("registrar = %q", r.registrarName)
	}
	if r.registrarServer() != "whois.example-registrar.test:43" {
		t.Errorf("referral = %q", r.registrarServer())
	}
	if len(r.nameServers) != 2 {
		t.Errorf("name servers = %v", r.nameServers)
	}
	if len(r.status) != 1 || !strings.Contains(r.status[0], "clientTransferProhibited") {
		t.Errorf("status = %v", r.status)
	}
	// The abuse address is published; the redacted registrant address must not be.
	var addresses []string
	for _, e := range r.emails {
		addresses = append(addresses, e.address)
	}
	if len(addresses) != 1 || addresses[0] != "abuse@example-registrar.test" {
		t.Errorf("emails = %v; only the published address should be kept", addresses)
	}
	if len(r.redacted) == 0 {
		t.Error("no withheld fields recorded")
	}
}

func TestRedactionMarkers(t *testing.T) {
	// Registries publish a range of phrases. Every one of them means the data exists
	// and is withheld, and none of them is a value.
	for _, phrase := range []string{
		"REDACTED FOR PRIVACY", "Data Redacted", "Not Disclosed",
		"Privacy Protected", "Withheld for privacy", "REDACTED BY GDPR",
		"Non-public Data", "Personal Data",
	} {
		if !isRedacted(phrase) {
			t.Errorf("%q was not recognised as withheld", phrase)
		}
	}
	for _, real := range []string{"Example Registrar Inc.", "abuse@example-registrar.test", ""} {
		if real != "" && isRedacted(real) {
			t.Errorf("%q was mistaken for a redaction marker", real)
		}
	}
}

func TestRateLimitedIsNotAnEmptyRecord(t *testing.T) {
	// Registries enforce volume with prose. Parsed as a record that yields a domain
	// with no nameservers and no dates, which is indistinguishable from a sparse entry.
	r := parseRecord(rateLimited)
	if !r.isRateLimited() {
		t.Error("a volume refusal was not detected")
	}
	if r.isEmpty() {
		t.Error("a volume refusal was read as an authoritative negative")
	}
}

func TestEmptyIsDetected(t *testing.T) {
	for _, body := range []string{
		noRecord,
		"No Entries Found for the selected source.",
		"NOT FOUND\n",
		"Domain not found.",
		"%% no object found %%",
	} {
		r := parseRecord(body)
		if !r.isEmpty() {
			t.Errorf("%q was not recognised as an authoritative negative", body)
		}
		if r.isRateLimited() {
			t.Errorf("%q was misread as a volume refusal", body)
		}
	}
	// A populated record must never read as empty.
	if parseRecord(thinCom).isEmpty() {
		t.Error("a populated record was read as an authoritative negative")
	}
	// Neither must an empty body, which is a failed read rather than a negative.
	if parseRecord("").isEmpty() {
		t.Error("an empty body was read as an authoritative negative")
	}
}

func TestDateLayouts(t *testing.T) {
	// WHOIS dates are the worst of the format: at least a dozen layouts, and some
	// servers publish several in one field. A date that does not parse must still
	// survive, so this checks both the shapes that work and that the raw value is not
	// silently dropped.
	cases := map[string]bool{
		"1995-08-14T04:00:00Z":       true,
		"1995-08-14T04:00:00.000Z":   true,
		"1995-08-14T04:00:00+00:00":  true,
		"1995-08-14 04:00:00":        true,
		"1995-08-14":                 true,
		"14-Aug-1995":                true,
		"14 Aug 1995":                true,
		"Aug 14 1995":                true,
		"1995/08/14":                 true,
		"19950814":                   true,
		"1995-08-14T04:00:00Z (UTC)": true,
		"not a date at all":          false,
		"":                           false,
		"REDACTED":                   false,
	}
	for in, wantOK := range cases {
		_, ok := parseDate(in)
		if ok != wantOK {
			t.Errorf("parseDate(%q) ok = %v, want %v", in, ok, wantOK)
		}
	}
}

func TestTwoDigitYearsUseTheConventionRegistriesUse(t *testing.T) {
	// A two-digit year needs the century pinned or it is a silent corruption. The
	// convention is POSIX: 69-99 are the twentieth century, 00-68 the twenty-first.
	// My first expectation here was the opposite, which would have moved a 1970
	// registration to 2070.
	for in, want := range map[string]int{
		"14-Aug-69": 1969,
		"14-Aug-70": 1970,
		"14-Aug-99": 1999,
		"14-Aug-00": 2000,
		"14-Aug-49": 2049,
		"14-Aug-68": 2068,
	} {
		d, ok := parseDate(in)
		if !ok {
			t.Errorf("parseDate(%q) did not parse", in)
			continue
		}
		if d.Year() != want {
			t.Errorf("parseDate(%q) year = %d, want %d", in, d.Year(), want)
		}
	}
}

func TestProseIsNotParsedAsAField(t *testing.T) {
	// A line of prose must not become a field. Splitting it on the first colon and
	// accepting whatever precedes it is how "Terms of Use: https://..." becomes a
	// registrar.
	text := `Terms of Use: https://www.verisign.com/domain-names/registration-data-access-protocol/
Please note: the data is for informational purposes
>>> Last update of whois database: 2026-09-01T00:00:00Z <<<
`
	r := parseRecord(text)
	if r.registrarName != "" {
		t.Errorf("prose became a registrar: %q", r.registrarName)
	}
	if len(r.nameServers) != 0 || len(r.emails) != 0 {
		t.Errorf("prose produced fields: ns=%v emails=%v", r.nameServers, r.emails)
	}
}

func TestSeparatorsAreAllAccepted(t *testing.T) {
	// Servers use "key: value", "key value", and tab-separated. Missing one of these
	// loses fields silently on whichever server uses it.
	for _, text := range []string{
		"Registrar: Example Registrar Inc.\n",
		"Registrar Example Registrar Inc.\n",
		"Registrar\tExample Registrar Inc.\n",
		"REGISTRAR: Example Registrar Inc.\n",
	} {
		r := parseRecord(text)
		if r.registrarName != "Example Registrar Inc." {
			t.Errorf("%q parsed to %q", text, r.registrarName)
		}
	}
}

func TestNameServerValuesThatAlsoCarryAddresses(t *testing.T) {
	// Some servers write "ns1.example.test [1.2.3.4]" or "ns1.example.test 1.2.3.4".
	// Only the name is wanted, and an address here would become a phantom subdomain.
	for _, value := range []string{
		"ns1.example.test [192.0.2.1]",
		"ns1.example.test 192.0.2.1",
		"ns1.example.test,",
	} {
		r := parseRecord("Name Server: " + value + "\n")
		if len(r.nameServers) != 1 || r.nameServers[0] != "ns1.example.test" {
			t.Errorf("%q produced %v", value, r.nameServers)
		}
	}
}

func TestReferralNormalisation(t *testing.T) {
	cases := map[string]string{
		"whois.example-registrar.test":          "whois.example-registrar.test:43",
		"WHOIS.EXAMPLE-REGISTRAR.TEST":          "whois.example-registrar.test:43",
		"whois.example-registrar.test:43":       "whois.example-registrar.test:43",
		"http://whois.example-registrar.test/x": "whois.example-registrar.test:43",
		"whois.example-registrar.test:4343":     "whois.example-registrar.test:4343",
		// A bare label is not a routable host, and a guessed referral is worse than none.
		"registrar": "",
		"":          "",
	}
	for in, want := range cases {
		r := &record{registrarHost: in}
		if got := r.registrarServer(); got != want {
			t.Errorf("registrarServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMergeKeepsTheRegistryValue(t *testing.T) {
	// The registry is authoritative for its own data, so the registrar only fills
	// gaps. Letting the registrar overwrite a registry date would let a stale or
	// wrong registrar record contradict the authoritative source.
	registry := &record{
		registrarName: "Registry Registrar Ltd",
		created:       "1995-08-14T04:00:00Z",
		expires:       "2027-08-13T04:00:00Z",
		nameServers:   []string{"ns.registry.test"},
	}
	registrar := &record{
		registrarName: "Different Registrar Ltd",
		created:       "2000-01-01T00:00:00Z",
		expires:       "2026-01-01T00:00:00Z",
		nameServers:   []string{"ns.registrar.test"},
		emails:        []labeledEmail{{address: "abuse@registrar.test", field: "abuse"}},
	}
	registry.merge(registrar)

	if registry.registrarName != "Registry Registrar Ltd" {
		t.Errorf("registrar = %q; the registry value must win", registry.registrarName)
	}
	if !strings.Contains(registry.created, "1995") {
		t.Errorf("created = %q; the registry value must win", registry.created)
	}
	if len(registry.nameServers) != 2 {
		t.Errorf("name servers = %v; the registrar's should be added", registry.nameServers)
	}
	if len(registry.emails) != 1 {
		t.Errorf("emails = %v; the registrar's should be filled in", registry.emails)
	}
}

func TestHoldsLock(t *testing.T) {
	for _, status := range []string{"clientHold", "serverhold", "pendingDelete", "redemptionPeriod", "EXPIRED"} {
		r := parseRecord("Domain Status: " + status + "\n")
		if !r.holdsLock() {
			t.Errorf("%q was not recognised as a hold", status)
		}
	}
	if parseRecord(thinCom).holdsLock() {
		t.Error("an ordinary record was treated as a hold")
	}
}

func TestUnknownFieldNamesAreIgnored(t *testing.T) {
	// A server inventing a field must not break the ones already understood.
	r := parseRecord("Domain Name: example.com\nSome Future Field: whatever\nRegistrar: Example Ltd\n")
	if r.registrarName != "Example Ltd" {
		t.Errorf("an unknown field disturbed parsing: %q", r.registrarName)
	}
}

func TestEmptyResponseParsesToAnEmptyRecord(t *testing.T) {
	r := parseRecord("")
	if r == nil {
		t.Fatal("an empty response must still produce a record")
	}
	if r.isThick() {
		t.Error("an empty response parsed as thick")
	}
	if len(r.nameServers) != 0 || len(r.emails) != 0 {
		t.Errorf("an empty response produced fields: %v %v", r.nameServers, r.emails)
	}
}

func TestNormalizeKeyFoldsSeparators(t *testing.T) {
	// Servers spell the same field as "Name_Server", "name-server" and "name server".
	for _, k := range []string{"Name_Server", "name-server", "name server", "NAMESERVER"} {
		if _, ok := reverseForms[normalizeKey(k)]; !ok {
			t.Errorf("%q did not normalize to a known concept", k)
		}
	}
}
