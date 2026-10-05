package egress

import (
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Resolvers disagree about quoting TXT values. Cloudflare returns
// "v=spf1 -all" and Google returns v=spf1 -all for the same record; if the module
// kept both spellings, consensus between those two providers could never be
// reached and every TXT lookup would fail.
func TestUnquoteTXTMatchesAcrossResolverStyles(t *testing.T) {
	cases := map[string]string{
		`"v=spf1 -all"`:                  "v=spf1 -all",
		`v=spf1 -all`:                    "v=spf1 -all",
		`"part one" "part two"`:          "part onepart two",
		`"a\"b"`:                         `a"b`,
		`  v=spf1 -all  `:                "v=spf1 -all",
		`"google-site-verification=abc"`: "google-site-verification=abc",
	}
	for in, want := range cases {
		if got := unquoteTXT(in); got != want {
			t.Errorf("unquoteTXT(%q) = %q, want %q", in, got, want)
		}
	}
}

// TTL is cache metadata, not part of the answer. Two resolvers returning identical
// records with different remaining TTLs must be counted as agreeing.
func TestAnswerKeyIgnoresTTL(t *testing.T) {
	a := []sdk.DNSRecord{{Type: "A", TTL: 300, Data: "203.0.113.10"}}
	b := []sdk.DNSRecord{{Type: "A", TTL: 42, Data: "203.0.113.10"}}
	if answerKey(a) != answerKey(b) {
		t.Errorf("answer keys differ only by TTL: %q vs %q", answerKey(a), answerKey(b))
	}
	// Order must not matter either.
	c := []sdk.DNSRecord{
		{Type: "A", TTL: 300, Data: "203.0.113.10"},
		{Type: "AAAA", TTL: 300, Data: "2001:db8::10"},
	}
	d := []sdk.DNSRecord{
		{Type: "AAAA", TTL: 900, Data: "2001:db8::10"},
		{Type: "A", TTL: 1, Data: "203.0.113.10"},
	}
	if answerKey(c) != answerKey(d) {
		t.Error("answer keys should not depend on record order")
	}
	// A different data set must not agree.
	e := []sdk.DNSRecord{{Type: "A", TTL: 300, Data: "203.0.113.99"}}
	if answerKey(a) == answerKey(e) {
		t.Error("different addresses must not share an answer key")
	}
}

// MX preference changes which host is tried first, so it is part of the answer.
func TestAnswerKeyKeepsPreference(t *testing.T) {
	a := []sdk.DNSRecord{{Type: "MX", Data: "mail.example.", Pref: 10}}
	b := []sdk.DNSRecord{{Type: "MX", Data: "mail.example.", Pref: 20}}
	if answerKey(a) == answerKey(b) {
		t.Error("MX preference must participate in the answer key")
	}
}

func TestResolverHostsAreExtractable(t *testing.T) {
	hosts := ResolverHosts(defaultDoHProviders)
	if len(hosts) != len(defaultDoHProviders) {
		t.Fatalf("hosts = %v, want %d entries", hosts, len(defaultDoHProviders))
	}
	for _, h := range hosts {
		if h == "" || strings.ToLower(h) != h {
			t.Errorf("host %q is empty or not lower case", h)
		}
	}
}

func TestSplitPreference(t *testing.T) {
	pref, host := splitPreference("10 mail.example.com.")
	if pref != 10 || host != "mail.example.com" {
		t.Errorf("splitPreference = (%d, %q), want (10, mail.example.com)", pref, host)
	}
	pref, host = splitPreference("mail.example.com.")
	if pref != 0 || host != "mail.example.com" {
		t.Errorf("bare host should yield preference 0, got (%d, %q)", pref, host)
	}
}
