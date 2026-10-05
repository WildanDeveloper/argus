package whois

import (
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// record is one parsed WHOIS response.
//
// WHOIS has no schema. Every server invents its own field names, its own date formats,
// and its own idea of what a blank means, so the parser is built around recognising
// shapes rather than reading a fixed set of keys. That is also why almost every value
// here is optional: a thin record has a registrar and nothing else.
type record struct {
	domainName    string
	registrarName string
	registrarHost string

	nameServers []string
	emails      []labeledEmail
	status      []string

	created string
	expires string
	updated string

	// redacted names the fields the registry withheld rather than left blank.
	redacted []string

	// textual is the raw text kept for rate-limit and empty-result detection, which
	// depend on the whole response rather than on any single field.
	textual string

	// reliability and credibility are set by the module, because they depend on which
	// server answered rather than on anything in the response itself.
	reliability byte
	credibility byte
}

type labeledEmail struct {
	address string
	field   string
}

// keyValues splits a WHOIS response into normalized keys and values.
//
// Servers use "key: value", "key value", and "key\tvalue", and some put the key alone
// on a line. Trying the colon first and falling back keeps a value containing a colon
// -- which timestamps are full of -- from being split at the wrong place.
func keyValues(text string) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		if key == "" || len(key) > 48 {
			continue
		}
		out = append(out, [2]string{key, value})
	}
	return out
}

func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, ':'); i > 0 {
		// A colon inside a timestamp is fine: the first one still separates the key
		// from the value in every format that has a colon at all.
		key := strings.TrimSpace(line[:i])
		if looksLikeKey(key) {
			return key, strings.TrimSpace(line[i+1:]), true
		}
	}
	if i := strings.IndexAny(line, "\t"); i > 0 {
		key := strings.TrimSpace(line[:i])
		if looksLikeKey(key) {
			return key, strings.TrimSpace(line[i+1:]), true
		}
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 && len(fields[0]) <= 48 && looksLikeKey(fields[0]) {
		return fields[0], strings.TrimSpace(strings.TrimPrefix(line, fields[0])), true
	}
	return "", "", false
}

// looksLikeKey keeps prose from being parsed as a field.
func looksLikeKey(k string) bool {
	if k == "" {
		return false
	}
	lower := strings.ToLower(k)
	for _, c := range k {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ' ', c == '/', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	// A key with no letters is a number, not a field name.
	hasLetter := false
	for _, c := range lower {
		if c >= 'a' && c <= 'z' {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

// keyForms maps the many spellings of each concept onto one name.
var keyForms = map[string][]string{
	"registrar": {
		"registrar", "sponsoring registrar", "registrar name", "registrar organization",
		"registrar organisation", "registrar handle", "registrar company",
	},
	"registrarHost": {
		"registrar whois server", "referralserver", "registrar url",
		"whois server", "referral url",
	},
	"nameServer": {
		"name server", "nameserver", "nserver", "name servers", "nameservers",
		"dns", "ns",
	},
	"email": {
		"registrant email", "registrant contact email", "registrant contact",
		"admin email", "administrative contact email", "tech email", "technical contact email",
		"registrar abuse contact email", "abuse contact email", "abuse-mailbox",
		"contact email", "email", "e-mail",
	},
	"status": {
		"domain status", "status", "state", "eppstatus",
	},
	"created": {
		"creation date", "created", "created on", "registered on", "registration time",
		"registered", "domain registration date", "record created", "activated",
	},
	"expires": {
		"registry expiry date", "expiration date", "expires", "expires on",
		"expiry date", "paid-till", "renewal date", "record expires",
		"registrar registration expiration date", "domain expiration date",
	},
	"updated": {
		"updated date", "last updated", "last-update", "modified", "changed",
		"last modified", "domain last updated date",
	},
	"domainName": {
		"domain name", "domain", "domainname", "query", "name",
	},
}

// reverseForms indexes keyForms for a case-insensitive lookup.
var reverseForms = func() map[string]string {
	m := map[string]string{}
	for concept, forms := range keyForms {
		for _, f := range forms {
			m[normalizeKey(f)] = concept
		}
	}
	return m
}()

func normalizeKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.ReplaceAll(k, "_", " ")
	k = strings.ReplaceAll(k, ".", " ")
	k = strings.ReplaceAll(k, "-", " ")
	return strings.Join(strings.Fields(k), " ")
}

// redactionMarkers are the phrases registries publish in place of withheld data.
var redactionMarkers = []string{
	"redacted for privacy",
	"data redacted",
	"not disclosed",
	"privacy protected",
	"privacy redacted",
	"redacted by gdpr",
	"gdpr masked",
	"withheld for privacy",
	"non-public data",
	"personal data",
	"redacted",
	"disclosed?",
}

func isRedacted(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return false
	}
	for _, m := range redactionMarkers {
		if s == m || strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// parseRecord turns a response into a record.
func parseRecord(text string) *record {
	r := &record{textual: text}
	if strings.TrimSpace(text) == "" {
		return r
	}

	for _, kv := range keyValues(text) {
		key, value := kv[0], kv[1]
		concept, known := reverseForms[normalizeKey(key)]
		if !known {
			continue
		}
		if isRedacted(value) {
			r.redacted = appendUnique(r.redacted, normalizeKey(key))
			continue
		}
		switch concept {
		case "registrar":
			if r.registrarName == "" {
				r.registrarName = cleanValue(value)
			}
		case "registrarHost":
			if r.registrarHost == "" {
				r.registrarHost = cleanValue(value)
			}
		case "nameServer":
			for _, ns := range splitList(value) {
				ns = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), "."))
				if ns == "" || !strings.Contains(ns, ".") {
					continue
				}
				// Servers write "ns1.example.test [192.0.2.1]" or
				// "ns1.example.test 192.0.2.1". The address is a companion, not a name,
				// and keeping it would turn it into a phantom subdomain whose value
				// happens to look like a host.
				if net.ParseIP(ns) != nil {
					continue
				}
				r.nameServers = appendUnique(r.nameServers, ns)
			}
		case "email":
			addr := extractEmail(value)
			if addr == "" {
				// Anything the extractor would not hand back whole is recorded as
				// withheld. It is the registry's statement either way, and guessing at
				// the unmasked value would fabricate a contact.
				if isRedacted(value) || looksMasked(value) {
					r.redacted = appendUnique(r.redacted, normalizeKey(key))
				}
				continue
			}
			r.emails = append(r.emails, labeledEmail{address: addr, field: normalizeKey(key)})
		case "status":
			if s := strings.TrimSpace(value); s != "" {
				r.status = appendUnique(r.status, s)
			}
		case "created":
			if r.created == "" {
				r.created = value
			}
		case "expires":
			if r.expires == "" {
				r.expires = value
			}
		case "updated":
			if r.updated == "" {
				r.updated = value
			}
		case "domainName":
			if r.domainName == "" {
				r.domainName = strings.ToLower(cleanValue(value))
			}
		}
	}

	r.nameServers = dedupeSorted(r.nameServers)
	r.status = dedupeSorted(r.status)
	sort.SliceStable(r.emails, func(i, j int) bool { return r.emails[i].field < r.emails[j].field })
	r.redacted = dedupeSorted(r.redacted)
	return r
}

// cleanValue strips the decoration servers wrap around values.
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	// A registrar is often written as "Registrar, Inc." with a trailing ID or IANA
	// number appended in parentheses by aggregators.
	if i := strings.Index(v, " ("); i > 0 && strings.HasSuffix(v, ")") {
		v = strings.TrimSpace(v[:i])
	}
	return strings.Trim(v, "\"")
}

var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// maskRuns are the placeholder characters privacy services substitute for the real
// local part or domain label.
const maskChars = "*xX"

// extractEmail pulls an address out of a field value, and refuses anything that is
// masked.
//
// The refusal matters more than the extraction. Privacy services publish forms like
// "a***b@example.com" and "XXXXX@privacy.xxxx.xxx", and a regex happily matches inside
// them: the first yields "b@example.com", which is not masked at all, is a different
// mailbox than any that exists, and would enter the graph looking like a verified
// contact. So an address is emitted only when it is byte-identical to the field, and
// anything that had to be trimmed or patched to produce a match is treated as withheld.
func extractEmail(v string) string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" || looksMasked(trimmed) {
		return ""
	}
	// The match must span the whole value. A partial match means the field held
	// something other than a bare address, and the remainder is decoration, a mask, or
	// a second address.
	m := emailPattern.FindString(trimmed)
	if m == "" || !strings.EqualFold(m, trimmed) {
		return ""
	}
	if strings.ContainsAny(trimmed, " \t,;<>") {
		return ""
	}
	return strings.ToLower(m)
}

// looksMasked reports whether a value has been obscured.
func looksMasked(v string) bool {
	lower := strings.ToLower(v)
	for _, marker := range []string{"privacy", "redacted", "notdisclosed", "not-disclosed",
		"disclosure", "withheld", "anonymized", "anonymised", "shielded", "obscured"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// A run of three or more identical mask characters is a placeholder, whether it
	// stands in for the local part or for a domain label.
	for _, part := range strings.FieldsFunc(lower, func(r rune) bool {
		return r == '.' || r == '@'
	}) {
		if len(part) >= 3 {
			same := 0
			for i := 0; i < len(part); i++ {
				if !strings.ContainsRune(maskChars, rune(part[i])) {
					break
				}
				same++
			}
			if same >= 3 {
				return true
			}
		}
	}
	return strings.Contains(v, "*")
}

// splitList breaks a value that may hold several entries on one line.
func splitList(v string) []string {
	v = strings.ReplaceAll(v, ",", " ")
	fields := strings.Fields(v)
	// A bracketed host list such as "ns1 [1.2.3.4]" keeps the address too; only the
	// name is wanted, and a bracketed token is skipped by the dot check downstream.
	var out []string
	for _, f := range fields {
		f = strings.Trim(f, "[]")
		out = append(out, f)
	}
	return out
}

// isThick reports whether the record carries registration data beyond a referral.
func (r *record) isThick() bool {
	return len(r.nameServers) > 0 || len(r.emails) > 0 || r.created != "" || r.expires != ""
}

// registrarServer returns the referral address, normalised to host:port.
func (r *record) registrarServer() string {
	h := strings.TrimSpace(r.registrarHost)
	if h == "" {
		return ""
	}
	h = strings.ToLower(h)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i > 0 {
		h = h[:i]
	}
	if !strings.Contains(h, ":") {
		h += ":43"
	}
	if !strings.Contains(h, ".") {
		// A bare label is not a routable WHOIS host. Following it would be a guess, and
		// a guessed referral is worse than no referral.
		return ""
	}
	return h
}

// merge folds a registrar answer into the registry answer.
//
// The registry record wins for anything it stated, because the registry is the
// authoritative source for its own data, and the registrar only fills gaps.
func (r *record) merge(other *record) {
	if r.registrarName == "" {
		r.registrarName = other.registrarName
	}
	if r.registrarHost == "" {
		r.registrarHost = other.registrarHost
	}
	if r.domainName == "" {
		r.domainName = other.domainName
	}
	if r.created == "" {
		r.created = other.created
	}
	if r.expires == "" {
		r.expires = other.expires
	}
	if r.updated == "" {
		r.updated = other.updated
	}
	r.nameServers = dedupeSorted(append(r.nameServers, other.nameServers...))
	r.status = dedupeSorted(append(r.status, other.status...))
	r.redacted = dedupeSorted(append(r.redacted, other.redacted...))

	seen := map[string]bool{}
	for _, e := range r.emails {
		seen[e.address] = true
	}
	for _, e := range other.emails {
		if !seen[e.address] {
			r.emails = append(r.emails, e)
		}
	}
	sort.SliceStable(r.emails, func(i, j int) bool { return r.emails[i].field < r.emails[j].field })
}

// isRateLimited reports whether the response is a refusal rather than an answer.
//
// Registries enforce volume by returning prose instead of a record. Parsing that as a
// record yields a domain with no nameservers and no dates, which looks exactly like a
// sparsely populated entry.
func (r *record) isRateLimited() bool {
	t := strings.ToLower(r.textual)
	markers := []string{
		"whois limit exceeded",
		"limit exceeded",
		"too many requests",
		"rate limit",
		"query rate",
		"queries per",
		"maximum number of queries",
		"you have exceeded",
		"exceeded the maximum",
		"try again later",
		"throttled",
	}
	for _, m := range markers {
		if strings.Contains(t, m) {
			return true
		}
	}
	return false
}

// isEmpty reports whether the server answered that it holds nothing.
//
// This is an authoritative negative and is not the same as a rate limit, a refused
// connection, or a record for a name the server is not authoritative for.
func (r *record) isEmpty() bool {
	t := strings.ToLower(r.textual)
	if strings.TrimSpace(t) == "" {
		return false
	}
	markers := []string{
		"no match for",
		"no entries found",
		"not found",
		"no data found",
		"domain not found",
		"no object found",
		"nothing found",
		"no such domain",
		"domain name not known",
	}
	for _, m := range markers {
		if strings.Contains(t, m) {
			return true
		}
	}
	return false
}

// holdsLock reports whether the name appears to be expiring or held.
func (r *record) holdsLock() bool {
	for _, s := range r.status {
		switch strings.ToLower(s) {
		case "clienthold", "serverhold", "pendingdelete", "redemptionperiod",
			"pendingrenew", "expired":
			return true
		}
	}
	return false
}

// date parses one of the record's timestamps.
//
// WHOIS dates are the worst part of the format: servers publish at least a dozen
// distinct layouts, and several publish several in the same field. Rather than
// enumerate them all and silently drop the rest, the common shapes are attempted in
// order of specificity and the raw value is returned as-is if none parse, so a date
// is never lost entirely.
func (r *record) date(kind string) (time.Time, bool) {
	var raw string
	switch kind {
	case "creation":
		raw = r.created
	case "expiry":
		raw = r.expires
	case "updated":
		raw = r.updated
	default:
		return time.Time{}, false
	}
	return parseDate(raw)
}

var dateLayouts = []string{
	"2006-01-02T15:04:05Z07:00",
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000Z",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"02 Jan 2006",
	"Jan 02 2006",
	"2006/01/02",
	"20060102",
	"02-Jan-2006 15:04:05 MST",
	"2006-01-02T15:04:05.000+0000",
}

func parseDate(raw string) (time.Time, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || isRedacted(s) {
		return time.Time{}, false
	}
	// Strip a trailing parenthetical some servers append.
	if i := strings.IndexByte(s, '('); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	// A two-digit year needs no correction here: Go applies the POSIX pivot, mapping
	// 69-99 into the twentieth century and 00-68 into the twenty-first, which is the
	// convention WHOIS records follow. Shifting the result would move 1970 to 2070,
	// and a registration date in 2070 is not a plausible reading of anything.
	for _, layout := range []string{"02-Jan-06", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
