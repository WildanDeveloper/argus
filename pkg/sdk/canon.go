package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/sha3"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// idnaProfile is deliberately not idna.Lookup: a few legitimate DNS names
// contain underscores and long labels, and Argus must be able to canonicalize
// observed (not merely resolvable) names. We still map and reject invalid
// sequences.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
	idna.BidiRule(),
)

var (
	reASN     = regexp.MustCompile(`^(?i)as(\d{1,10})$`)
	reCVE     = regexp.MustCompile(`^(?i)cve-(\d{4})-(\d{4,7})$`)
	reE164    = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)
	reAccount = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,39}):(.+)$`)
	rePURL    = regexp.MustCompile(`^pkg:[a-zA-Z0-9.+-]+/.+`)
	reWallet  = regexp.MustCompile(`^(?i)(bitcoin|btc|ethereum|eth|tron|trx|solana|sol|ltc|bch|xmr|ripple|xrp):?([0-9a-z]{8,128})$`)
	reGeo     = regexp.MustCompile(`^-?\d{1,3}(?:\.\d+)?,\s*-?\d{1,3}(?:\.\d+)?(@\d+)?$`)
)

// trackingParams are stripped during URL canonicalization. Keeping them would
// make two references to the same page look like two distinct entities.
var trackingParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true,
	"utm_term": true, "utm_content": true, "utm_id": true,
	"utm_name": true, "utm_reader": true, "utm_brand": true,
	"utm_social": true, "utm_social-type": true,
	"gclid": true, "gclsrc": true, "dclid": true, "gbraid": true, "wbraid": true,
	"fbclid": true, "msclkid": true, "yclid": true, "twclid": true,
	"igshid": true, "mc_cid": true, "mc_eid": true,
	"_ga": true, "_gl": true, "ref": true, "referrer": true,
	"spm": true, "scm": true, "trk": true, "trkCampaign": true,
	"vero_id": true, "oly_enc_id": true, "oly_anon_id": true,
	"hsCtaTracking": true, "__hssc": true, "__hstc": true, "__hsfp": true,
}

// defaultPorts are removed so that https://x:443/ and https://x/ agree.
var defaultPorts = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443"}

// Canonicalize returns the canonical form of value for the given entity type.
//
// Canonical form is the input to NewEntityID, so it must be a pure function of
// the value alone: no network, no clock, no randomness. Two analysts on two
// machines must derive byte-identical IDs for the same real-world thing.
func Canonicalize(t EntityType, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", &UnknownEntityError{Type: t, Value: value, Why: "empty"}
	}

	switch t {
	case TypeDomain, TypeSubdomain:
		return canonDomain(v)
	case TypeIP:
		return canonIP(v)
	case TypeCIDR:
		return canonCIDR(v)
	case TypeASN:
		return canonASN(v)
	case TypeURL:
		return canonURL(v)
	case TypeEmail:
		return canonEmail(v)
	case TypeUsername:
		// Platforms disagree on case sensitivity, so the SDK does not case-fold.
		// Callers that know the platform should lower-case before calling.
		return norm.NFC.String(v), nil
	case TypeAccount:
		return canonAccount(v)
	case TypePhone:
		return canonPhone(v)
	case TypePerson, TypeOrg, TypeLocation:
		return canonText(t, v)
	case TypeGeo:
		return canonGeo(v)
	case TypeFile, TypeImage:
		// Identity is the SHA-256 of content, supplied by the collector.
		return lowerHex(v)
	case TypeHash:
		return canonHash(v)
	case TypeCert:
		return canonHash(v)
	case TypeCVE:
		return canonCVE(v)
	case TypeWallet:
		return canonWallet(v)
	case TypeTx:
		if i := strings.IndexByte(v, ':'); i > 0 {
			return strings.ToLower(v[:i]) + ":" + strings.ToLower(v[i+1:]), nil
		}
		return "", &UnknownEntityError{Type: t, Value: value, Why: "transaction must be chain:hash"}
	case TypeApp:
		return lowerNfc(v)
	case TypeRepo:
		return canonRepo(v)
	case TypePackage:
		return canonPackage(v)
	case TypeIOC:
		return lowerNfc(v)
	case TypeText:
		// Free text is content-addressed by the caller (see NewTextEntity).
		return norm.NFC.String(v), nil
	case TypeFinding:
		// Findings are hashed by kind + subject + key attributes; see NewFinding.
		return lowerNfc(v)
	}
	return "", &UnknownEntityError{Type: t, Value: value, Why: "unknown entity type"}
}

func canonDomain(v string) (string, error) {
	// Strip any scheme or path a careless collector handed us.
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	// A bracketed IPv6 literal with a port is an IP entity, not a domain.
	if strings.HasPrefix(v, "[") {
		return canonIP(v)
	}
	// Drop an explicit port. A DNS name cannot otherwise contain a colon, so the
	// last colon followed only by digits is unambiguously a port. Without this,
	// "example.com:443" and "example.com" would become two domains.
	if i := strings.LastIndexByte(v, ':'); i > 0 && allDigits(v[i+1:]) {
		v = v[:i]
	}
	// A single trailing dot is legal in DNS presentation format but must not
	// create a second entity.
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return "", &UnknownEntityError{Type: TypeDomain, Value: v, Why: "empty after trimming"}
	}
	// Numeric-only labels that parse as an IP are an IP, not a domain.
	if net.ParseIP(v) != nil {
		return canonIP(v)
	}
	ascii, err := idnaProfile.ToASCII(v)
	if err != nil {
		return "", &UnknownEntityError{Type: TypeDomain, Value: v, Why: "IDNA: " + err.Error()}
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || len(ascii) > 253 {
		return "", &UnknownEntityError{Type: TypeDomain, Value: v, Why: "length out of range"}
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", &UnknownEntityError{Type: TypeDomain, Value: v, Why: "empty label"}
		}
	}
	return ascii, nil
}

func canonIP(v string) (string, error) {
	// net.ParseIP rejects zone identifiers, brackets, and ports. Collectors hand
	// us all of those, so reduce every accepted spelling to the bare address
	// before parsing: "[2001:db8::1]:443", "2001:db8::1%eth0", and "2001:db8::1"
	// must all be one IP entity.
	if strings.HasPrefix(v, "[") {
		if j := strings.IndexByte(v, ']'); j > 0 {
			v = v[1:j]
		} else {
			return "", &UnknownEntityError{Type: TypeIP, Value: v, Why: "unterminated '['"}
		}
	}
	if i := strings.IndexByte(v, '%'); i > 0 {
		v = v[:i]
	}
	if ip := net.ParseIP(v); ip != nil {
		// ip.String() emits RFC 5952 compressed form for v6, dotted quad for v4.
		return ip.String(), nil
	}
	// A bare "host:port" where host is not already bracketed.
	if i := strings.LastIndexByte(v, ':'); i > 0 && allDigits(v[i+1:]) {
		if ip := net.ParseIP(v[:i]); ip != nil {
			return ip.String(), nil
		}
	}
	return "", &UnknownEntityError{Type: TypeIP, Value: v, Why: "not an IP address"}
}

func allDigits(s string) bool {
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

func canonCIDR(v string) (string, error) {
	_, n, err := net.ParseCIDR(v)
	if err != nil {
		return "", &UnknownEntityError{Type: TypeCIDR, Value: v, Why: err.Error()}
	}
	return n.String(), nil
}

func canonASN(v string) (string, error) {
	m := reASN.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", &UnknownEntityError{Type: TypeASN, Value: v, Why: "expected AS<number>"}
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || n == 0 {
		return "", &UnknownEntityError{Type: TypeASN, Value: v, Why: "ASN out of range"}
	}
	return "AS" + strconv.FormatUint(n, 10), nil
}

func canonURL(v string) (string, error) {
	u, err := url.Parse(v)
	if err != nil {
		return "", &UnknownEntityError{Type: TypeURL, Value: v, Why: err.Error()}
	}
	if u.Scheme == "" {
		// Assume https rather than rejecting: collectors frequently see bare
		// "//host/path" or "host/path" from HTML.
		if strings.HasPrefix(v, "//") {
			u.Scheme = "https"
		} else {
			return "", &UnknownEntityError{Type: TypeURL, Value: v, Why: "missing scheme"}
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Host == "" {
		return "", &UnknownEntityError{Type: TypeURL, Value: v, Why: "missing host"}
	}

	host := u.Hostname()
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		host = ip.String()
	} else {
		a, err := idnaProfile.ToASCII(host)
		if err != nil {
			return "", &UnknownEntityError{Type: TypeURL, Value: v, Why: "IDNA: " + err.Error()}
		}
		host = strings.ToLower(a)
	}
	port := u.Port()
	if port == "" || defaultPorts[u.Scheme] == port {
		u.Host = host
	} else {
		u.Host = host + ":" + port
	}

	u.Fragment = ""
	u.RawFragment = ""

	if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery = stripTracking(u.RawQuery)

	return u.String(), nil
}

func stripTracking(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var keep []kv
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if trackingParams[k] {
			continue
		}
		keep = append(keep, kv{k, v})
	}
	if len(keep) == 0 {
		return ""
	}
	parts := make([]string, 0, len(keep))
	for _, p := range keep {
		if p.v == "" {
			parts = append(parts, p.k)
		} else {
			parts = append(parts, p.k+"="+p.v)
		}
	}
	return strings.Join(parts, "&")
}

func canonEmail(v string) (string, error) {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	at := strings.LastIndex(v, "@")
	if at <= 0 || at == len(v)-1 {
		return "", &UnknownEntityError{Type: TypeEmail, Value: v, Why: "missing local part or domain"}
	}
	local, domain := v[:at], v[at+1:]
	if strings.ContainsAny(local, " \t") {
		return "", &UnknownEntityError{Type: TypeEmail, Value: v, Why: "whitespace in local part"}
	}
	d, err := canonDomain(domain)
	if err != nil {
		return "", err
	}
	// Appendix A: lowercase the domain, preserve the local part. Provider-aware
	// aliasing (googlemail.com vs gmail.com, plus-addressing) is recorded by the
	// normalizer as an alias relation, never silently merged.
	return local + "@" + d, nil
}

func canonAccount(v string) (string, error) {
	v = norm.NFC.String(strings.TrimSpace(v))
	platform, handle, ok := strings.Cut(v, ":")
	if !ok {
		return "", &UnknownEntityError{Type: TypeAccount, Value: v, Why: "expected platform:handle"}
	}
	platform = strings.ToLower(strings.TrimSpace(platform))
	handle = strings.TrimSpace(handle)
	if platform == "" || handle == "" {
		return "", &UnknownEntityError{Type: TypeAccount, Value: v, Why: "empty platform or handle"}
	}
	if !reAccount.MatchString(platform + ":x") {
		return "", &UnknownEntityError{Type: TypeAccount, Value: v, Why: "invalid platform"}
	}
	// Handles are case-sensitive on some platforms; keep them but bound length.
	if len(handle) > 128 {
		return "", &UnknownEntityError{Type: TypeAccount, Value: v, Why: "handle too long"}
	}
	return platform + ":" + handle, nil
}

func canonPhone(v string) (string, error) {
	// Convert "+62 812-3456-789" and "(+62) 812 3456 789" to E.164.
	var b strings.Builder
	b.WriteByte('+')
	digits := 0
	for _, r := range v {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
			digits++
		}
	}
	if digits == 0 {
		return "", &UnknownEntityError{Type: TypePhone, Value: v, Why: "no digits"}
	}
	out := b.String()
	if !reE164.MatchString(out) {
		return "", &UnknownEntityError{Type: TypePhone, Value: v, Why: "not E.164"}
	}
	return out, nil
}

// canonText normalizes a human name or organization. We apply Unicode NFC and
// collapse whitespace, but deliberately do NOT strip legal suffixes: the entity
// resolver (internal/er) owns that decision so that the merge stays reversible
// and explainable.
func canonText(t EntityType, v string) (string, error) {
	s := norm.NFC.String(v)
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "", &UnknownEntityError{Type: t, Value: v, Why: "empty after normalization"}
	}
	return s, nil
}

// canonGeo accepts "lat,lon", "lat,lon@precision" or a plain float pair.
func canonGeo(v string) (string, error) {
	m := reGeo.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", &UnknownEntityError{Type: TypeGeo, Value: v, Why: "expected lat,lon[@precision]"}
	}
	lat, err1 := strconv.ParseFloat(m[1], 64)
	lon, err2 := strconv.ParseFloat(m[2], 64)
	if err1 != nil || err2 != nil {
		return "", &UnknownEntityError{Type: TypeGeo, Value: v, Why: "non-numeric coordinate"}
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return "", &UnknownEntityError{Type: TypeGeo, Value: v, Why: "coordinate out of range"}
	}
	prec := ""
	if m[3] != "" {
		prec = m[3]
	}
	return fmt.Sprintf("%.6f,%.6f%s", lat, lon, prec), nil
}

func canonHash(v string) (string, error) {
	v = strings.TrimSpace(v)
	v = strings.ToLower(v)
	if i := strings.IndexByte(v, ':'); i > 0 {
		alg, hexPart := v[:i], v[i+1:]
		hexPart = strings.TrimPrefix(hexPart, "0x")
		if !isHex(hexPart) {
			return "", &UnknownEntityError{Type: TypeHash, Value: v, Why: "non-hex digest"}
		}
		return alg + ":" + hexPart, nil
	}
	hexPart := strings.TrimPrefix(v, "0x")
	if !isHex(hexPart) {
		return "", &UnknownEntityError{Type: TypeHash, Value: v, Why: "non-hex digest"}
	}
	// Infer the algorithm from digest length so "5d41402a..." and
	// "sha256:5d41402a..." produce one entity, not two.
	switch len(hexPart) {
	case 32:
		return "md5:" + hexPart, nil
	case 40:
		return "sha1:" + hexPart, nil
	case 64:
		return "sha256:" + hexPart, nil
	case 128:
		return "sha512:" + hexPart, nil
	}
	return "", &UnknownEntityError{Type: TypeHash, Value: v, Why: "unrecognized digest length"}
}

func canonCVE(v string) (string, error) {
	m := reCVE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", &UnknownEntityError{Type: TypeCVE, Value: v, Why: "expected CVE-YYYY-NNNN"}
	}
	year, _ := strconv.Atoi(m[1])
	num, _ := strconv.Atoi(m[2])
	if year < 1999 || year > 2999 {
		return "", &UnknownEntityError{Type: TypeCVE, Value: v, Why: "implausible year"}
	}
	return fmt.Sprintf("CVE-%04d-%04d", year, num), nil
}

// canonWallet normalizes a blockchain address. EVM addresses use EIP-55
// checksum casing; other chains are lower-cased with the chain prefixed.
func canonWallet(v string) (string, error) {
	s := strings.TrimSpace(v)
	chain, addr := "", s
	if i := strings.Index(s, ":"); i > 0 {
		chain, addr = strings.ToLower(s[:i]), s[i+1:]
	}
	addr = strings.TrimSpace(addr)
	switch chain {
	case "ethereum", "eth":
		if c, err := canonEIP55(addr); err == nil {
			if chain == "eth" {
				chain = "ethereum"
			}
			return chain + ":" + c, nil
		}
	}
	lower := strings.ToLower(addr)
	switch {
	case chain == "bitcoin" || chain == "btc":
		return "bitcoin:" + lower, nil
	case chain == "" && reWallet.MatchString("bitcoin:"+lower):
		return "bitcoin:" + lower, nil
	}
	if chain == "" {
		return "", &UnknownEntityError{Type: TypeWallet, Value: v, Why: "missing chain prefix"}
	}
	return chain + ":" + lower, nil
}

// canonEIP55 applies the EIP-55 mixed-case checksum.
//
// Two details matter and are easy to get wrong:
//  1. the digest is Keccak-256 (the original padding used by Ethereum), not
//     NIST SHA3-256 and not SHA-256. x/crypto exposes it as LegacyKeccak256.
//  2. the hashed input is the lower-case hex *without* the "0x" prefix.
//
// Getting either wrong still yields a valid-looking checksum, so it fails
// silently: two clients would disagree about the address casing and produce two
// wallet entities for the same address.
func canonEIP55(addr string) (string, error) {
	addr = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(addr)), "0x")
	if len(addr) != 40 || !isHex(addr) {
		return "", fmt.Errorf("not a 20-byte EVM address")
	}
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(addr))
	sum := h.Sum(nil)

	var b strings.Builder
	b.WriteString("0x")
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		nibble := sum[i/2]
		if i%2 == 0 {
			nibble >>= 4
		} else {
			nibble &= 0x0f
		}
		if nibble >= 8 {
			b.WriteByte(upperHex(c))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func canonRepo(v string) (string, error) {
	s := norm.NFC.String(strings.TrimSpace(v))
	for _, prefix := range []string{"https://", "http://", "git://", "ssh://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	s = strings.TrimPrefix(s, "www.")
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, "/")
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return "", &UnknownEntityError{Type: TypeRepo, Value: v, Why: "expected host/owner/name"}
	}
	// Preserve the host case-insensitively but the owner/repo as published:
	// several forges are case-sensitive about repository names.
	host := strings.ToLower(parts[0])
	owner, name := parts[len(parts)-2], parts[len(parts)-1]
	return host + "/" + owner + "/" + name, nil
}

func canonPackage(v string) (string, error) {
	s := norm.NFC.String(strings.TrimSpace(v))
	if rePURL.MatchString(s) {
		return lowerNfc(s)
	}
	// Accept npm-style and bare "namespace/name" shorthand used by collectors.
	if i := strings.IndexByte(s, '@'); i > 0 && !strings.HasPrefix(s, "@") {
		ns, err1 := lowerNfc(s[:i])
		name, err2 := lowerNfc(s[i+1:])
		if err1 != nil || err2 != nil {
			return "", &UnknownEntityError{Type: TypePackage, Value: v, Why: "empty namespace or name"}
		}
		return "pkg:generic/" + ns + "/" + name, nil
	}
	return "", &UnknownEntityError{Type: TypePackage, Value: v, Why: "not a PURL"}
}

// lowerNfc returns the lower-cased NFC form. It satisfies the (string, error)
// shape of the Canonicalize arms so a value that normalizes to empty is
// rejected rather than silently producing the empty canonical form.
func lowerNfc(s string) (string, error) {
	out := strings.ToLower(norm.NFC.String(strings.TrimSpace(s)))
	if out == "" {
		return "", errors.New("empty after normalization")
	}
	return out, nil
}

func lowerHex(s string) (string, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if !isHex(s) {
		return "", &UnknownEntityError{Type: TypeHash, Value: s, Why: "non-hex digest"}
	}
	return s, nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

// contentID derives a stable ID from raw bytes, used for file and image
// entities whose identity is the SHA-256 of the content itself.
func contentID(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
