package ipgeo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// adapter is one geolocation provider.
//
// Each is independent so a single one being unavailable or wrong does not take the
// module with it, and so each can be tested against a shape captured from the real
// service rather than from documentation.
type adapter interface {
	// name identifies the provider in the record.
	name() string
	// host is the only host this adapter may contact.
	host() string
	// buildURL returns the request URL.
	buildURL(addr string) string
	// parse converts the response into a normalized observation.
	parse(raw []byte) (*observation, error)
}

// fetchOne retrieves and parses one provider's answer.
func fetchOne(ctx context.Context, a adapter, m *Module, e sdk.Emitter, addr string) (*observation, error) {
	url := a.buildURL(addr)
	raw, err := m.get(ctx, e, url, a.name())
	if err != nil {
		return nil, err
	}
	o, err := a.parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.name(), err)
	}
	o.provider = a.name()
	return o, nil
}

func defaultAdapters() []adapter {
	// Only HTTPS providers are used. ip-api.com would be a natural fourth source,
	// but its unauthenticated tier is cleartext only, and an on-path attacker able
	// to rewrite a geolocation answer would place an operator in a city they are not.
	return []adapter{ipwhoIs{}, ipinfo{}, freeipapi{}}
}

// --- ipwho.is ---

type ipwhoIs struct{ base string }

func (ipwhoIs) name() string { return "ipwho.is" }
func (ipwhoIs) host() string { return "ipwho.is" }

func (a ipwhoIs) buildURL(addr string) string {
	base := a.base
	if base == "" {
		base = "https://ipwho.is"
	}
	return base + "/" + escapeQuery(addr)
}

func (ipwhoIs) parse(raw []byte) (*observation, error) {
	var r struct {
		Success     *bool    `json:"success"`
		Message     string   `json:"message"`
		Country     string   `json:"country"`
		CountryCode string   `json:"country_code"`
		Region      string   `json:"region"`
		City        string   `json:"city"`
		Latitude    *float64 `json:"latitude"`
		Longitude   *float64 `json:"longitude"`
		Connection  struct {
			ASN json.Number `json:"asn"`
			Org string      `json:"org"`
			ISP string      `json:"isp"`
		} `json:"connection"`
	}
	if err := readJSON(raw, &r); err != nil {
		return nil, err
	}
	// The service reports its own failures in a 200 body. Treating that as data would
	// produce a provider with every field empty, which then counts as a provider that
	// answered and drags the agreement calculation down.
	if r.Success != nil && !*r.Success {
		return nil, fmt.Errorf("service reported failure: %s", r.Message)
	}
	o := &observation{
		country: strings.ToUpper(strings.TrimSpace(r.CountryCode)),
		region:  strings.TrimSpace(r.Region),
		city:    strings.TrimSpace(r.City),
		org:     strings.TrimSpace(firstNonEmpty(r.Connection.Org, r.Connection.ISP)),
		asn:     trimASNumber(r.Connection.ASN.String()),
	}
	if r.Latitude != nil && r.Longitude != nil {
		o.lat, o.lon, o.hasPoint = *r.Latitude, *r.Longitude, true
	}
	return o, nil
}

// --- ipinfo.io ---

type ipinfo struct{ base string }

func (ipinfo) name() string { return "ipinfo.io" }
func (ipinfo) host() string { return "ipinfo.io" }

func (a ipinfo) buildURL(addr string) string {
	base := a.base
	if base == "" {
		base = "https://ipinfo.io"
	}
	return base + "/" + escapeQuery(addr) + "/json"
}

func (ipinfo) parse(raw []byte) (*observation, error) {
	var r struct {
		IP      string `json:"ip"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Country string `json:"country"`
		Loc     string `json:"loc"`
		Org     string `json:"org"`
		// Anycast is only present when the account may see it. Its absence must not
		// be read as a negative, which is why the provider records whether it
		// reported the flag at all.
		Anycast *bool `json:"anycast"`
	}
	if err := readJSON(raw, &r); err != nil {
		return nil, err
	}
	if isPlaceholder(r.IP, r.Country) {
		return nil, fmt.Errorf("service returned a documentation placeholder rather than a record")
	}
	o := &observation{
		country: strings.ToUpper(strings.TrimSpace(r.Country)),
		city:    strings.TrimSpace(r.City),
		region:  strings.TrimSpace(r.Region),
		asn:     asnFromOrg(r.Org),
		org:     orgFromOrg(r.Org),
	}
	if r.Anycast != nil {
		o.anycast, o.hasAnycast = *r.Anycast, true
	}
	lat, lon, ok := parseLoc(r.Loc)
	if ok {
		o.lat, o.lon, o.hasPoint = lat, lon, true
	}
	return o, nil
}

// isPlaceholder reports whether a body is ipinfo's unauthenticated placeholder.
//
// ipinfo answers an unauthenticated request with a valid-looking document whose only
// meaningful field is a pointer to its documentation. Parsing that as a location
// would leave every field empty and, worse, count as a provider that answered, which
// would drag the agreement calculation down for no reason.
func isPlaceholder(ip, country string) bool {
	return strings.TrimSpace(ip) == "" && strings.TrimSpace(country) == ""
}

// parseLoc reads ipinfo's "lat,lon" string.
func parseLoc(s string) (float64, float64, bool) {
	lat, lon, ok := splitLoc(s)
	return lat, lon, ok
}

// --- freeipapi.com ---

type freeipapi struct{ base string }

func (freeipapi) name() string { return "freeipapi.com" }
func (freeipapi) host() string { return "free.freeipapi.com" }

func (a freeipapi) buildURL(addr string) string {
	base := a.base
	if base == "" {
		// The api.freeipapi.com host redirects here. Asking for the canonical endpoint
		// directly rather than relying on the redirect matters because the redirect
		// target is a different host, and this module is only permitted to reach the
		// hosts its manifest declares.
		base = "https://free.freeipapi.com/api/v1/json"
	}
	return base + "/" + escapeQuery(addr)
}

func (freeipapi) parse(raw []byte) (*observation, error) {
	var r struct {
		IPAddress       string   `json:"ipAddress"`
		CountryCode     string   `json:"countryCode"`
		RegionName      string   `json:"regionName"`
		CityName        string   `json:"cityName"`
		Latitude        *float64 `json:"latitude"`
		Longitude       *float64 `json:"longitude"`
		ASN             string   `json:"asn"`
		ASNOrganization string   `json:"asnOrganization"`
		IsProxy         *bool    `json:"isProxy"`
	}
	if err := readJSON(raw, &r); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.IPAddress) == "" {
		return nil, fmt.Errorf("response carries no address")
	}
	o := &observation{
		country: strings.ToUpper(strings.TrimSpace(r.CountryCode)),
		region:  strings.TrimSpace(r.RegionName),
		city:    strings.TrimSpace(r.CityName),
		org:     strings.TrimSpace(r.ASNOrganization),
		asn:     trimASNumber(r.ASN),
	}
	if r.Latitude != nil && r.Longitude != nil {
		o.lat, o.lon, o.hasPoint = *r.Latitude, *r.Longitude, true
	}
	// A proxy flag is not an anycast flag. Recording it as one would suppress a
	// legitimate city for every address behind a proxy, which is most of the
	// internet. It is not carried on the observation at all for now rather than
	// being mapped onto the wrong concept.
	return o, nil
}

// --- shared parsing helpers ---

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// trimASNumber normalizes the several shapes an ASN arrives in: "15169", "AS15169",
// "AS15169 GOOGLE, US".
func trimASNumber(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, " ,"); i > 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(strings.ToUpper(s), "AS")
	// Keep only digits.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	if len(out) == 0 || len(out) > 10 {
		return ""
	}
	return string(out)
}

// asnFromOrg pulls the number out of ipinfo's "AS15169 Google LLC" org string.
func asnFromOrg(org string) string { return trimASNumber(org) }

// orgFromOrg pulls the name out of ipinfo's "AS15169 Google LLC" org string.
func orgFromOrg(org string) string {
	org = strings.TrimSpace(org)
	if i := strings.Index(org, " "); i > 0 && strings.HasPrefix(strings.ToUpper(org), "AS") {
		return strings.TrimSpace(org[i+1:])
	}
	return org
}

// splitLoc reads a "lat,lon" pair.
func splitLoc(s string) (float64, float64, bool) {
	parts := strings.Split(strings.TrimSpace(s), ",")
	if len(parts) != 2 {
		return 0, 0, false
	}
	lat, err1 := parseFloat(parts[0])
	lon, err2 := parseFloat(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return 0, 0, false
	}
	return lat, lon, true
}

func parseFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	neg := false
	if s[0] == '-' {
		neg, s = true, s[1:]
	} else if s[0] == '+' {
		s = s[1:]
	}
	if s == "" {
		return 0, fmt.Errorf("no digits")
	}
	var whole, frac float64
	var scale float64 = 1
	i := 0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		whole = whole*10 + float64(s[i]-'0')
	}
	if i < len(s) && s[i] == '.' {
		i++
		for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
			scale /= 10
			frac += float64(s[i]-'0') * scale
		}
	}
	if i != len(s) {
		return 0, fmt.Errorf("trailing %q", s[i:])
	}
	v := whole + frac
	if neg {
		v = -v
	}
	return v, nil
}
