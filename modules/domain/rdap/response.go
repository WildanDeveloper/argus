package rdap

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// response covers the shared shape of a domain, IP, and ASN RDAP object. The three
// object classes differ in which fields are populated, so one struct with optional
// parts is simpler than three parsers that share most of their logic.
type response struct {
	ObjectClassName string   `json:"objectClassName"`
	Handle          string   `json:"handle"`
	LDHName         string   `json:"ldhName"`
	UnicodeName     string   `json:"unicodeName"`
	Status          []string `json:"status"`

	// Domain-specific.
	Nameservers []struct {
		ObjectClassName string `json:"objectClassName"`
		LDHName         string `json:"ldhName"`
		UnicodeName     string `json:"unicodeName"`
	} `json:"nameservers"`
	SecureDNS struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`

	// Network-specific.
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	ParentHandle string `json:"parentHandle"`

	// Autnum-specific.
	AutnumID    int64 `json:"autnumId"`
	StartAutnum int64 `json:"startAutnum"`
	EndAutnum   int64 `json:"endAutnum"`

	Entities []entity    `json:"entities"`
	Events   []event     `json:"events"`
	Redacted []redaction `json:"redacted"`
	Remarks  []remark    `json:"remarks"`
}

type entity struct {
	ObjectClassName string   `json:"objectClassName"`
	Handle          string   `json:"handle"`
	Roles           []string `json:"roles"`
	VCardArray      any      `json:"vcardArray"`
	Entities        []entity `json:"entities"`
	Events          []event  `json:"events"`
}

type event struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type redaction struct {
	Name struct {
		Type string `json:"type"`
	} `json:"name"`
	PrePath  string `json:"prePath"`
	PostPath string `json:"postPath"`
	PathLang string `json:"pathLang"`
	Method   string `json:"method"`
	Reason   struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	} `json:"reason"`
	Replacement string `json:"replacementPath"`
}

type remark struct {
	Title       string   `json:"title"`
	Type        string   `json:"type"`
	Description []string `json:"description"`
}

// parseResponse decodes an RDAP object.
func parseResponse(raw []byte) (*response, error) {
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("rdap: parse response: %w", err)
	}
	if r.ObjectClassName == "" && r.Handle == "" && r.LDHName == "" && r.AutnumID == 0 {
		return nil, fmt.Errorf("rdap: response carries no identifiable object")
	}
	return &r, nil
}

// date parses an RDAP timestamp. RDAP requires RFC 3339, but registries are known
// to emit slightly malformed values, so a permissive fallback keeps a real registry
// answer from being discarded as a parse error.
func date(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// eventDate returns a named event's date.
func (r *response) eventDate(action string) (time.Time, bool) {
	for _, e := range r.Events {
		if strings.EqualFold(e.EventAction, action) {
			return date(e.EventDate)
		}
	}
	return time.Time{}, false
}

// registrarEntity returns the top-level entity holding the registrar role.
func (r *response) registrarEntity() *entity {
	for i := range r.Entities {
		for _, role := range r.Entities[i].Roles {
			if strings.EqualFold(role, "registrar") {
				return &r.Entities[i]
			}
		}
	}
	return nil
}

// abuseContact finds the abuse contact, which may hang off the registrar or off a
// separate entity with the abuse role.
func (r *response) abuseContact() *vCard {
	// An explicitly registered abuse role wins over anything inferred from the
	// registrar's own card, because it is the address the registry intends for
	// abuse reports.
	for i := range r.Entities {
		for _, role := range r.Entities[i].Roles {
			if strings.EqualFold(role, "abuse") {
				if c := parseVCardArray(r.Entities[i].VCardArray); len(c.emails()) > 0 {
					return c
				}
			}
		}
	}
	if reg := r.registrarEntity(); reg != nil {
		// Nested entities, as used by some registries.
		for i := range reg.Entities {
			for _, role := range reg.Entities[i].Roles {
				if strings.EqualFold(role, "abuse") {
					if c := parseVCardArray(reg.Entities[i].VCardArray); len(c.emails()) > 0 {
						return c
					}
				}
			}
		}
		if c := parseVCardArray(reg.VCardArray); len(c.emails()) > 0 {
			return c
		}
	}
	return nil
}

// registrarName returns the registrar's published name.
func (r *response) registrarName() string {
	if reg := r.registrarEntity(); reg != nil {
		if n := parseVCardArray(reg.VCardArray).name(); n != "" {
			return n
		}
		if reg.Handle != "" {
			return reg.Handle
		}
	}
	return ""
}

// nameservers returns the normalized nameserver names, sorted and deduplicated.
func (r *response) nameservers() []string {
	seen := map[string]bool{}
	var out []string
	for _, ns := range r.Nameservers {
		name := strings.ToLower(strings.TrimSuffix(ns.LDHName, "."))
		if name == "" {
			name = strings.ToLower(strings.TrimSuffix(ns.UnicodeName, "."))
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// redactedFields returns the property names the registry withheld.
//
// This is reported rather than treated as an absent value. A registrar that
// redacts the registrant is stating that the data exists and is withheld under a
// privacy regime; recording that as "no registrant" would misrepresent the
// registry, and guessing at the value would fabricate personal data.
func (r *response) redactedFields() []string {
	seen := map[string]bool{}
	var out []string
	for _, red := range r.Redacted {
		t := strings.TrimSpace(red.Name.Type)
		if t == "" {
			continue
		}
		key := strings.ToLower(t)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// redactionMethods returns the distinct withholding methods, which distinguish a
// legal privacy removal from an operational redaction.
func (r *response) redactionMethods() []string {
	seen := map[string]bool{}
	var out []string
	for _, red := range r.Redacted {
		m := strings.ToLower(strings.TrimSpace(red.Method))
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// remarkText joins the free-text remarks, which is where a registry explains a
// status such as clientHold.
func (r *response) remarkText() string {
	var parts []string
	for _, rem := range r.Remarks {
		title := strings.TrimSpace(rem.Title)
		for _, d := range rem.Description {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if title != "" {
				parts = append(parts, title+": "+d)
			} else {
				parts = append(parts, d)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// statusList returns the normalized EPP status codes.
func (r *response) statusList() []string {
	out := make([]string, 0, len(r.Status))
	for _, s := range r.Status {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// isRegistered reports whether the object exists but a status suggests the
// registration is being held or is in a transitional phase. It does not mean the
// domain is unregistered.
func (r *response) isHeld() (bool, string) {
	for _, s := range r.statusList() {
		switch strings.ToLower(s) {
		case "clienthold", "serverhold", "pendingdelete", "redemptionperiod",
			"pendingrestore", "addperiod", "autorenewperiod", "renewperiod",
			"transferperiod", "inactive":
			return true, s
		}
	}
	return false, ""
}
