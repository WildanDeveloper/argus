package rdap

import (
	"math"
	"strconv"
	"strings"
)

// vCard is the parsed form of the vcardArray field in an RDAP entity.
//
// RFC 9083 requires registrars to publish contact details as jCard, which is JSON
// encoding of vCard 4.0. Each property is a four-element array:
//
//	["fn", {}, "text", "Example Registrar Inc."]
//	 ["tel", {"type":["voice"]}, "uri", "tel:+1.5555555555"]
//
// so the name, a parameter object, a value type, and the value itself.
type vCard struct {
	version string
	// fields keeps the first value seen for each property, lower-cased by name.
	fields map[string]string
	// all keeps every value, because multi-valued properties such as multiple
	// email addresses are common and the first one is not necessarily the
	// operational one.
	all map[string][]string
	// types keeps the declared value type per property.
	types map[string]string
}

func newVCard() *vCard {
	return &vCard{
		fields: map[string]string{},
		all:    map[string][]string{},
		types:  map[string]string{},
	}
}

// parseVCardArray parses a jCard as it appears in an RDAP response.
func parseVCardArray(raw any) *vCard {
	c := newVCard()

	arr, ok := raw.([]any)
	if !ok || len(arr) < 2 {
		return c
	}
	// The first element is the literal "vcard"; only the second carries properties.
	if s, ok := arr[0].(string); !ok || s != "vcard" {
		return c
	}
	props, ok := arr[1].([]any)
	if !ok {
		return c
	}

	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, ok := prop[0].(string)
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		valueType, _ := prop[2].(string)
		value := flattenValue(prop[3])

		if key == "version" {
			c.version = value
			continue
		}
		if _, seen := c.fields[key]; !seen {
			c.fields[key] = value
			c.types[key] = strings.ToLower(valueType)
		}
		c.all[key] = append(c.all[key], value)
	}
	return c
}

// flattenValue renders a jCard value as a string.
//
// vCard values are typed: an address is an array of components, and a label is an
// array with a language. Both are flattened to something a human can read, because
// the alternative is silently losing the field.
func flattenValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s := flattenValue(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers arrive as float64; an integer must not render as "1e+06".
		return formatNumber(t)
	}
	return ""
}

// formatNumber renders a JSON number without an exponent or trailing zeros, which
// strconv's default formatting would introduce for larger integers.
func formatNumber(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// get returns the first value of a property.
func (c *vCard) get(name string) string {
	return c.fields[strings.ToLower(name)]
}

// getAll returns every value of a property.
func (c *vCard) getAll(name string) []string {
	return c.all[strings.ToLower(name)]
}

// emails returns every address, preferring the explicitly labelled abuse contact
// and skipping the placeholder a registrar publishes when redaction applies.
func (c *vCard) emails() []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range c.getAll("email") {
		e = strings.TrimSpace(e)
		if e == "" || seen[strings.ToLower(e)] {
			continue
		}
		// Redaction placeholders are not addresses.
		if strings.EqualFold(e, "REDACTED FOR PRIVACY") ||
			strings.EqualFold(e, "DATA REDACTED") ||
			strings.EqualFold(e, "NOT DISCLOSED") {
			continue
		}
		seen[strings.ToLower(e)] = true
		out = append(out, e)
	}
	return out
}

// name returns the best available human or organization name.
func (c *vCard) name() string {
	for _, f := range []string{"fn", "org", "n"} {
		if v := strings.TrimSpace(c.get(f)); v != "" {
			return v
		}
	}
	return ""
}

// phones returns declared telephone numbers with their URI scheme removed.
func (c *vCard) phones() []string {
	var out []string
	for _, p := range c.getAll("tel") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.TrimPrefix(p, "tel:")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isRedacted reports whether a property was withheld.
func (c *vCard) isRedacted(name string) bool {
	v := c.get(name)
	switch {
	case v == "":
		return false
	case strings.EqualFold(v, "REDACTED FOR PRIVACY"):
		return true
	case strings.EqualFold(v, "DATA REDACTED"):
		return true
	case strings.EqualFold(v, "NOT DISCLOSED"):
		return true
	}
	return false
}
