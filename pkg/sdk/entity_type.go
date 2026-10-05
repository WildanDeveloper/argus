package sdk

import "errors"

// EntityType enumerates the things Argus can reason about. The string values
// are the on-disk and wire representation; they are part of the public data
// model (Appendix A) and must stay stable.
type EntityType string

const (
	TypeDomain    EntityType = "domain"
	TypeSubdomain EntityType = "subdomain"
	TypeIP        EntityType = "ip"
	TypeCIDR      EntityType = "cidr"
	TypeASN       EntityType = "asn"
	TypeURL       EntityType = "url"
	TypeEmail     EntityType = "email"
	TypeUsername  EntityType = "username"
	TypeAccount   EntityType = "account"
	TypePhone     EntityType = "phone"
	TypePerson    EntityType = "person"
	TypeOrg       EntityType = "organization"
	TypeLocation  EntityType = "location"
	TypeGeo       EntityType = "geo"
	TypeFile      EntityType = "file"
	TypeImage     EntityType = "image"
	TypeHash      EntityType = "hash"
	TypeCert      EntityType = "certificate"
	TypeCVE       EntityType = "cve"
	TypeWallet    EntityType = "wallet"
	TypeTx        EntityType = "transaction"
	TypeApp       EntityType = "app"
	TypeRepo      EntityType = "repository"
	TypePackage   EntityType = "package"
	TypeIOC       EntityType = "ioc"
	TypeText      EntityType = "text"
	TypeFinding   EntityType = "finding"
)

// EntityCategories maps an entity type to the module category that naturally
// consumes it. Used by `argus scan` to pick modules when the user does not
// name any explicitly, and by the CLI help output.
var EntityCategories = map[EntityType][]string{
	TypeDomain:    {"domain"},
	TypeSubdomain: {"domain", "web"},
	TypeIP:        {"network"},
	TypeCIDR:      {"network"},
	TypeASN:       {"network"},
	TypeURL:       {"web"},
	TypeEmail:     {"identity"},
	TypeUsername:  {"identity"},
	TypeAccount:   {"social"},
	TypePhone:     {"identity"},
	TypePerson:    {"corporate", "identity"},
	TypeOrg:       {"corporate"},
	TypeLocation:  {"geo"},
	TypeGeo:       {"geo"},
	TypeFile:      {"media"},
	TypeImage:     {"media"},
	TypeHash:      {"media", "threat"},
	TypeCert:      {"domain", "network"},
	TypeCVE:       {"threat"},
	TypeWallet:    {"crypto"},
	TypeTx:        {"crypto"},
	TypeApp:       {"cloud"},
	TypeRepo:      {"code"},
	TypePackage:   {"code"},
	TypeIOC:       {"threat"},
	TypeText:      {"media"},
	TypeFinding:   {"threat"},
}

// allTypes is the authoritative ordering used by `argus entities --type` help
// and by schema generation. Keep it alphabetical within families.
var allTypes = []EntityType{
	TypeDomain, TypeSubdomain, TypeIP, TypeCIDR, TypeASN, TypeURL,
	TypeEmail, TypeUsername, TypeAccount, TypePhone, TypePerson, TypeOrg,
	TypeLocation, TypeGeo, TypeFile, TypeImage, TypeHash, TypeCert,
	TypeCVE, TypeWallet, TypeTx, TypeApp, TypeRepo, TypePackage,
	TypeIOC, TypeText, TypeFinding,
}

// AllEntityTypes returns every known entity type in stable order.
func AllEntityTypes() []EntityType {
	out := make([]EntityType, len(allTypes))
	copy(out, allTypes)
	return out
}

// ValidEntityType reports whether s names a known entity type.
func ValidEntityType(s string) bool {
	for _, t := range allTypes {
		if string(t) == s {
			return true
		}
	}
	return false
}

// Sensitivity is the honest self-declaration of how sensitive a module's inputs
// or outputs are. The policy engine reads this; modules may not understate it.
type Sensitivity uint8

const (
	SensLow Sensitivity = iota
	SensMedium
	SensHigh // personal data: purpose + case (+ approval) required
)

func (s Sensitivity) String() string {
	switch s {
	case SensMedium:
		return "medium"
	case SensHigh:
		return "high"
	default:
		return "low"
	}
}

// Mode describes how a collector touches the world. Argus is passive-first.
type Mode uint8

const (
	// ModePassive queries third-party datasets or processes local files. It
	// never contacts the target's infrastructure.
	ModePassive Mode = iota
	// ModeSemiActive issues low-volume requests that resemble ordinary use of
	// public target endpoints (DNS lookups, HTTP GET, TLS handshake).
	ModeSemiActive
	// ModeActive probes or verifies against target infrastructure. Requires
	// --allow-active, an in-scope target, and an authorization block in the
	// scope file.
	ModeActive
)

func (m Mode) String() string {
	switch m {
	case ModeSemiActive:
		return "semi-active"
	case ModeActive:
		return "active"
	default:
		return "passive"
	}
}

// ParseMode maps a config or flag string to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "passive":
		return ModePassive, nil
	case "standard", "semi-active", "semi_active", "semiactive":
		return ModeSemiActive, nil
	case "active":
		return ModeActive, nil
	}
	return ModePassive, errors.New("unknown mode " + s)
}

// Satisfies reports whether the module's declared mode is permitted when the
// scan runs at the given ceiling. A passive collector may run in any mode; an
// active collector may not run in a passive scan.
func (m Mode) Satisfies(ceiling Mode) bool {
	return m <= ceiling
}
