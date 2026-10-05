// Package reverse performs reverse DNS on an address and checks the result with a
// forward-confirmed reverse DNS lookup.
//
// The PTR record is a statement of intent by whoever controls the address, not an
// observation of the host. It can be set to anything, it is routinely set to a cloud
// provider's generic service name, and it survives long after the service it once
// described has moved. So the pointer is reported as a claim, and a forward lookup is
// performed to see whether the name actually resolves back, which is what separates a
// maintained PTR from a stale or spoofed one.
package reverse

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// Grading. A PTR record is published by the address holder but says nothing on its
// own about the machine behind it, and a forward-confirmed answer is corroborated by
// the forward zone. B/2 reflects a pointer that has been checked once.
const (
	gradeReliability = 'B'
	gradeCredibility = '2'
)

// Module is the reverse-dns collector.
type Module struct {
	dns sdk.DNSResolver
	now func() time.Time
}

// Option configures the module.
type Option func(*Module)

// WithDNS injects the brokered resolver.
func WithDNS(d sdk.DNSResolver) Option { return func(m *Module) { m.dns = d } }

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{now: time.Now}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "reverse-dns",
		Version:     Version,
		Category:    "domain",
		Description: "PTR records with a forward-confirmed reverse DNS check",
		Consumes:    []sdk.EntityType{sdk.TypeIP},
		Produces:    []sdk.EntityType{sdk.TypeDomain, sdk.TypeSubdomain, sdk.TypeIP, sdk.TypeFinding},
		// DNS lookups reach the target's own resolvers, so this touches
		// infrastructure the subject operates. Semi-active is the honest grade.
		Mode:        sdk.ModeSemiActive,
		Sensitivity: sdk.SensLow,
		// The brokered resolver reaches one of these over DoH. A module that resolves
		// DNS without naming the resolvers it will contact reaches hosts it has not
		// declared, which is the same omission asn-lookup and dns-records were fixed
		// for.
		EgressHosts: []string{
			"cloudflare-dns.com",
			"dns.google",
			"dns.adguard-dns.com",
		},
		RateHints: map[string]sdk.Rate{
			"dns": {Requests: 20, Per: time.Second, Burst: 40},
		},
		Tags: []string{"dns", "pivot", "infrastructure"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	if d.DNS == nil {
		return fmt.Errorf("reverse-dns: no DNS resolver injected")
	}
	m.dns = d.DNS
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// Run looks up the pointer and checks it forwards.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("reverse-dns: task has no target")
	}
	if t.Target.Type != sdk.TypeIP {
		return nil
	}

	name, err := ptrName(t.Target.Value)
	if err != nil {
		// An address that cannot be put into the reverse tree has no PTR to look up.
		// That is a property of the value, not a failure worth reporting.
		return nil
	}

	records, lookupErr := m.dns.Lookup(ctx, name, "PTR")
	if lookupErr != nil {
		return fmt.Errorf("reverse-dns: query %s: %w", name, lookupErr)
	}
	target := strings.TrimSuffix(strings.TrimSpace(ptrValue(records)), ".")
	if target == "" {
		return m.emitNoPTR(t, e, name)
	}

	dom, err := sdk.NewEntityOrErr(domainType(target), target)
	if err != nil {
		// A PTR value that is not a usable name, such as a malformed label, is
		// skipped rather than forced into the graph.
		return m.emitNoPTR(t, e, name)
	}

	// Forward confirmation. The PTR name is resolved back to addresses; the claim is
	// confirmed only if the original address is among them.
	forward, fwdErr := m.forwardAddresses(ctx, target)
	var confirmed bool
	backTo := []string{}
	for _, a := range forward {
		backTo = append(backTo, a)
		if a == t.Target.Value {
			confirmed = true
		}
	}

	source := sdk.Source{Module: "reverse-dns", Provider: "dns", Method: "ptr"}
	obs := sdk.Observation{
		Predicate:   "reverse_of",
		Object:      target,
		Source:      source,
		Reliability: gradeReliability,
		Credibility: gradeCredibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("ptr_query", name)
	obs.AddAttr("forward_confirmed", confirmed)
	if len(forward) > 0 {
		obs.AddAttr("resolves_to", forward)
	}
	if fwdErr != nil {
		obs.AddAttr("forward_error", fwdErr.Error())
	}
	// A pointer into a shared-provider namespace describes the hosting platform, not
	// whoever asked for the address. Without this note a reader would conclude that
	// the target owns the machine.
	if shared, provider := sharedInfrastructure(target); shared {
		obs.AddAttr("shared_infrastructure", true)
		obs.AddAttr("shared_provider", provider)
		obs.AddAttr("shared_note",
			"this pointer names a hosting platform's service namespace, so it identifies where the address is served, not who operates it")
	}

	sev := sdk.SevInfo
	kind := "reverse-dns-ptr"
	if !confirmed && fwdErr == nil {
		// A pointer that does not resolve back is either a misconfiguration or a
		// deliberate misdirection. Either way it is worth more than a routine record.
		kind = "reverse-dns-fcrdns-mismatch"
		sev = sdk.SevLow
		obs.AddAttr("fcrdns_note",
			"the pointer name does not resolve back to this address, so it describes no host Argus can confirm here")
	}

	if err := e.Emit(sdk.Finding{
		Entity:      dom,
		Relations:   []sdk.Relation{sdk.Rel(t.Target.ID, dom.ID, sdk.RelReverseOf)},
		Observation: obs,
		Kind:        kind,
		Severity:    sev,
	}); err != nil {
		return err
	}

	// Addresses the pointer resolves to are real entities even when the pointer does
	// not point back here, because that is where the name actually leads.
	for _, a := range forward {
		if a == t.Target.Value {
			continue
		}
		ipEnt, err := sdk.NewEntityOrErr(sdk.TypeIP, a)
		if err != nil {
			continue
		}
		fobs := sdk.Observation{
			Predicate:   "resolves_to",
			Object:      a,
			Source:      sdk.Source{Module: "reverse-dns", Provider: "dns", Method: "ptr.forward"},
			Reliability: gradeReliability,
			Credibility: gradeCredibility,
			ObservedAt:  m.now(),
		}
		fobs.AddAttr("via_ptr", target)
		// The forward answers do not come back to the address that asked, so this
		// edge is where the mismatch shows rather than a claim about the target.
		fobs.AddAttr("reverse_confirmed", false)
		if err := e.Emit(sdk.Finding{
			Entity:      ipEnt,
			Relations:   []sdk.Relation{sdk.HeuristicRel(dom.ID, ipEnt.ID, sdk.RelResolvesTo)},
			Observation: fobs,
			Kind:        "reverse-dns-forward",
			Severity:    sdk.SevInfo,
		}); err != nil {
			return err
		}
	}
	return nil
}

// forwardAddresses resolves a pointer name forward.
func (m *Module) forwardAddresses(ctx context.Context, name string) ([]string, error) {
	records, err := m.dns.Lookup(ctx, name, "A")
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range records {
		if r.Type != "" && !strings.EqualFold(r.Type, "A") {
			continue
		}
		v := strings.TrimSpace(r.Data)
		a, err := netip.ParseAddr(v)
		if err != nil {
			continue
		}
		s := a.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	records6, err := m.dns.Lookup(ctx, name, "AAAA")
	if err == nil {
		for _, r := range records6 {
			if r.Type != "" && !strings.EqualFold(r.Type, "AAAA") {
				continue
			}
			a, err := netip.ParseAddr(strings.TrimSpace(r.Data))
			if err != nil {
				continue
			}
			s := a.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// emitNoPTR records an address with no pointer.
func (m *Module) emitNoPTR(t sdk.Task, e sdk.Emitter, query string) error {
	obs := sdk.Observation{
		Predicate:   "no_ptr_record",
		Object:      t.Target.Value,
		Source:      sdk.Source{Module: "reverse-dns", Provider: "dns", Method: "ptr"},
		Reliability: gradeReliability,
		Credibility: gradeCredibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("ptr_query", query)
	// "No answer" covers both an absent record and a name server with no opinion, and
	// the resolver reports neither as a failure. Saying so avoids reading an empty
	// answer as a statement about the host.
	obs.AddAttr("note", "no PTR record was returned; this does not indicate whether the host exists or is reachable")
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "reverse-dns-no-ptr",
		Severity:    sdk.SevInfo,
	})
}

// ptrName builds the reverse-tree name for an address.
func ptrName(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(value), "[]"))
	if err != nil {
		return "", err
	}
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), nil
	}
	// IPv6 reverse names are 32 nibbles in reverse order. netip does not build them,
	// and building them by hand from the bytes is exact, so it is done here rather
	// than approximated.
	bytes := addr.As16()
	var sb strings.Builder
	for i := len(bytes) - 1; i >= 0; i-- {
		sb.WriteByte(hexDigit(bytes[i] & 0x0f))
		sb.WriteByte('.')
		sb.WriteByte(hexDigit(bytes[i] >> 4))
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

func hexDigit(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + (b - 10)
}

// ptrValue returns the first pointer target.
func ptrValue(records []sdk.DNSRecord) string {
	for _, r := range records {
		if r.Type != "" && !strings.EqualFold(r.Type, "PTR") {
			continue
		}
		if v := strings.TrimSpace(r.Data); v != "" {
			return v
		}
	}
	return ""
}

// domainType classifies a name as a registrable domain or a subdomain.
func domainType(name string) sdk.EntityType {
	if strings.Contains(strings.TrimSuffix(name, "."), ".") {
		// The distinction between apex and subdomain needs the Public Suffix List,
		// which the SDK deliberately does not carry. A subdomain is the safe default
		// here because a host name recovered from a PTR is rarely the registrable
		// apex, and a wrongly-typed subdomain is corrected by canon on the next hop.
		return sdk.TypeSubdomain
	}
	return sdk.TypeDomain
}

// sharedNamespace lists the suffixes of hosting platforms whose names identify the
// platform rather than the tenant.
//
// This list is necessarily incomplete and it is a heuristic, so a miss is a missing
// note rather than a wrong conclusion. It is only ever used to add a caveat.
var sharedNamespace = []struct {
	suffix   string
	provider string
}{
	{".amazonaws.com", "Amazon Web Services"},
	{".awsglobalaccelerator.com", "Amazon Web Services"},
	{".cloudfront.net", "Amazon CloudFront"},
	{".elb.amazonaws.com", "Amazon Elastic Load Balancing"},
	{".googleusercontent.com", "Google Cloud"},
	{".gcp", "Google Cloud"},
	{".googleapis.com", "Google Cloud"},
	{".appspot.com", "Google App Engine"},
	{".cloudapp.azure.com", "Microsoft Azure"},
	{".azurewebsites.net", "Microsoft Azure"},
	{".app-service.windows.net", "Microsoft Azure"},
	{".cloudapp.net", "Microsoft Azure"},
	{".digitaloceanspaces.com", "DigitalOcean"},
	{".linode.com", "Linode"},
	{".compute.amazonaws.com", "Amazon Web Services"},
	{".oraclecloud.com", "Oracle Cloud"},
	{".scaleway.com", "Scaleway"},
	{".hetzner.de", "Hetzner"},
	{".hetzner.com", "Hetzner"},
	{".ovh.net", "OVHcloud"},
	{".fastly.net", "Fastly"},
	{".akamaiedge.net", "Akamai"},
	{".akadns.net", "Akamai"},
	{".edgekey.net", "Akamai"},
	{".vercel.app", "Vercel"},
	{".netlify.app", "Netlify"},
	{".fly.dev", "Fly.io"},
}

// sharedInfrastructure reports whether a pointer names a hosting platform.
func sharedInfrastructure(name string) (bool, string) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, ns := range sharedNamespace {
		if strings.HasSuffix(n, ns.suffix) {
			return true, ns.provider
		}
	}
	return false, ""
}

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}
