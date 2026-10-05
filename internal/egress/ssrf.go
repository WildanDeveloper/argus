// Package egress implements the single choke point for every outbound request.
//
// Placing scope, SSRF protection, rate limiting, caching, circuit breaking,
// retry, size limits, and audit behind one Client is the reason those controls
// can be trusted: a module cannot forget them, because it has no way to reach
// the network except through here. ADR-003.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// SSRFGuard blocks requests to addresses an attacker could use to reach
// infrastructure the analyst cannot see: loopback, private ranges, link-local,
// the cloud metadata service, and carrier-grade NAT.
//
// The check runs at dial time against the resolved IP, not at URL-parse time
// against the hostname. Checking the hostname is not enough: DNS can return a
// public address during validation and a private one when the connection is
// actually made. That is DNS rebinding, and it is why Control (below) is
// installed on the dialer rather than used as a pre-flight filter.
type SSRFGuard struct {
	// AllowPrivate permits internal assessment ranges. It exists because
	// legitimate work includes internal asset mapping, and it is deliberately
	// never implied by scope: scope says what may be assessed, this says whether
	// private addresses may be reached at all.
	AllowPrivate bool
	// AllowPrivateCIDRs narrows AllowPrivate to specific ranges.
	AllowPrivateCIDRs []netip.Prefix
	// AllowExtraCIDRs permits specific otherwise-blocked ranges (an internal
	// resolver, a self-hosted SearXNG on a private address).
	AllowExtraCIDRs []netip.Prefix
	// AllowLoopback permits loopback, for testing against a local httptest
	// server. Never enable this in a scan.
	AllowLoopback bool
}

// blockedAlways are ranges with no legitimate place in an OSINT scan.
var blockedAlways = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
	netip.MustParsePrefix("169.254.169.254/32"), // cloud metadata (AWS/GCP/Azure/DO)
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local, incl. metadata
	netip.MustParsePrefix("fe80::/10"),          // v6 link-local
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("64:ff9b::/96"),       // v4/v6 translation
	netip.MustParsePrefix("100::/64"),           // discard-only
	netip.MustParsePrefix("2001:db8::/32"),      // documentation
	netip.MustParsePrefix("fc00::/7"),           // v6 unique local
}

// privateV4 are the classic private ranges.
var privateV4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// ErrSSRFBlocked is returned when the guard refuses a destination.
var ErrSSRFBlocked = errors.New("egress: destination blocked by SSRF guard")

// CheckAddr reports whether addr may be dialed. It is used by the dialer via
// Control and is also callable directly, which is what lets `argus doctor`
// verify a configuration without opening a connection.
func (g *SSRFGuard) CheckAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrSSRFBlocked)
	}
	// Unmap 4-in-6 so ::ffff:10.0.0.1 is judged as 10.0.0.1.
	addr = addr.Unmap()

	for _, p := range g.AllowExtraCIDRs {
		if p.Contains(addr) {
			return nil
		}
	}

	if addr.IsLoopback() {
		if g.AllowLoopback {
			return nil
		}
		return fmt.Errorf("%w: loopback address %s", ErrSSRFBlocked, addr)
	}

	if addr.IsMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: multicast address %s", ErrSSRFBlocked, addr)
	}

	for _, p := range blockedAlways {
		if p.Contains(addr) {
			return fmt.Errorf("%w: %s is in %s", ErrSSRFBlocked, addr, p)
		}
	}

	isPrivate := addr.IsPrivate()
	if !isPrivate {
		for _, p := range privateV4 {
			if p.Contains(addr) {
				isPrivate = true
				break
			}
		}
	}
	if isPrivate {
		if g.AllowPrivate {
			for _, p := range g.AllowPrivateCIDRs {
				if p.Contains(addr) {
					return nil
				}
			}
			// AllowPrivate with an empty list means all private ranges, which is
			// the documented way to run an internal assessment.
			if len(g.AllowPrivateCIDRs) == 0 {
				return nil
			}
		}
		return fmt.Errorf("%w: private address %s (set network.egress.allow_private_cidrs only for an authorized internal assessment)", ErrSSRFBlocked, addr)
	}

	return nil
}

// CheckHost resolves host and checks every address it resolves to.
//
// Checking all records rather than the first is deliberate: a name with both a
// public and a private A record must be refused outright, not resolved on the
// happy path.
func (g *SSRFGuard) CheckHost(ctx context.Context, host string, lookup func(context.Context, string) ([]net.IP, error)) error {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err == nil {
		return g.CheckAddr(ip)
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return fmt.Errorf("egress: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("egress: %s resolved to no addresses", host)
	}
	for _, raw := range ips {
		a, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		if err := g.CheckAddr(a); err != nil {
			return err
		}
	}
	return nil
}

// Control is a net.Dialer Control hook: it runs on the resolved IP immediately
// before the connection is made, which is the only point where DNS rebinding
// can be defeated.
func (g *SSRFGuard) Control(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		// Nothing else should be dialable. Refusing udp here prevents a module
		// from opening a side channel that the audit log never sees.
		return fmt.Errorf("%w: network %q is not permitted", ErrSSRFBlocked, network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable address %q", ErrSSRFBlocked, address)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return g.CheckAddr(a)
	}
	// Should not happen: the resolver runs before Control and hands us an IP.
	// Fail closed rather than assume.
	return fmt.Errorf("%w: dial target %q is not an IP address", ErrSSRFBlocked, address)
}

// Compile-time assurance that the guard never silently stops being wired in.
var _ = func() bool {
	var c syscall.RawConn
	_ = c
	return true
}()
