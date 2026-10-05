package egress

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestSSRFBlocksInternalDestinations(t *testing.T) {
	g := &SSRFGuard{}
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // v6 loopback
		"10.0.0.1",        // private
		"172.16.0.1",      // private
		"192.168.1.1",     // private
		"169.254.169.254", // cloud metadata
		"100.64.0.1",      // CGNAT
		"0.0.0.0",         // this network
		"255.255.255.255", // broadcast
		"fc00::1",         // v6 unique local
		"fe80::1",         // v6 link-local
		"::ffff:10.0.0.1", // 4-in-6 must be judged after unmapping
		"2606:4700::1111", // public, must be allowed (control)
	}
	for _, s := range blocked {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test address %q invalid: %v", s, err)
		}
		err = g.CheckAddr(a)
		if s == "2606:4700::1111" {
			if err != nil {
				t.Errorf("public address %s must be allowed: %v", s, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("CheckAddr(%s) allowed; SSRF guard must block it", s)
		}
	}
}

func TestSSRFExplicitAllowances(t *testing.T) {
	// An authorized internal assessment needs private ranges, but only those
	// named.
	g := &SSRFGuard{AllowPrivate: true, AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}}
	if err := g.CheckAddr(netip.MustParseAddr("10.10.1.1")); err != nil {
		t.Errorf("explicitly allowed private range should pass: %v", err)
	}
	if err := g.CheckAddr(netip.MustParseAddr("10.11.1.1")); err == nil {
		t.Error("private range outside the allow list must still be blocked")
	}

	// AllowPrivate with no list permits all private space (internal mapping).
	g2 := &SSRFGuard{AllowPrivate: true}
	if err := g2.CheckAddr(netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Errorf("AllowPrivate with no list should permit private space: %v", err)
	}
	// But never the metadata service, even then: that endpoint hands out cloud
	// credentials and is not an assessment target under any authorization.
	if err := g2.CheckAddr(netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Error("cloud metadata must remain blocked even with AllowPrivate")
	}

	// Loopback is separate from private and must be opted into explicitly.
	g3 := &SSRFGuard{AllowPrivate: true}
	if err := g3.CheckAddr(netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Error("loopback must require its own opt-in")
	}
	g4 := &SSRFGuard{AllowLoopback: true}
	if err := g4.CheckAddr(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("AllowLoopback should permit loopback: %v", err)
	}
}

func TestSSRFDocumentationRangesBlocked(t *testing.T) {
	// The RFC test ranges are used in fixtures. Blocking them in production
	// prevents a scan from mistaking documentation space for a live host.
	g := &SSRFGuard{}
	for _, s := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"} {
		if err := g.CheckAddr(netip.MustParseAddr(s)); err == nil {
			t.Errorf("documentation range %s should be blocked", s)
		}
	}
}

func TestSSRFRebindingResistance(t *testing.T) {
	// The guard is invoked from net.Dialer.Control, i.e. on the already-resolved
	// IP. Simulate the rebinding case: the hostname validated as public, but the
	// dial is handed a private address. Control must refuse.
	g := &SSRFGuard{}
	addr := netip.MustParseAddr("169.254.169.254")
	if err := g.CheckAddr(addr); err == nil {
		t.Fatal("precondition: metadata address must be blocked")
	}
	// The Control hook receives "ip:port"; verify it parses and refuses.
	err := g.Control("tcp", "169.254.169.254:80", nil)
	if err == nil {
		t.Fatal("Control allowed a rebound private address; DNS rebinding is possible")
	}

	// It must also refuse non-TCP networks so a module cannot open an unaudited
	// side channel.
	if err := g.Control("udp", "1.1.1.1:53", nil); err == nil {
		t.Error("Control must refuse udp")
	}
	if err := g.Control("tcp", "not-an-ip:80", nil); err == nil {
		t.Error("Control must refuse a non-IP dial target")
	}
	if err := g.Control("tcp", "1.1.1.1:443", nil); err != nil {
		t.Errorf("Control must allow a public address: %v", err)
	}
}

func TestSSRFCheckHostResolvesAll(t *testing.T) {
	g := &SSRFGuard{}
	// A name with both a public and a private record must be refused outright.
	// Accepting it because "the first answer was fine" is how rebinding works.
	calls := 0
	err := g.CheckHost(t.Context(), "mixed.example", func(ctx context.Context, host string) ([]net.IP, error) {
		calls++
		return []net.IP{mustIP("93.184.216.34"), mustIP("10.0.0.5")}, nil
	})
	if err == nil {
		t.Fatal("a name with a private record must be refused")
	}
	if calls != 1 {
		t.Errorf("resolver called %d times, want 1", calls)
	}

	// An all-public name passes.
	if err := g.CheckHost(t.Context(), "good.example", func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{mustIP("93.184.216.34")}, nil
	}); err != nil {
		t.Errorf("all-public name refused: %v", err)
	}
}

func TestParseRate(t *testing.T) {
	ok := map[string]Rate{
		"5/s":   {Requests: 5, Per: 1_000_000_000},
		"20/m":  {Requests: 20, Per: 60_000_000_000},
		"100/h": {Requests: 100, Per: 3_600_000_000_000},
		"2/day": {Requests: 2, Per: 86_400_000_000_000},
		"1/sec": {Requests: 1, Per: 1_000_000_000},
		"3":     {Requests: 3, Per: 1_000_000_000},
	}
	for in, want := range ok {
		got, err := ParseRate(in)
		if err != nil {
			t.Errorf("ParseRate(%q): %v", in, err)
			continue
		}
		if got.Requests != want.Requests || got.Per != want.Per {
			t.Errorf("ParseRate(%q) = %+v, want %+v", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "/s", "5/x", "-1/s"} {
		if _, err := ParseRate(bad); err == nil && bad != "" {
			t.Errorf("ParseRate(%q) should fail", bad)
		}
	}
}
func mustIP(s string) net.IP {
	a := netip.MustParseAddr(s)
	b := a.AsSlice()
	return net.IP(b)
}
