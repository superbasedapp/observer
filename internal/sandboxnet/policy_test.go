package sandboxnet

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestDestinationAllowed(t *testing.T) {
	t.Parallel()

	local := []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("fd00::10")}

	tests := []struct {
		name     string
		ip       net.IP
		wantRule string // "" = allowed
	}{
		{"nil", nil, RuleNil},
		{"short garbage", net.IP{1, 2, 3}, RuleNil},
		{"ipv4 unspecified", net.ParseIP("0.0.0.0"), RuleUnspecified},
		{"ipv6 unspecified", net.ParseIP("::"), RuleUnspecified},
		{"this network", net.ParseIP("0.1.2.3"), RuleThisNetwork},
		{"loopback 127.0.0.1", net.ParseIP("127.0.0.1"), RuleLoopback},
		{"loopback 127.5.5.5", net.ParseIP("127.5.5.5"), RuleLoopback},
		{"loopback 4-byte form", net.IPv4(127, 0, 0, 1).To4(), RuleLoopback},
		{"loopback ::1", net.ParseIP("::1"), RuleLoopback},
		{"cloud metadata", net.ParseIP("169.254.169.254"), RuleLinkLocalUnicast},
		{"ipv6 link-local", net.ParseIP("fe80::1"), RuleLinkLocalUnicast},
		{"ipv6 link-local multicast", net.ParseIP("ff02::1"), RuleLinkLocalMulticast},
		{"ipv4 link-local multicast", net.ParseIP("224.0.0.1"), RuleLinkLocalMulticast},
		{"ipv6 interface-local multicast", net.ParseIP("ff01::1"), RuleInterfaceLocalMulticast},
		{"ipv4 multicast", net.ParseIP("239.1.2.3"), RuleMulticast},
		{"ipv6 global multicast", net.ParseIP("ff0e::1"), RuleMulticast},
		{"limited broadcast", net.ParseIP("255.255.255.255"), RuleLimitedBroadcast},
		{"mapped loopback", net.ParseIP("::ffff:127.0.0.1"), RuleLoopback},
		{"mapped metadata", net.ParseIP("::ffff:169.254.169.254"), RuleLinkLocalUnicast},
		{"nat64 loopback", net.ParseIP("64:ff9b::7f00:1"), RuleLoopback},
		{"ipv4-compatible loopback", net.ParseIP("::7f00:1"), RuleIPv4Compatible},
		{"host interface address", net.ParseIP("192.168.1.10"), RuleHostLocal},
		{"host interface address mapped", net.ParseIP("::ffff:192.168.1.10"), RuleHostLocal},
		{"host interface ipv6", net.ParseIP("fd00::10"), RuleHostLocal},
		{"same lan, not local", net.ParseIP("192.168.1.11"), RulePrivate},
		{"rfc1918 10/8", net.ParseIP("10.0.0.1"), RulePrivate},
		{"rfc1918 172.16/12", net.ParseIP("172.16.5.5"), RulePrivate},
		{"rfc1918 172.16/12 upper edge", net.ParseIP("172.31.255.254"), RulePrivate},
		{"just outside 172.16/12", net.ParseIP("172.32.0.1"), ""},
		{"rfc1918 192.168/16", net.ParseIP("192.168.200.1"), RulePrivate},
		{"wsl2 nat default gateway", net.ParseIP("172.24.64.1"), RulePrivate},
		{"docker bridge gateway", net.ParseIP("172.17.0.1"), RulePrivate},
		{"docker bridge container", net.ParseIP("172.17.0.2"), RulePrivate},
		{"mapped rfc1918", net.ParseIP("::ffff:10.1.2.3"), RulePrivate},
		{"nat64 rfc1918", net.ParseIP("64:ff9b::a01:203"), RulePrivate},
		{"cgnat 100.64/10", net.ParseIP("100.64.0.1"), RuleSharedAddress},
		{"tailnet address", net.ParseIP("100.101.102.103"), RuleSharedAddress},
		{"just outside 100.64/10", net.ParseIP("100.128.0.1"), ""},
		{"ula", net.ParseIP("fd12:3456::1"), RuleUniqueLocal},
		{"ula fc00", net.ParseIP("fc00::1"), RuleUniqueLocal},
		{"site-local", net.ParseIP("fec0::1"), RuleSiteLocal},
		{"public v4", net.ParseIP("8.8.8.8"), ""},
		{"public v4 mapped", net.ParseIP("::ffff:8.8.8.8"), ""},
		{"public v6", net.ParseIP("2001:4860:4860::8888"), ""},
		{"nat64 public", net.ParseIP("64:ff9b::808:808"), ""},
		{"test-net-3", net.ParseIP("203.0.113.7"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := DestinationAllowed(tc.ip, local)
			if tc.wantRule == "" {
				if err != nil {
					t.Fatalf("DestinationAllowed(%v) = %v, want allowed", tc.ip, err)
				}
				return
			}
			var re *RefusedError
			if !errors.As(err, &re) {
				t.Fatalf("DestinationAllowed(%v) = %v, want RefusedError rule %s", tc.ip, err, tc.wantRule)
			}
			if re.Rule != tc.wantRule {
				t.Fatalf("DestinationAllowed(%v) rule = %s, want %s", tc.ip, re.Rule, tc.wantRule)
			}
		})
	}
}

func TestDestinationAllowed_NoLocal(t *testing.T) {
	t.Parallel()
	// With no local list a public address is allowed and a nil entry in the
	// list never matches (the host-local row cannot refuse by accident).
	if err := DestinationAllowed(net.ParseIP("203.0.113.9"), nil); err != nil {
		t.Fatalf("public address with no local list refused: %v", err)
	}
	if err := DestinationAllowed(net.ParseIP("203.0.113.9"), []net.IP{nil}); err != nil {
		t.Fatalf("nil entry in local list matched: %v", err)
	}
	// A private address is refused by the private row, not host-local.
	var re *RefusedError
	if err := DestinationAllowed(net.ParseIP("192.168.1.10"), nil); !errors.As(err, &re) || re.Rule != RulePrivate || !re.AllowListable {
		t.Fatalf("private address with no local list = %v, want %s (allow-listable)", err, RulePrivate)
	}
}

func TestPolicyAllowList(t *testing.T) {
	t.Parallel()
	allow, err := ParseAllowCIDRs([]string{"10.20.0.0/16", "fd00:1::/32", "100.100.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Allow: allow}
	local := []net.IP{net.ParseIP("10.20.0.5")}
	tests := []struct {
		name     string
		ip       net.IP
		wantRule string
	}{
		{"allow-listed v4", net.ParseIP("10.20.30.40"), ""},
		{"allow-listed mapped v4", net.ParseIP("::ffff:10.20.30.40"), ""},
		{"allow-listed nat64 v4", net.ParseIP("64:ff9b::a14:1e28"), ""},
		{"allow-listed v6 ula", net.ParseIP("fd00:1::9"), ""},
		{"allow-listed cgnat", net.ParseIP("100.100.1.1"), ""},
		{"private outside the list", net.ParseIP("10.21.0.1"), RulePrivate},
		{"ula outside the list", net.ParseIP("fd00:2::1"), RuleUniqueLocal},
		{"host interface inside the list stays refused", net.ParseIP("10.20.0.5"), RuleHostLocal},
		{"loopback stays refused", net.ParseIP("127.0.0.1"), RuleLoopback},
		{"metadata stays refused", net.ParseIP("169.254.169.254"), RuleLinkLocalUnicast},
		{"public still allowed", net.ParseIP("8.8.8.8"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := p.Check(tc.ip, local)
			if tc.wantRule == "" {
				if err != nil {
					t.Fatalf("Check(%v) = %v, want allowed", tc.ip, err)
				}
				return
			}
			var re *RefusedError
			if !errors.As(err, &re) || re.Rule != tc.wantRule {
				t.Fatalf("Check(%v) = %v, want rule %s", tc.ip, err, tc.wantRule)
			}
		})
	}
}

func TestRefusedErrorNamesConfigKeyOnlyForAllowListableRules(t *testing.T) {
	t.Parallel()
	err := DestinationAllowed(net.ParseIP("192.168.1.20"), nil)
	if err == nil || !strings.Contains(err.Error(), RulePrivate) || !strings.Contains(err.Error(), AllowCIDRsConfigKey) {
		t.Fatalf("private refusal %v does not name the rule and %s", err, AllowCIDRsConfigKey)
	}
	err = DestinationAllowed(net.ParseIP("127.0.0.1"), nil)
	if err == nil || strings.Contains(err.Error(), AllowCIDRsConfigKey) {
		t.Fatalf("loopback refusal %v must not suggest the allow-list", err)
	}
	if strings.ContainsRune(err.Error(), '\u2014') {
		t.Fatalf("em-dash in %q", err)
	}
}

func TestParseAllowCIDRs(t *testing.T) {
	t.Parallel()
	good := []string{"10.0.0.0/8", "10.20.0.0/16", "172.16.0.0/12", "172.20.1.0/24", "192.168.0.0/16", "192.168.5.7/32", "100.64.0.0/10", "fc00::/7", "fd12:3456::/48", "fec0::/10", " 10.1.0.0/16 "}
	got, err := ParseAllowCIDRs(good)
	if err != nil || len(got) != len(good) {
		t.Fatalf("ParseAllowCIDRs(%v) = %v, %v", good, got, err)
	}
	if got, err := ParseAllowCIDRs(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty list = %v, %v", got, err)
	}
	bad := []string{
		"",                    // empty
		"10.0.0.1",            // no mask
		"10.1.2.3/8",          // host bits
		"0.0.0.0/0",           // everything
		"8.8.8.0/24",          // public: a no-op
		"10.0.0.0/7",          // wider than 10/8
		"172.0.0.0/8",         // wider than 172.16/12
		"127.0.0.0/8",         // loopback
		"169.254.0.0/16",      // link-local / metadata
		"::/0",                // everything v6
		"fe80::/10",           // link-local v6
		"::ffff:10.0.0.0/104", // mapped
		"-10.0.0.0/8",         // flag-shaped garbage
		"10.0.0.0/8 x",        // trailing junk
	}
	for _, b := range bad {
		if _, err := ParseAllowCIDRs([]string{b}); err == nil {
			t.Errorf("ParseAllowCIDRs(%q) accepted", b)
		} else if strings.ContainsRune(err.Error(), '\u2014') {
			t.Errorf("em-dash in %q", err)
		}
	}
}
