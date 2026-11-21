package openshellorg

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestCompileInternetRow (lane G4, design 6.1): the internet row compiles
// one network rule from the narrowed hosts, refuses a run with no blocked
// ranges, compiles no host for an empty list (every connection denied), and
// keeps an allow-list range that falls inside a blocked range blocked.
func TestCompileInternetRow(t *testing.T) {
	base := CompileInput{
		OrgID: "org-1", RunID: "AAAAAAAAAAAAAAAAAAAAAA", MemberID: "m1", NodeHash: "n1",
		Image: "registry.example.com/box@sha256:" + strings.Repeat("a", 64), Quotas: DefaultQuotas(),
		Narrowed:   Narrowed{Tier: TierInternet, Source: SourceCloneLocal, EgressHosts: []string{"pypi.org"}},
		AllowCIDRs: []string{"10.1.0.0/16"}, BlockedCIDRs: []string{"10.0.0.0/8"},
	}
	cases := []struct {
		name    string
		change  func(*CompileInput)
		reason  Reason
		has     []string
		hasNot  []string
		noRules bool
	}{
		{"hosts and ranges", func(*CompileInput) {}, ReasonNone, []string{"pypi.org", BoxObserverBinary}, []string{"10.1.0.0/16", BoxGitBinary}, false},
		{"no blocked ranges refused", func(c *CompileInput) { c.BlockedCIDRs = nil }, ReasonBlockedCIDRsMissing, nil, nil, false},
		{"empty host list compiles no host", func(c *CompileInput) { c.Narrowed.EgressHosts = nil }, ReasonNone, nil, []string{"pypi.org"}, true},
		{"clone host added with git", func(c *CompileInput) {
			c.Narrowed.Source, c.Narrowed.CloneHosts = SourceCloneRemote, []string{"git.example.com"}
		}, ReasonNone, []string{"git.example.com", BoxGitBinary}, nil, false},
	}
	for _, tc := range cases {
		c := base
		tc.change(&c)
		spec, _, r, err := CompileOrgSpec(c)
		if err != nil || r != tc.reason {
			t.Errorf("%s: reason %s err %v", tc.name, r, err)
			continue
		}
		if r != ReasonNone {
			continue
		}
		for _, w := range tc.has {
			if !strings.Contains(spec.PolicyYAML, w) {
				t.Errorf("%s: policy lacks %q:\n%s", tc.name, w, spec.PolicyYAML)
			}
		}
		for _, w := range tc.hasNot {
			if strings.Contains(spec.PolicyYAML, w) {
				t.Errorf("%s: policy names %q:\n%s", tc.name, w, spec.PolicyYAML)
			}
		}
		if tc.noRules && strings.Contains(spec.PolicyYAML, "network_policies:\n  ") {
			t.Errorf("%s: an empty host list compiled a rule:\n%s", tc.name, spec.PolicyYAML)
		}
	}
}

// TestNetSubtractBlocked (the netrules.go hunk): an allow-list entry inside
// a blocked range stays blocked, a range outside it is kept, an empty list
// changes nothing, and a non-canonical range is refused.
func TestNetSubtractBlocked(t *testing.T) {
	in := sandboxopenshell.NetInput{Hosts: []string{"pypi.org"}, AllowCIDRs: []string{"10.1.0.0/16", "192.168.5.0/24"}, BlockedCIDRs: []string{"10.0.0.0/8"}, Binaries: []string{BoxObserverBinary}}
	rules, err := sandboxopenshell.CompileNetRules(vocab.TierInternet, in)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules %v %v", rules, err)
	}
	has := func(p string) bool {
		want := netip.MustParsePrefix(p)
		for _, ep := range rules[0].Endpoints {
			for _, a := range ep.AllowedIPs {
				if a.Overlaps(want) {
					return true
				}
			}
		}
		return false
	}
	if has("10.1.2.0/24") {
		t.Error("an allow-list range inside the blocked range is reachable")
	}
	if !has("192.168.5.0/24") {
		t.Error("an allow-list range outside the blocked range was dropped")
	}
	same, err := sandboxopenshell.NetSubtractBlocked([]netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}, nil)
	if err != nil || len(same) != 1 {
		t.Errorf("empty blocked list: %v %v", same, err)
	}
	if _, err := sandboxopenshell.NetSubtractBlocked(nil, []string{"10.0.0.1/8"}); err == nil {
		t.Error("a non-canonical blocked range was accepted")
	}
}

// TestCompileOrgRowWritablePaths (fix round 1, A3 and A4): the org row's
// box has no home mount (its home is on the box's writable layer, kept by a
// hold), and the policy lets the workload write the home, the fixed
// workspace and the run dir; the keeper is a plain shell.
func TestCompileOrgRowWritablePaths(t *testing.T) {
	in := CompileInput{
		OrgID: "org-1", RunID: "AAAAAAAAAAAAAAAAAAAAAA", MemberID: "m1", NodeHash: "n1",
		Image: "registry.example.com/box@sha256:" + strings.Repeat("a", 64), Quotas: DefaultQuotas(),
		Narrowed: Narrowed{Tier: TierInternet, Source: SourceCloneLocal}, BlockedCIDRs: []string{"10.0.0.0/8"},
	}
	spec, _, r, err := CompileOrgSpec(in)
	if err != nil || r != ReasonNone {
		t.Fatalf("reason %s err %v", r, err)
	}
	_, rest, ok := strings.Cut(spec.PolicyYAML, "read_write:")
	if !ok {
		t.Fatalf("no read_write list:\n%s", spec.PolicyYAML)
	}
	for _, p := range []string{BoxHome, BoxWorkspace, BoxRunDir} {
		if !strings.Contains(rest, p) {
			t.Errorf("read_write lacks %s:\n%s", p, spec.PolicyYAML)
		}
	}
	if strings.Contains(spec.PolicyYAML, "tmpfs") {
		t.Errorf("the org row's policy names a tmpfs:\n%s", spec.PolicyYAML)
	}
	if strings.Join(spec.Command, " ") != strings.Join(KeeperArgv, " ") || spec.Command[0] != "sh" {
		t.Errorf("keeper %v", spec.Command)
	}
}

// TestHostAddrsOf pins the host-address rule of OB-085: an IP entry becomes
// an address, and a CIDR, a zoned address or anything else is refused as
// org_host_addrs_invalid (deny-side input, so never dropped).
func TestHostAddrsOf(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		want    []netip.Addr
		reason  Reason
	}{
		{"none", nil, nil, ReasonNone},
		{"ipv4", []string{"10.0.0.1"}, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, ReasonNone},
		{"ipv4 mapped is unmapped", []string{"::ffff:10.0.0.1"}, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, ReasonNone},
		{"ipv6 loopback", []string{"::1"}, []netip.Addr{netip.MustParseAddr("::1")}, ReasonNone},
		{"cidr refused", []string{"10.0.0.1", "10.0.0.1/32"}, nil, ReasonHostAddrsInvalid},
		{"zone refused", []string{"::1%lo"}, nil, ReasonHostAddrsInvalid},
		{"name refused", []string{"host.example.com"}, nil, ReasonHostAddrsInvalid},
	}
	for _, tc := range cases {
		got, r := HostAddrsOf(tc.entries)
		if r != tc.reason || len(got) != len(tc.want) {
			t.Errorf("%s: %v %s", tc.name, got, r)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
			}
		}
	}
}

// TestCompileInternetHostAddrs: the sandbox host's address is cut out of an
// allow-list range, so the compile's input really reaches the policy.
func TestCompileInternetHostAddrs(t *testing.T) {
	in := CompileInput{
		OrgID: "org-1", RunID: "AAAAAAAAAAAAAAAAAAAAAA", MemberID: "m1", NodeHash: "n1",
		Image: "registry.example.com/box@sha256:" + strings.Repeat("a", 64), Quotas: DefaultQuotas(),
		Narrowed:   Narrowed{Tier: TierInternet, Source: SourceCloneLocal, EgressHosts: []string{"pypi.org"}},
		AllowCIDRs: []string{"10.0.0.1/32"}, BlockedCIDRs: []string{"169.254.169.254/32"},
	}
	_, without, r, err := CompileOrgSpec(in)
	if err != nil || r != ReasonNone {
		t.Fatalf("without host: %s %v", r, err)
	}
	in.HostAddrs = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	spec, with, r, err := CompileOrgSpec(in)
	if err != nil || r != ReasonNone {
		t.Fatalf("with host: %s %v", r, err)
	}
	if with == without || strings.Contains(spec.PolicyYAML, "10.0.0.1/32") {
		t.Fatalf("the host address did not reach the policy:\n%s", spec.PolicyYAML)
	}
}
