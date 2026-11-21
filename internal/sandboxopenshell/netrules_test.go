package sandboxopenshell

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// testObserverBin is the box path of Observer's own binary in the network
// fixtures (a sentinel path, same-path bound).
const testObserverBin = "/home/dev/.observer/bin/observer"

// netInput is an internet run's network input: a host list with an exact
// name and a wildcard, a private allow-list entry, a public and a private
// host address (sentinel documentation addresses) and Observer's binary.
func netInput() NetInput {
	return NetInput{
		Hosts:      []string{"proxy.golang.org", "*.npmjs.org", "api.github.com"},
		AllowCIDRs: []string{"10.20.0.0/16"},
		HostAddrs:  []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("2001:db8::7")},
		Binaries:   []string{testObserverBin},
	}
}

// netGoldenCases are the network compiler's goldens: the whole policy
// document of an internet run, so a drift in either section shows.
var netGoldenCases = []struct {
	name string
	in   func() Input
}{
	{"net-internet-hosts", func() Input {
		in := baseInput()
		in.Settings.Egress = vocab.TierInternet
		in.Net = netInput()
		return in
	}},
	// An organization pin that left no host in common: no rule at all, so
	// every connection is denied, exactly as on proxy_only.
	{"net-internet-org-pin-none", func() Input {
		in := baseInput()
		in.Settings.Egress = vocab.TierInternet
		in.Net = NetInput{NoHost: true}
		return in
	}},
}

func TestNetRulesGolden(t *testing.T) {
	t.Parallel()
	for _, tc := range netGoldenCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Compile(tc.in())
			if err != nil {
				t.Fatal(err)
			}
			got := string(p.PolicyYAML)
			file := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/sandboxopenshell -run TestNetRulesGolden -update)", err)
			}
			if got != string(want) {
				t.Fatalf("%s drifted:\n--- got\n%s\n--- want\n%s", file, got, want)
			}
		})
	}
}

// TestNetTierRows: one case per row of the tier table. proxy_only and none
// compile no rule (and no network_policies key, the O1B goldens are
// unchanged); internet compiles the one host rule; host is not a row.
func TestNetTierRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tier    vocab.Tier
		rules   int
		wantErr error
	}{
		{vocab.TierInternet, 1, nil},
		{vocab.TierProxyOnly, 0, nil},
		{vocab.TierNone, 0, nil},
		{vocab.TierHost, 0, ErrTier},
	}
	if len(cases) != len(netTierRows)+1 {
		t.Fatalf("%d cases for %d tier rows plus host", len(cases), len(netTierRows))
	}
	for _, tc := range cases {
		t.Run(string(tc.tier), func(t *testing.T) {
			rules, err := CompileNetRules(tc.tier, netInput())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			if len(rules) != tc.rules {
				t.Fatalf("%d rules, want %d", len(rules), tc.rules)
			}
			if tc.wantErr != nil {
				return
			}
			in := baseInput()
			in.Settings.Egress = tc.tier
			in.Net = netInput()
			p, err := Compile(in)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(p.PolicyYAML), "network_policies:"); got != (tc.rules > 0) {
				t.Fatalf("network_policies present %v, want %v", got, tc.rules > 0)
			}
		})
	}
}

// TestNetMappingRows: one case per mapping row of netrules.go's comment.
func TestNetMappingRows(t *testing.T) {
	t.Parallel()
	rules, err := CompileNetRules(vocab.TierInternet, netInput())
	if err != nil {
		t.Fatal(err)
	}
	r := rules[0]
	t.Run("key not reserved", func(t *testing.T) {
		if strings.HasPrefix(r.Key, "_provider_") || r.Key != NetRuleKey {
			t.Fatalf("key %q", r.Key)
		}
	})
	t.Run("exact host", func(t *testing.T) {
		if !slices.ContainsFunc(r.Endpoints, func(e NetEndpoint) bool { return e.Host == "api.github.com" && e.Entry == "api.github.com" }) {
			t.Fatalf("endpoints %+v", r.Endpoints)
		}
	})
	t.Run("wildcard is a whole first label glob", func(t *testing.T) {
		if !slices.ContainsFunc(r.Endpoints, func(e NetEndpoint) bool { return e.Host == "**.npmjs.org" && e.Entry == "*.npmjs.org" }) {
			t.Fatalf("endpoints %+v", r.Endpoints)
		}
	})
	t.Run("ports 80 and 443", func(t *testing.T) {
		for _, e := range r.Endpoints {
			if !slices.Equal(e.Ports, []int{80, 443}) {
				t.Fatalf("%s ports %v", e.Host, e.Ports)
			}
		}
	})
	t.Run("binaries are Observer's own", func(t *testing.T) {
		if !slices.Equal(r.Binaries, []string{testObserverBin}) {
			t.Fatalf("binaries %v", r.Binaries)
		}
	})
	t.Run("every endpoint agrees on allowed_ips", func(t *testing.T) {
		for _, e := range r.Endpoints {
			if !slices.Equal(e.AllowedIPs, r.Endpoints[0].AllowedIPs) {
				t.Fatalf("%s allowed_ips differ (OpenShell rejects a generation whose same-host endpoints disagree)", e.Host)
			}
		}
	})
	t.Run("enforcement is enforce", func(t *testing.T) {
		in := baseInput()
		in.Settings.Egress = vocab.TierInternet
		in.Net = netInput()
		p, err := Compile(in)
		if err != nil {
			t.Fatal(err)
		}
		y := string(p.PolicyYAML)
		if strings.Count(y, `enforcement: "enforce"`) != len(r.Endpoints) || strings.Contains(y, "audit") {
			t.Fatalf("enforcement not explicit on every endpoint:\n%s", y)
		}
	})
}

// TestNetAllowedIPs pins the private-range and floor mapping: which
// addresses a resolved listed host may and may not land on.
func TestNetAllowedIPs(t *testing.T) {
	t.Parallel()
	in := netInput()
	allowed, err := NetAllowedIPs(in.AllowCIDRs, in.HostAddrs)
	if err != nil {
		t.Fatal(err)
	}
	inside := func(a string) bool {
		addr := netip.MustParseAddr(a)
		return slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(addr) })
	}
	cases := []struct {
		addr string
		want bool
		why  string
	}{
		{"8.8.8.8", true, "public IPv4"},
		{"1.1.1.1", true, "public IPv4"},
		{"2606:4700::1111", true, "public IPv6"},
		{"10.20.3.4", true, "inside egress_allow_cidrs"},
		{"10.21.0.1", false, "private, not allow-listed"},
		{"172.16.0.1", false, "private"},
		{"192.168.0.1", false, "private"},
		{"100.64.0.1", false, "shared address space"},
		{"127.0.0.1", false, "loopback"},
		{"0.0.0.0", false, "unspecified"},
		{"0.1.2.3", false, "this network"},
		{"169.254.169.254", false, "link-local metadata"},
		{"224.0.0.1", false, "multicast"},
		{"255.255.255.255", false, "limited broadcast"},
		{"203.0.113.7", false, "the host's own public address"},
		{"203.0.113.8", true, "a public neighbour of the host's address"},
		{"2001:db8::7", false, "the host's own IPv6 address"},
		{"::1", false, "IPv6 loopback"},
		{"::", false, "IPv6 unspecified"},
		{"fe80::1", false, "IPv6 link-local"},
		{"fc00::1", false, "unique local"},
		{"fec0::1", false, "site-local"},
		{"ff02::1", false, "IPv6 multicast"},
		{"::ffff:10.0.0.1", false, "IPv4-mapped private"},
		{"64:ff9b::a00:1", false, "NAT64 of a private address"},
		{"::a00:1", false, "IPv4-compatible"},
	}
	for _, tc := range cases {
		if got := inside(tc.addr); got != tc.want {
			t.Errorf("%s (%s): allowed %v, want %v", tc.addr, tc.why, got, tc.want)
		}
	}
	for i := 1; i < len(allowed); i++ {
		if allowed[i-1].Overlaps(allowed[i]) {
			t.Errorf("%s overlaps %s", allowed[i-1], allowed[i])
		}
	}
	if _, err := NetAllowedIPs([]string{"8.8.8.0/24"}, nil); !errors.Is(err, ErrNetCIDR) {
		t.Errorf("a public allow-list entry: err %v, want ErrNetCIDR", err)
	}
	if _, err := NetAllowedIPs([]string{"127.0.0.0/8"}, nil); !errors.Is(err, ErrNetCIDR) {
		t.Errorf("a loopback allow-list entry: err %v, want ErrNetCIDR", err)
	}
}

// TestNetCompileRefusals: one case per refusal.
func TestNetCompileRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*NetInput)
		want error
	}{
		{"no host list", func(n *NetInput) { n.Hosts = nil }, ErrNetAllowList},
		{"literal IPv4", func(n *NetInput) { n.Hosts = []string{"93.184.216.34"} }, ErrNetHost},
		{"literal IPv6", func(n *NetInput) { n.Hosts = []string{"[2001:db8::1]"} }, ErrNetHost},
		{"uppercase", func(n *NetInput) { n.Hosts = []string{"Example.com"} }, ErrNetHost},
		{"one label", func(n *NetInput) { n.Hosts = []string{"localhost"} }, ErrNetHost},
		{"wildcard over a TLD", func(n *NetInput) { n.Hosts = []string{"*.com"} }, ErrNetHost},
		{"inner wildcard", func(n *NetInput) { n.Hosts = []string{"a.*.example.com"} }, ErrNetHost},
		{"bare star", func(n *NetInput) { n.Hosts = []string{"*"} }, ErrNetHost},
		{"punycode", func(n *NetInput) { n.Hosts = []string{"xn--80ak6aa92e.com"} }, ErrNetHost},
		{"trailing dot", func(n *NetInput) { n.Hosts = []string{"example.com."} }, ErrNetHost},
		{"space", func(n *NetInput) { n.Hosts = []string{" example.com"} }, ErrNetHost},
		{"underscore", func(n *NetInput) { n.Hosts = []string{"a_b.example.com"} }, ErrNetHost},
		{"provider host", func(n *NetInput) { n.Hosts = []string{"api.anthropic.com"} }, ErrNetProviderHost},
		{"configured upstream", func(n *NetInput) {
			n.Hosts = []string{"llm.corp.example"}
			n.ProviderHosts = []string{"llm.corp.example"}
		}, ErrNetProviderHost},
		{"private CIDR outside the ranges", func(n *NetInput) { n.AllowCIDRs = []string{"8.8.8.0/24"} }, ErrNetCIDR},
		{"no binary", func(n *NetInput) { n.Binaries = nil }, ErrNetBinary},
		{"relative binary", func(n *NetInput) { n.Binaries = []string{"bin/observer"} }, ErrNetBinary},
		{"too many hosts", func(n *NetInput) {
			n.Hosts = nil
			for i := 0; i <= maxNetHosts; i++ {
				n.Hosts = append(n.Hosts, "h"+strings.Repeat("a", i%50)+string(rune('a'+i%26))+".example.com")
			}
		}, ErrNetTooMany},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := netInput()
			tc.mut(&in)
			if _, err := CompileNetRules(vocab.TierInternet, in); !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			// The refusal reaches the launch through Compile.
			pin := baseInput()
			pin.Settings.Egress = vocab.TierInternet
			pin.Net = in
			if _, err := Compile(pin); !errors.Is(err, tc.want) {
				t.Fatalf("Compile err %v, want %v", err, tc.want)
			}
		})
	}
}

// TestNetHostAliasFloor is floor F-NET-HOSTALIAS (audit finding O3-A3):
// one row per alias, each refused as itself, as a name below it and under
// a wildcard that covers it, while near misses compile.
func TestNetHostAliasFloor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		alias     string
		spellings []string
	}{
		{"localhost", []string{"a.localhost", "*.a.localhost"}},
		{"localhost.localdomain", []string{"localhost.localdomain", "a.localhost.localdomain", "*.localhost.localdomain"}},
		{"openshell.internal", []string{"host.openshell.internal", "openshell.internal", "*.openshell.internal", "x.host.openshell.internal"}},
		{"host.docker.internal", []string{"host.docker.internal", "*.docker.internal", "*.host.docker.internal"}},
		{"gateway.docker.internal", []string{"gateway.docker.internal", "a.gateway.docker.internal"}},
		{"host.containers.internal", []string{"host.containers.internal", "*.containers.internal"}},
		{"metadata.google.internal", []string{"metadata.google.internal", "*.google.internal"}},
		{"instance-data.ec2.internal", []string{"instance-data.ec2.internal", "*.ec2.internal"}},
	}
	if len(cases) != len(netAliases) {
		t.Fatalf("%d cases for %d alias rows", len(cases), len(netAliases))
	}
	for i, tc := range cases {
		if netAliases[i].name != tc.alias {
			t.Fatalf("row %d is %s, case %s", i, netAliases[i].name, tc.alias)
		}
		for _, sp := range tc.spellings {
			in := netInput()
			in.Hosts = append(in.Hosts, sp)
			if _, err := CompileNetRules(vocab.TierInternet, in); !errors.Is(err, ErrNetHostAlias) {
				t.Errorf("%s (%q): err %v, want ErrNetHostAlias", tc.alias, sp, err)
			}
		}
	}
	in := netInput()
	in.Hosts = []string{"localhost.example.com", "docker.internal.example.com", "notlocalhost.com", "metadata.google.internal.example.org"}
	if _, err := CompileNetRules(vocab.TierInternet, in); err != nil {
		t.Fatalf("near misses: %v", err)
	}
}

// TestNetModelHostNeverListed is the adversarial row (lane O3, rule W4): a
// model provider's host is never reachable directly from the box. Every
// spelling that would name or cover one is refused, whatever
// provider_direct says (the compiler does not read it), and no compiled
// endpoint of a long mixed list matches any provider host.
func TestNetModelHostNeverListed(t *testing.T) {
	t.Parallel()
	upstream := "llm.corp.example"
	providers := append(vocab.ModelProviderHosts(), upstream)
	for _, p := range providers {
		labels := strings.Split(p, ".")
		spellings := []string{p, "eu." + p, "*." + p}
		if len(labels) >= 3 {
			spellings = append(spellings, "*."+strings.Join(labels[1:], "."))
		}
		for _, s := range spellings {
			in := netInput()
			in.Hosts = append(in.Hosts, s)
			in.ProviderHosts = []string{upstream}
			if _, err := CompileNetRules(vocab.TierInternet, in); !errors.Is(err, ErrNetProviderHost) {
				t.Errorf("%q (provider %s): err %v, want ErrNetProviderHost", s, p, err)
			}
		}
	}
	// A list of near misses compiles, and no endpoint can match a provider.
	in := netInput()
	in.ProviderHosts = []string{upstream}
	in.Hosts = []string{"anthropic.com.example.org", "openai.com.example.org", "*.githubusercontent.com", "docs.anthropic.com", "platform.openai.com", "corp.example"}
	rules, err := CompileNetRules(vocab.TierInternet, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rules[0].Endpoints {
		name, glob := strings.CutPrefix(e.Host, "**.")
		for _, p := range providers {
			if (!glob && vocab.MatchesHost(name, []string{p})) || (glob && (vocab.MatchesHost(name, []string{p}) || strings.HasSuffix(p, "."+name))) {
				t.Errorf("endpoint %s reaches provider %s", e.Host, p)
			}
		}
	}
	// The proxy_only and none tiers list no endpoint at all.
	for _, tier := range []vocab.Tier{vocab.TierProxyOnly, vocab.TierNone} {
		in := netInput()
		in.Hosts = []string{"api.anthropic.com"}
		if rules, err := CompileNetRules(tier, in); err != nil || len(rules) != 0 {
			t.Errorf("%s: rules %v err %v, want none", tier, rules, err)
		}
	}
}

// TestNetSubtract pins the prefix arithmetic the allowed_ips list rests on.
func TestNetSubtract(t *testing.T) {
	t.Parallel()
	pp := netip.MustParsePrefix
	got := subtract(pp("10.0.0.0/8"), pp("10.0.0.0/9"))
	if len(got) != 1 || got[0] != pp("10.128.0.0/9") {
		t.Fatalf("10/8 less 10/9 = %v", got)
	}
	if got := subtract(pp("10.0.0.0/8"), pp("11.0.0.0/8")); len(got) != 1 || got[0] != pp("10.0.0.0/8") {
		t.Fatalf("disjoint = %v", got)
	}
	if got := subtract(pp("10.1.0.0/16"), pp("10.0.0.0/8")); len(got) != 0 {
		t.Fatalf("covered = %v", got)
	}
	if got := subtract(pp("2000::/3"), pp("10.0.0.0/8")); len(got) != 1 {
		t.Fatalf("mixed families = %v", got)
	}
	got = subtract(pp("10.0.0.0/30"), pp("10.0.0.1/32"))
	want := []netip.Prefix{pp("10.0.0.0/32"), pp("10.0.0.2/31")}
	if !slices.Equal(got, want) {
		t.Fatalf("/30 less one address = %v, want %v", got, want)
	}
}
