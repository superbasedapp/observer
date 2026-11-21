package sandboxopenshell

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// netrules.go is the network rule compiler of the openshell row (lane O3,
// OpenShell plan doc 04 R2.6 O3, rule W4): it maps the run's internet-tier
// inputs, the same ones the sandboxnet egress gateway reads on every other
// row ([terminal.sandbox].egress_allow_hosts, egress_allow_cidrs, the
// private-range rules, the SSRF floor and the model-provider host block),
// onto OpenShell network rules (the policy document's network_policies, a
// map of named rules with endpoints and binaries; o0-receipts.md "Policy
// document").
//
// One egress owner per run (W4): on the openshell row OpenShell's own proxy
// is the only egress owner on every tier (Net.Enforcer openshell_proxy), so
// the host helper never starts Observer's egress gateway beside it; the
// proxy_only and none tiers compile no rule at all (all egress denied, the
// model proxy and the hooks reach the daemon only through the capture relay
// over the per-run socket dir), and the internet tier compiles exactly the
// rules below.
//
// The mapping, row by row (sandboxnet's rule on the left):
//
//   - host list (hosts.go): each exact entry is an endpoint host; a
//     "*.<suffix>" entry, which matches every name below the suffix at any
//     depth and never the suffix itself, is the OpenShell glob
//     "**.<suffix>" ("**" is a whole first label only and needs three
//     labels, which the two-label suffix rule guarantees). No list: the
//     internet tier means "every public host", which OpenShell cannot
//     express (whole-host globs are rejected), so the compile refuses the
//     tier with a plain reason (ErrNetAllowList). An organization pin that
//     left no host in common compiles no rule (all egress denied), as the
//     gateway's deny-all list refuses every host.
//   - ports (tlsname.go): 443 and 80 only, as the gateway allows CONNECT to
//     443 and a plain http request to 80 under a list.
//   - private ranges and the SSRF floor (policy.go): every endpoint carries
//     the same allowed_ips list, the public address space (IPv4 less the
//     floor and the private ranges, IPv6 global unicast 2000::/3) plus the
//     operator's egress_allow_cidrs, less the host's own addresses. An
//     exact host OpenShell would otherwise let resolve to an RFC 1918
//     address is then refused, as the gateway refuses it.
//   - literal IPs: never an endpoint (the list holds names only).
//   - host aliases (floor F-NET-HOSTALIAS, netAliases): localhost,
//     host.openshell.internal and every *.openshell.internal name, the
//     Docker and Podman host aliases and the cloud metadata names are never
//     an endpoint; an entry that is or covers one refuses the compile.
//   - provider-host block (provider.go): a model provider's host, or a
//     wildcard that covers one, is never an endpoint, whatever
//     provider_direct says (W4 and decision D3 of the build: model traffic
//     leaves the box only through the relay to the Observer proxy). Such an
//     entry refuses the compile (ErrNetProviderHost) instead of being
//     silently dropped, so the user sees why the host is unreachable.
//   - binaries: OpenShell matches the connecting program or any ancestor
//     (doc 03 section 4.2 note 3), and an empty list matches nothing. The
//     only binary listed is Observer's own, the box's init and an ancestor
//     of every process the agent starts, so the rule is host-level for any
//     process in the box, which is the gateway's own semantics.
//   - enforcement: always "enforce" (doc 03 AM-8; OpenShell's default is
//     "audit", which logs and allows).
//
// The compiler is pure: the driver resolves the list (governance pins
// applied), the CIDRs, the proxy's upstream hosts and the host's addresses
// and hands them in.

// NetInput is everything the network rule compiler reads beside the tier
// (Settings.Egress).
type NetInput struct {
	// Hosts is the effective [terminal.sandbox].egress_allow_hosts (an
	// organization pin applied), as sandboxnet.ParseHostRules validated it.
	Hosts []string
	// NoHost is set when an organization pin left no host in common
	// (config PinnedNoEgressHost): the run may reach no host at all.
	NoHost bool
	// AllowCIDRs is the effective [terminal.sandbox].egress_allow_cidrs.
	AllowCIDRs []string
	// ProviderHosts are the proxy's own configured upstream hosts, added to
	// the closed model-provider list (sandboxvocab.ModelProviderHosts).
	ProviderHosts []string
	// HostAddrs are the host's own interface addresses: none of them is
	// ever reachable (sandboxnet's host-local rule).
	HostAddrs []netip.Addr
	// Binaries are the box paths of the programs a rule names (Observer's
	// own binary, the box's init). Required when the tier compiles a rule.
	Binaries []string
	// BlockedCIDRs are ranges no resolved address may fall in, subtracted
	// LAST, after AllowCIDRs is added (the org-hosted row's blocked_cidrs:
	// the org's internal ranges, g1-design.md section 6.1, lane G4), so no
	// allow-list entry can re-open a blocked range. Empty for every local
	// row.
	BlockedCIDRs []string
}

// NetEndpoint is one compiled endpoint of a network rule.
type NetEndpoint struct {
	// Host is the OpenShell host pattern (exact or "**.<suffix>").
	Host string
	// Entry is the egress_allow_hosts entry it came from.
	Entry string
	// Ports are the allowed ports, ascending.
	Ports []int
	// AllowedIPs are the CIDRs a resolved address must fall in.
	AllowedIPs []netip.Prefix
}

// NetRule is one compiled network rule.
type NetRule struct {
	// Key is the network_policies map key (never "_provider_..."); Name is
	// its display name.
	Key, Name string
	Endpoints []NetEndpoint
	// Binaries are the rule's binary paths.
	Binaries []string
}

// NetRuleKey is the key of the run's one host allow-list rule. It does not
// start with "_provider_", the prefix OpenShell reserves for provider
// layers.
const NetRuleKey = "observer_egress_allow_hosts"

// NetPorts are the ports every endpoint allows (sandboxnet's listed-run
// port rule: 443 through CONNECT, 80 for a plain http request).
var NetPorts = []int{80, 443}

// netEnforcement is every endpoint's enforcement (doc 03 AM-8).
const netEnforcement = "enforce"

// The network compile refusals.
var (
	ErrNetAllowList    = errors.New("sandboxopenshell: the internet tier on the openshell row needs a host allow-list ([terminal.sandbox].egress_allow_hosts): OpenShell cannot express \"every public host\"")
	ErrNetHost         = errors.New("sandboxopenshell: a host allow-list entry is not a host name the network rules can carry")
	ErrNetProviderHost = errors.New("sandboxopenshell: a host allow-list entry is or covers a model provider's host, which is never listed in a network rule (model traffic leaves the box only through the Observer proxy)")
	ErrNetCIDR         = errors.New("sandboxopenshell: an egress_allow_cidrs entry is not a private range the rules can allow")
	ErrNetBinary       = errors.New("sandboxopenshell: a network rule needs the box path of Observer's own binary")
	ErrNetTooMany      = errors.New("sandboxopenshell: the host allow-list is longer than the network rules carry")
	ErrNetHostAlias    = errors.New("sandboxopenshell: a host allow-list entry is or covers a host-alias or metadata name, which no network rule may name (floor F-NET-HOSTALIAS)")
)

// maxNetHosts bounds the endpoints of the one rule.
const maxNetHosts = 256

// netTierRow is one row of the tier table: what the compiler does with a
// tier on the openshell row.
type netTierRow struct {
	tier vocab.Tier
	// rules: the tier compiles the host allow-list rule; false compiles no
	// rule (all egress denied by OpenShell's proxy).
	rules bool
}

// netTierRows is the tier table. The host tier is not here: the row does
// not offer it (rule K2), because OpenShell's deny-by-default fence cannot
// be lifted to the host network.
var netTierRows = []netTierRow{
	{vocab.TierInternet, true},
	{vocab.TierProxyOnly, false},
	{vocab.TierNone, false},
}

// CompileNetRules compiles the run's network rules for tier. A tier with no
// rule returns nil; the internet tier returns the one host allow-list rule
// (none when an organization pin left no host). It refuses with ErrTier,
// ErrNetAllowList, ErrNetHost, ErrNetHostAlias, ErrNetProviderHost,
// ErrNetCIDR, ErrNetBinary or ErrNetTooMany.
func CompileNetRules(tier vocab.Tier, in NetInput) ([]NetRule, error) {
	i := slices.IndexFunc(netTierRows, func(r netTierRow) bool { return r.tier == tier })
	if i < 0 {
		return nil, fmt.Errorf("%w: %q has no network rule mapping", ErrTier, tier)
	}
	if !netTierRows[i].rules || in.NoHost {
		return nil, nil
	}
	if len(in.Hosts) == 0 {
		return nil, ErrNetAllowList
	}
	if len(in.Hosts) > maxNetHosts {
		return nil, fmt.Errorf("%w (%d entries, at most %d)", ErrNetTooMany, len(in.Hosts), maxNetHosts)
	}
	if len(in.Binaries) == 0 {
		return nil, ErrNetBinary
	}
	for _, b := range in.Binaries {
		if !cleanAbs(b) {
			return nil, fmt.Errorf("%w: %q is not absolute and clean", ErrNetBinary, b)
		}
	}
	allowed, err := NetAllowedIPs(in.AllowCIDRs, in.HostAddrs)
	if err != nil {
		return nil, err
	}
	if allowed, err = NetSubtractBlocked(allowed, in.BlockedCIDRs); err != nil {
		return nil, err
	}
	providers := append(vocab.ModelProviderHosts(), in.ProviderHosts...)
	seen := map[string]bool{}
	var eps []NetEndpoint
	for _, entry := range in.Hosts {
		host, err := netHostPattern(entry)
		if err != nil {
			return nil, err
		}
		if a, hit := netAliasOverlap(entry); hit {
			return nil, fmt.Errorf("%w: %q reaches %s (%s)", ErrNetHostAlias, entry, a.name, a.why)
		}
		if p, hit := netProviderOverlap(entry, providers); hit {
			return nil, fmt.Errorf("%w: %q reaches %s", ErrNetProviderHost, entry, p)
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		eps = append(eps, NetEndpoint{Host: host, Entry: entry, Ports: append([]int(nil), NetPorts...), AllowedIPs: allowed})
	}
	sort.Slice(eps, func(a, b int) bool { return eps[a].Host < eps[b].Host })
	bins := append([]string(nil), in.Binaries...)
	sort.Strings(bins)
	bins = slices.Compact(bins)
	return []NetRule{{Key: NetRuleKey, Name: NetRuleKey, Endpoints: eps, Binaries: bins}}, nil
}

// netHostPattern validates one list entry and returns its OpenShell host
// pattern. It re-applies the shape sandboxnet.ParseHostRules enforces
// (lowercase ASCII labels, at least two labels, no IP literal, no punycode,
// "*." only as the whole first label) rather than trusting the caller,
// because a pattern the two sides read differently would allow a host the
// gateway refuses.
func netHostPattern(entry string) (string, error) {
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("%w: %q %s", ErrNetHost, entry, why)
	}
	if entry == "" || entry != strings.TrimSpace(entry) || entry != strings.ToLower(entry) {
		return bad("is empty, has surrounding space or is not lowercase")
	}
	if _, err := netip.ParseAddr(strings.Trim(entry, "[]")); err == nil {
		return bad("is an IP address")
	}
	name, wildcard := strings.CutPrefix(entry, "*.")
	if strings.Contains(name, "*") {
		return bad("has a wildcard outside a leading \"*.\"")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 || len(name) > 253 {
		return bad("needs at least two labels and at most 253 bytes")
	}
	for _, l := range labels {
		if !netLabel(l) {
			return bad("has a label that is not 1 to 63 letters, digits or '-'")
		}
		if strings.HasPrefix(l, "xn--") {
			return bad("has a punycode label")
		}
	}
	if wildcard {
		return "**." + name, nil
	}
	return name, nil
}

// netLabel reports whether l is a plain DNS label (1 to 63 of a-z, 0-9 and
// '-', not starting or ending with '-').
func netLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// netAlias is one row of the host-alias floor: a name that reaches the
// host, the container runtime's host or a cloud metadata service.
type netAlias struct{ name, why string }

// netAliases is floor F-NET-HOSTALIAS (doc 04, re-checked by every target
// compiler): no entry that is, sits below or could match one of these names
// compiles into a rule, whatever the list says. On the sandboxnet rows such
// a name resolves to a loopback, link-local, host-local or private address
// and is refused there by a rule no allow-list lifts; OpenShell documents
// that a rule naming host.openshell.internal reaches services on the
// gateway host, so the compiler refuses the name itself. The literal
// addresses of the floor (127.0.0.0/8, ::1, link-local, the host's own) are
// already outside every rule: an entry is never an IP, and allowed_ips
// excludes them.
var netAliases = []netAlias{
	{"localhost", "the box's own loopback (RFC 6761: every name below it is loopback too)"},
	{"localhost.localdomain", "a loopback alias in many hosts files"},
	{"openshell.internal", "OpenShell's host aliases (host.openshell.internal reaches services on the gateway host)"},
	{"host.docker.internal", "Docker's alias for the host"},
	{"gateway.docker.internal", "Docker's alias for the host's gateway"},
	{"host.containers.internal", "Podman's alias for the host"},
	{"metadata.google.internal", "the Google Cloud metadata service"},
	{"instance-data.ec2.internal", "the AWS EC2 metadata service"},
}

// netAliasOverlap reports the alias row an entry reaches: an exact entry
// that is the alias or below it, or a wildcard whose names could include
// the alias or a name below it (its suffix is the alias, below it, or above
// it).
func netAliasOverlap(entry string) (netAlias, bool) {
	name, wildcard := strings.CutPrefix(entry, "*.")
	for _, a := range netAliases {
		if name == a.name || strings.HasSuffix(name, "."+a.name) {
			return a, true
		}
		if wildcard && strings.HasSuffix(a.name, "."+name) {
			return a, true
		}
	}
	return netAlias{}, false
}

// NetAliasNames returns the host-alias floor's names, in table order (the
// driver's tests and the live script read them).
func NetAliasNames() []string {
	out := make([]string, len(netAliases))
	for i, a := range netAliases {
		out[i] = a.name
	}
	return out
}

// netProviderOverlap reports the provider an entry reaches: an exact entry
// that is a provider host or below one (sandboxnet blocks a provider's
// subdomains too) or in a provider family, or a wildcard whose names
// include a provider host, a name below one or a family member. The rule
// is sandboxvocab.ProviderOverlap, the closed list's one owner (lane FU8,
// ledger OSH-43: "*.amazonaws.com" covers Bedrock and is refused).
func netProviderOverlap(entry string, providers []string) (string, bool) {
	return vocab.ProviderOverlap(entry, providers)
}

// netFloorV4 are the IPv4 ranges no rule ever allows: this network,
// loopback, link-local (with the metadata address), multicast and the
// limited broadcast (sandboxnet's floor rows). The private ranges come from
// internal/sandboxcidr, their one owner.
var netFloorV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// netPublicV6 is the IPv6 space a rule allows: global unicast. Loopback,
// unspecified, IPv4-mapped and IPv4-compatible forms, the NAT64 prefix,
// link-local, site-local, unique local and multicast all lie outside it.
var netPublicV6 = netip.MustParsePrefix("2000::/3")

// NetAllowedIPs returns the allowed_ips list every endpoint carries: the
// public IPv4 space (all of it less the floor and the private ranges), the
// IPv6 global unicast space, and the operator's private allow-list, each
// less the host's own addresses, sorted IPv4 first. It refuses an
// allow-list entry sandboxcidr does not accept (ErrNetCIDR).
func NetAllowedIPs(allowCIDRs []string, hostAddrs []netip.Addr) ([]netip.Prefix, error) {
	allow, err := sandboxcidr.ParseAllowCIDRs(allowCIDRs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNetCIDR, err)
	}
	exclude := append([]netip.Prefix(nil), netFloorV4...)
	for _, r := range sandboxcidr.PrivateRanges() {
		for _, p := range r.Prefixes {
			if p.Addr().Is4() {
				exclude = append(exclude, p)
			}
		}
	}
	out := subtractAll([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, exclude)
	out = append(out, netPublicV6)
	out = append(out, allow...)
	var hosts []netip.Prefix
	for _, a := range hostAddrs {
		a = a.Unmap().WithZone("")
		if a.IsValid() {
			hosts = append(hosts, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	out = subtractAll(out, hosts)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	return out, nil
}

// NetSubtractBlocked removes the blocked ranges from an allowed set, last
// (the org-hosted row's blocked_cidrs, lane G4). Each entry must be a
// canonical prefix; an empty list changes nothing.
func NetSubtractBlocked(allowed []netip.Prefix, blocked []string) ([]netip.Prefix, error) {
	if len(blocked) == 0 {
		return allowed, nil
	}
	var minus []netip.Prefix
	for _, b := range blocked {
		p, err := netip.ParsePrefix(strings.TrimSpace(b))
		if err != nil || p.Masked() != p {
			return nil, fmt.Errorf("%w: blocked range %q is not a canonical CIDR", ErrNetCIDR, b)
		}
		minus = append(minus, p)
	}
	return subtractAll(allowed, minus), nil
}

// subtractAll removes every prefix of minus from every prefix of from.
func subtractAll(from, minus []netip.Prefix) []netip.Prefix {
	out := from
	for _, m := range minus {
		var next []netip.Prefix
		for _, p := range out {
			next = append(next, subtract(p, m)...)
		}
		out = next
	}
	return out
}

// subtract returns p less q as a set of prefixes (p itself when they do
// not overlap, nothing when q covers p, else the two halves of p each less
// q).
func subtract(p, q netip.Prefix) []netip.Prefix {
	if p.Addr().Is4() != q.Addr().Is4() || !p.Overlaps(q) {
		return []netip.Prefix{p}
	}
	if q.Bits() <= p.Bits() {
		return nil
	}
	lo, hi := halves(p)
	return append(subtract(lo, q), subtract(hi, q)...)
}

// halves splits p into its two prefixes one bit longer.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	b := p.Addr().AsSlice()
	idx := (bits - 1) / 8
	b[idx] |= 0x80 >> ((bits - 1) % 8)
	a, _ := netip.AddrFromSlice(b)
	return lo, netip.PrefixFrom(a, bits)
}

// renderNetwork writes the network_policies section of rules ("" when
// there is none: no key at all, so all egress is denied).
func renderNetwork(rules []NetRule) string {
	if len(rules) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("network_policies:\n")
	for _, r := range rules {
		b.WriteString("  " + quote(r.Key) + ":\n")
		b.WriteString("    name: " + quote(r.Name) + "\n")
		if len(r.Endpoints) == 0 {
			b.WriteString("    endpoints: []\n")
		} else {
			b.WriteString("    endpoints:\n")
		}
		for _, e := range r.Endpoints {
			b.WriteString("      - host: " + quote(e.Host) + "\n")
			ports := make([]string, len(e.Ports))
			for i, p := range e.Ports {
				ports[i] = fmt.Sprint(p)
			}
			b.WriteString("        ports: [" + strings.Join(ports, ", ") + "]\n")
			b.WriteString("        enforcement: " + quote(netEnforcement) + "\n")
			b.WriteString("        allowed_ips:\n")
			for _, ip := range e.AllowedIPs {
				b.WriteString("          - " + quote(ip.String()) + "\n")
			}
		}
		b.WriteString("    binaries:\n")
		for _, bin := range r.Binaries {
			b.WriteString("      - path: " + quote(bin) + "\n")
		}
	}
	return b.String()
}
