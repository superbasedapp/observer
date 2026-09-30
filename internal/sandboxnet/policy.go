package sandboxnet

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Rule names used by DestinationAllowed. They appear in RefusedError.Rule and
// in the gateway's 403 body, so they are part of the operator-visible
// vocabulary and must stay stable.
const (
	RuleNil                     = "nil-address"
	RuleUnspecified             = "unspecified"
	RuleThisNetwork             = "this-network"
	RuleLoopback                = "loopback"
	RuleLinkLocalUnicast        = "link-local-unicast"
	RuleLinkLocalMulticast      = "link-local-multicast"
	RuleInterfaceLocalMulticast = "interface-local-multicast"
	RuleMulticast               = "multicast"
	RuleLimitedBroadcast        = "limited-broadcast"
	RuleIPv4Compatible          = "ipv4-compatible"
	RuleHostLocal               = "host-local-address"
	// RulePrivate refuses the RFC 1918 private IPv4 ranges (10/8,
	// 172.16/12, 192.168/16): the WSL2 NAT gateway (the Windows host and
	// every service it listens on), Docker bridge containers and LAN hosts
	// all live there.
	RulePrivate = "private-rfc1918"
	// RuleSharedAddress refuses the RFC 6598 shared address space
	// 100.64.0.0/10 (carrier-grade NAT, and the tailnet addresses of a
	// Tailscale network).
	RuleSharedAddress = "shared-address-cgnat"
	// RuleUniqueLocal refuses IPv6 unique local addresses fc00::/7.
	RuleUniqueLocal = "unique-local-ipv6"
	// RuleSiteLocal refuses the deprecated IPv6 site-local range fec0::/10.
	RuleSiteLocal = "site-local-ipv6"
)

// AllowCIDRsConfigKey is the operator-facing config key that allow-lists
// private destinations. It is named in every refusal a private-range rule
// produces, so an operator who hits one knows exactly what to change.
const AllowCIDRsConfigKey = "[terminal.sandbox].egress_allow_cidrs"

// RefusedError is returned by DestinationAllowed when a rule refuses an
// address. Rule is one of the Rule* constants.
type RefusedError struct {
	// IP is the refused address as given (before normalisation).
	IP net.IP
	// Rule names the policy row that refused IP.
	Rule string
	// AllowListable reports whether the refusing row can be lifted for a
	// destination by listing its CIDR under AllowCIDRsConfigKey.
	AllowListable bool
}

// Error implements error.
func (e *RefusedError) Error() string {
	msg := fmt.Sprintf("sandboxnet: destination %s refused by rule %s", e.IP, e.Rule)
	if e.AllowListable {
		msg += " (to allow it, add its CIDR to " + AllowCIDRsConfigKey + ")"
	}
	return msg
}

// policyRule is one row of the egress policy: a named predicate over a
// normalised address. allowListable rows (the private ranges) are skipped
// for a destination inside a Policy.Allow prefix; every other row always
// applies.
type policyRule struct {
	name          string
	allowListable bool
	match         func(ip net.IP, local []net.IP) bool
}

// nat64Prefix is the RFC 6052 well-known NAT64 prefix 64:ff9b::/96; an
// address inside it carries an IPv4 destination in its last four bytes.
var nat64Prefix = net.IP{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}

// privateRanges maps each allow-listable rule to the prefixes it refuses.
// It is the one owner of those ranges: the rule rows below and
// ParseAllowCIDRs both read it.
var privateRanges = []struct {
	rule     string
	prefixes []netip.Prefix
}{
	{RulePrivate, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}},
	{RuleSharedAddress, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}},
	{RuleUniqueLocal, []netip.Prefix{netip.MustParsePrefix("fc00::/7")}},
	{RuleSiteLocal, []netip.Prefix{netip.MustParsePrefix("fec0::/10")}},
}

// inRanges reports whether ip lies in any prefix of the named private rule.
func inRanges(rule string) func(ip net.IP, _ []net.IP) bool {
	return func(ip net.IP, _ []net.IP) bool {
		a, ok := toAddr(ip)
		if !ok {
			return false
		}
		for _, r := range privateRanges {
			if r.rule != rule {
				continue
			}
			for _, p := range r.prefixes {
				if p.Contains(a) {
					return true
				}
			}
		}
		return false
	}
}

// policyRules is walked top-down; the first matching row refuses. Order only
// matters for which name is reported (0.0.0.0 reports unspecified, not
// this-network; a host interface address in 192.168/16 reports
// host-local-address, which no allow-list can lift).
var policyRules = []policyRule{
	{name: RuleUnspecified, match: func(ip net.IP, _ []net.IP) bool { return ip.IsUnspecified() }},
	{name: RuleThisNetwork, match: func(ip net.IP, _ []net.IP) bool {
		v4 := ip.To4()
		return v4 != nil && v4[0] == 0
	}},
	{name: RuleLoopback, match: func(ip net.IP, _ []net.IP) bool { return ip.IsLoopback() }},
	{name: RuleLinkLocalUnicast, match: func(ip net.IP, _ []net.IP) bool { return ip.IsLinkLocalUnicast() }},
	{name: RuleLinkLocalMulticast, match: func(ip net.IP, _ []net.IP) bool { return ip.IsLinkLocalMulticast() }},
	{name: RuleInterfaceLocalMulticast, match: func(ip net.IP, _ []net.IP) bool { return ip.IsInterfaceLocalMulticast() }},
	{name: RuleMulticast, match: func(ip net.IP, _ []net.IP) bool { return ip.IsMulticast() }},
	{name: RuleLimitedBroadcast, match: func(ip net.IP, _ []net.IP) bool { return ip.Equal(net.IPv4bcast) }},
	{name: RuleIPv4Compatible, match: func(ip net.IP, _ []net.IP) bool {
		// Deprecated IPv4-compatible IPv6 (::a.b.c.d, RFC 4291 2.5.5.1). :: and
		// ::1 are caught above; nothing legitimate lives in the rest of ::/96.
		if ip.To4() != nil || len(ip) != net.IPv6len {
			return false
		}
		for _, b := range ip[:12] {
			if b != 0 {
				return false
			}
		}
		return true
	}},
	{name: RuleHostLocal, match: func(ip net.IP, local []net.IP) bool {
		for _, l := range local {
			if l != nil && normalize(l).Equal(ip) {
				return true
			}
		}
		return false
	}},
	{name: RulePrivate, allowListable: true, match: inRanges(RulePrivate)},
	{name: RuleSharedAddress, allowListable: true, match: inRanges(RuleSharedAddress)},
	{name: RuleUniqueLocal, allowListable: true, match: inRanges(RuleUniqueLocal)},
	{name: RuleSiteLocal, allowListable: true, match: inRanges(RuleSiteLocal)},
}

// normalize returns the IPv4 form of an IPv4-mapped (::ffff:a.b.c.d) or
// NAT64 well-known-prefix (64:ff9b::a.b.c.d) address so neither can bypass an
// IPv4 rule; any other address is returned unchanged.
func normalize(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if len(ip) == net.IPv6len && ip[:12].Equal(nat64Prefix) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	return ip
}

// toAddr converts a normalised net.IP to an unmapped netip.Addr.
func toAddr(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Policy is the egress policy with its one operator knob: Allow lists the
// private prefixes a sandboxed agent may reach (corporate registries or git
// servers on private addresses). Allow only ever lifts the allow-listable
// rows (private-rfc1918, shared-address-cgnat, unique-local-ipv6,
// site-local-ipv6); loopback, link-local (including cloud metadata),
// multicast, broadcast and the host's own interface addresses stay refused
// whatever it says. The zero Policy allows no private destination. Build
// Allow with ParseAllowCIDRs.
type Policy struct {
	Allow []netip.Prefix
}

// allowed reports whether a (normalised) ip lies inside an Allow prefix.
func (p Policy) allowed(ip net.IP) bool {
	if len(p.Allow) == 0 {
		return false
	}
	a, ok := toAddr(ip)
	if !ok {
		return false
	}
	for _, pre := range p.Allow {
		if pre.Contains(a) {
			return true
		}
	}
	return false
}

// Check is the PURE egress policy: it returns nil when ip may be dialled by
// the gateway, or a *RefusedError naming the rule that refused it.
//
// Refused: a nil ip; unspecified (0.0.0.0, ::); the IPv4 "this network"
// block 0.0.0.0/8; loopback (127/8, ::1); link-local unicast (169.254/16,
// including cloud metadata 169.254.169.254, and fe80::/10); link-local,
// interface-local and all other multicast; the IPv4 limited broadcast
// 255.255.255.255; deprecated IPv4-compatible IPv6 (::/96); any address
// equal to one in local (the host's own interface addresses); and, unless
// the address lies inside p.Allow, the RFC 1918 private ranges, the RFC 6598
// shared address space 100.64.0.0/10, IPv6 unique local fc00::/7 and the
// deprecated site-local fec0::/10. IPv4-mapped (::ffff:a.b.c.d) and NAT64
// (64:ff9b::a.b.c.d) addresses are normalised to IPv4 first so they cannot
// bypass an IPv4 rule.
func (p Policy) Check(ip net.IP, local []net.IP) error {
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return &RefusedError{IP: ip, Rule: RuleNil}
	}
	n := normalize(ip)
	for _, r := range policyRules {
		if !r.match(n, local) {
			continue
		}
		if r.allowListable && p.allowed(n) {
			continue
		}
		return &RefusedError{IP: ip, Rule: r.name, AllowListable: r.allowListable}
	}
	return nil
}

// DestinationAllowed is Policy{}.Check: the default policy with no
// allow-listed private prefix.
func DestinationAllowed(ip net.IP, local []net.IP) error {
	return Policy{}.Check(ip, local)
}

// ParseAllowCIDRs validates the operator's allow-list (AllowCIDRsConfigKey)
// and returns it as prefixes. It is the ONE owner of what an allow-list
// entry may be, shared by config validation, the daemon's runtime and the
// host-side helper. Each entry must be a canonical CIDR (no host bits set,
// IPv4 in dotted form rather than IPv4-mapped IPv6) lying entirely inside
// one of the ranges the allow-listable rules refuse: a public prefix would
// be a no-op (public addresses are already allowed) and a loopback,
// link-local or metadata prefix can never be allow-listed. An empty list is
// valid (the default).
func ParseAllowCIDRs(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("sandboxnet.ParseAllowCIDRs: %q is not a CIDR (for example 10.20.0.0/16): %w", raw, err)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("sandboxnet.ParseAllowCIDRs: %q is an IPv4-mapped IPv6 prefix; write the IPv4 form", raw)
		}
		if p.Addr().Zone() != "" {
			return nil, fmt.Errorf("sandboxnet.ParseAllowCIDRs: %q carries a zone", raw)
		}
		if m := p.Masked(); m != p {
			return nil, fmt.Errorf("sandboxnet.ParseAllowCIDRs: %q has host bits set; did you mean %s", raw, m)
		}
		if !insidePrivateRange(p) {
			return nil, fmt.Errorf("sandboxnet.ParseAllowCIDRs: %q is not inside a private range the egress gateway refuses (%s); public addresses are already allowed, and loopback, link-local and host addresses cannot be allow-listed", raw, privateRangeList())
		}
		out = append(out, p)
	}
	return out, nil
}

// insidePrivateRange reports whether p lies entirely inside one of the
// allow-listable ranges.
func insidePrivateRange(p netip.Prefix) bool {
	for _, r := range privateRanges {
		for _, rp := range r.prefixes {
			if rp.Addr().Is4() == p.Addr().Is4() && rp.Bits() <= p.Bits() && rp.Contains(p.Addr()) {
				return true
			}
		}
	}
	return false
}

// privateRangeList renders every allow-listable prefix for an error message.
func privateRangeList() string {
	var parts []string
	for _, r := range privateRanges {
		for _, p := range r.prefixes {
			parts = append(parts, p.String())
		}
	}
	return strings.Join(parts, ", ")
}
