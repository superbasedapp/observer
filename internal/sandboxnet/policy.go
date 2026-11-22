package sandboxnet

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/marmutapp/superbased-observer/internal/ipclass"
	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
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
	// RuleCloudMetadata refuses a cloud instance-metadata endpoint
	// (ipclass.MetadataAddresses) that no earlier row names: the ones
	// outside link-local space, 100.100.100.200 (Alibaba Cloud, inside
	// 100.64.0.0/10) and fd00:ec2::254 / fd00:ec2::23 (AWS over IPv6, inside
	// fc00::/7), in every encoding. No allow-list lifts it, and it is checked
	// before the allow-listable private rows, so an allow-listed prefix that
	// contains a metadata address allows the rest of the prefix only (the
	// address is carved out; the prefix is not rejected). The link-local
	// metadata addresses (169.254.169.254, ...) keep reporting
	// link-local-unicast.
	RuleCloudMetadata = "cloud-metadata"
	// The four allow-listable private-range rules are defined in
	// internal/sandboxcidr (the neutral owner of the ranges, shared with
	// config validation) and re-exported here.
	RulePrivate       = sandboxcidr.RulePrivate
	RuleSharedAddress = sandboxcidr.RuleSharedAddress
	RuleUniqueLocal   = sandboxcidr.RuleUniqueLocal
	RuleSiteLocal     = sandboxcidr.RuleSiteLocal
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
	switch {
	case e.AllowListable:
		msg += " (to allow it, add its CIDR to " + AllowCIDRsConfigKey + ")"
	case e.Rule == RuleCloudMetadata:
		msg += " (a cloud metadata endpoint is never allow-listed: a prefix in " + AllowCIDRsConfigKey +
			" that contains it allows the rest of the prefix, never this address)"
	}
	return msg
}

// addrClass is one destination as the policy rows read it: the address
// after ipclass.Unwrap (IPv4-mapped, NAT64 and 6to4 forms carry an IPv4
// address the rows judge) and its ipclass.Detail kind. ipclass is the one
// owner of the classification (SEC-02): before, this package carried its
// own classifier, which unwrapped IPv4-mapped and NAT64 but not 6to4, and had
// no metadata rule.
type addrClass struct {
	ip   net.IP
	kind ipclass.Kind
}

// policyRule is one row of the egress policy: a named predicate over a
// classified address. allowListable rows (the private ranges) are skipped
// for a destination inside a Policy.Allow prefix; every other row always
// applies.
type policyRule struct {
	name          string
	allowListable bool
	match         func(a addrClass, local []net.IP) bool
}

// isKind returns a row predicate for one ipclass Kind.
func isKind(k ipclass.Kind) func(addrClass, []net.IP) bool {
	return func(a addrClass, _ []net.IP) bool { return a.kind == k }
}

// inRanges reports whether an address lies in any prefix of the named
// sandboxcidr rule. It backs the one allow-listable row ipclass reads as
// public: the deprecated site-local fec0::/10.
func inRanges(rule string) func(addrClass, []net.IP) bool {
	return func(a addrClass, _ []net.IP) bool {
		addr, ok := toAddr(a.ip)
		if !ok {
			return false
		}
		for _, r := range sandboxcidr.PrivateRanges() {
			if r.Rule != rule {
				continue
			}
			for _, p := range r.Prefixes {
				if p.Contains(addr) {
					return true
				}
			}
		}
		return false
	}
}

// policyRules is walked top-down; the first matching row refuses. The rows
// read the ipclass.Detail kind and split it into this package's stable rule
// names. Order only matters for which name is reported (0.0.0.0 reports
// unspecified, not this-network; 169.254.169.254 reports link-local-unicast,
// not cloud-metadata; a host interface address in 192.168/16 reports
// host-local-address, which no allow-list can lift), except that
// cloud-metadata must precede the allow-listable rows: a metadata address
// lives inside CGNAT and ULA space. Two rows refine what ipclass reads as
// public: limited-broadcast and site-local-ipv6.
var policyRules = []policyRule{
	{name: RuleUnspecified, match: func(a addrClass, _ []net.IP) bool {
		return a.kind == ipclass.KindUnspecified && a.ip.IsUnspecified()
	}},
	{name: RuleThisNetwork, match: func(a addrClass, _ []net.IP) bool {
		return a.kind == ipclass.KindUnspecified && len(a.ip) == net.IPv4len
	}},
	{name: RuleLoopback, match: isKind(ipclass.KindLoopback)},
	{name: RuleLinkLocalUnicast, match: func(a addrClass, _ []net.IP) bool {
		return a.kind == ipclass.KindLinkLocal || (a.kind == ipclass.KindMetadata && a.ip.IsLinkLocalUnicast())
	}},
	{name: RuleLinkLocalMulticast, match: func(a addrClass, _ []net.IP) bool {
		return a.kind == ipclass.KindMulticast && a.ip.IsLinkLocalMulticast()
	}},
	{name: RuleInterfaceLocalMulticast, match: func(a addrClass, _ []net.IP) bool {
		return a.kind == ipclass.KindMulticast && a.ip.IsInterfaceLocalMulticast()
	}},
	{name: RuleMulticast, match: isKind(ipclass.KindMulticast)},
	{name: RuleLimitedBroadcast, match: func(a addrClass, _ []net.IP) bool { return a.ip.Equal(net.IPv4bcast) }},
	// Deprecated IPv4-compatible IPv6 (::a.b.c.d, RFC 4291 2.5.5.1): the
	// rest of ipclass's KindUnspecified once :: and 0.0.0.0/8 are named.
	{name: RuleIPv4Compatible, match: isKind(ipclass.KindUnspecified)},
	{name: RuleHostLocal, match: func(a addrClass, local []net.IP) bool {
		for _, l := range local {
			if l != nil && ipclass.Unwrap(l).Equal(a.ip) {
				return true
			}
		}
		return false
	}},
	{name: RuleCloudMetadata, match: isKind(ipclass.KindMetadata)},
	{name: RulePrivate, allowListable: true, match: isKind(ipclass.KindPrivate)},
	{name: RuleSharedAddress, allowListable: true, match: isKind(ipclass.KindCGNAT)},
	{name: RuleUniqueLocal, allowListable: true, match: isKind(ipclass.KindULA)},
	{name: RuleSiteLocal, allowListable: true, match: inRanges(RuleSiteLocal)},
}

// toAddr converts an unwrapped net.IP to an unmapped netip.Addr.
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
// site-local-ipv6); loopback, link-local, cloud metadata (also the
// endpoints inside CGNAT and ULA space), multicast, broadcast and the
// host's own interface addresses stay refused whatever it says. The zero
// Policy allows no private destination. Build Allow with ParseAllowCIDRs.
type Policy struct {
	Allow []netip.Prefix
}

// allowed reports whether an (unwrapped) ip lies inside an Allow prefix.
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
// equal to one in local (the host's own interface addresses); every other
// cloud metadata endpoint (100.100.100.200, fd00:ec2::254, fd00:ec2::23);
// and, unless the address lies inside p.Allow, the RFC 1918 private ranges,
// the RFC 6598 shared address space 100.64.0.0/10, IPv6 unique local
// fc00::/7 and the deprecated site-local fec0::/10. IPv4-mapped
// (::ffff:a.b.c.d), NAT64 (64:ff9b::a.b.c.d) and 6to4 (2002:aabb:ccdd::)
// addresses are unwrapped to the IPv4 they carry first (ipclass.Unwrap) so
// they cannot bypass an IPv4 rule; the classification is ipclass.Detail's.
func (p Policy) Check(ip net.IP, local []net.IP) error {
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return &RefusedError{IP: ip, Rule: RuleNil}
	}
	n := ipclass.Unwrap(ip)
	a := addrClass{ip: n, kind: ipclass.Detail(n)}
	for _, r := range policyRules {
		if !r.match(a, local) {
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
// and returns it as prefixes. The rules live in internal/sandboxcidr, the
// neutral owner shared with config validation (modular packaging phase PB);
// see sandboxcidr.ParseAllowCIDRs.
func ParseAllowCIDRs(entries []string) ([]netip.Prefix, error) {
	return sandboxcidr.ParseAllowCIDRs(entries)
}
