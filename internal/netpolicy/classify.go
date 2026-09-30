package netpolicy

import "net"

// NetworkClass is the resolved classification of one dialed IP address.
type NetworkClass int

const (
	// ClassForbidden is never dialable under any policy: unspecified,
	// 0.0.0.0/8, link-local unicast (169.254.0.0/16 cloud metadata, fe80::/10),
	// every multicast scope and the deprecated IPv4-compatible ::/96 form.
	ClassForbidden NetworkClass = iota
	// ClassLoopback is 127.0.0.0/8 / ::1.
	ClassLoopback
	// ClassPrivate is RFC 1918, RFC 6598 CGNAT shared space and IPv6 ULA
	// (fc00::/7).
	ClassPrivate
	// ClassPublic is everything else - the only class a public-internet
	// upstream ever needs.
	ClassPublic
)

// String renders the class for error text.
func (c NetworkClass) String() string {
	switch c {
	case ClassLoopback:
		return "loopback"
	case ClassPrivate:
		return "private-network"
	case ClassPublic:
		return "public"
	default:
		return "link-local/metadata/multicast"
	}
}

// cgnatBlock is RFC 6598 shared address space: carrier-internal, treated as
// private (reachable only with the explicit unlock).
var cgnatBlock = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// nat64Prefix (RFC 6052 64:ff9b::/96) and sixToFourPrefix (RFC 3056 2002::/16)
// EMBED an IPv4 address that none of the stdlib IPv4 predicates look at;
// ipv4CompatPrefix is the deprecated RFC 4291 section 2.5.5.1 ::/96 form.
var (
	nat64Prefix      = &net.IPNet{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)}
	sixToFourPrefix  = &net.IPNet{IP: net.ParseIP("2002::"), Mask: net.CIDRMask(16, 128)}
	ipv4CompatPrefix = &net.IPNet{IP: net.ParseIP("::"), Mask: net.CIDRMask(96, 128)}
)

// embeddedIPv4 extracts the IPv4 address a transition-mechanism IPv6 address
// carries (NAT64 low 32 bits; 6to4 bytes 2..5). ok is false for every other
// form.
func embeddedIPv4(ip net.IP) (net.IP, bool) {
	if len(ip) != net.IPv6len {
		return nil, false
	}
	switch {
	case nat64Prefix.Contains(ip):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4(), true
	case sixToFourPrefix.Contains(ip):
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4(), true
	default:
		return nil, false
	}
}

// ClassifyIP buckets one address. IPv4-mapped IPv6 (::ffff:10.0.0.1) is
// normalized through To4 FIRST so the hand-written 0.0.0.0/8 rule (which
// indexes ip[0]) reads the same address the stdlib predicates do. The other
// IPv4-in-IPv6 forms are handled after the unspecified/loopback rules so `::`
// and `::1` keep their own verdicts: IPv4-compatible ::/96 is forbidden
// outright; NAT64 and 6to4 are unwrapped and classified as the IPv4 they carry.
func ClassifyIP(ip net.IP) NetworkClass {
	if ip == nil {
		return ClassForbidden
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified(),
		ip.IsLinkLocalUnicast(), // 169.254/16 + fe80::/10 - cloud metadata
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return ClassForbidden
	case ip.IsLoopback():
		return ClassLoopback
	case len(ip) == net.IPv4len && ip[0] == 0:
		// 0.0.0.0/8 "this network" - IsUnspecified covers only 0.0.0.0.
		return ClassForbidden
	case len(ip) == net.IPv6len && ipv4CompatPrefix.Contains(ip):
		return ClassForbidden
	case ip.IsPrivate(), cgnatBlock.Contains(ip):
		return ClassPrivate
	default:
		if v4, ok := embeddedIPv4(ip); ok {
			return ClassifyIP(v4)
		}
		return ClassPublic
	}
}

// IsLoopbackHost reports whether a URL host is a loopback LITERAL or the
// conventional name "localhost". Nothing else counts: a name that merely
// happens to resolve to 127.0.0.1 does not relax any rule, and the dialer
// still verifies the resolved address for every host.
func IsLoopbackHost(host string) bool {
	h := trimLower(host)
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// trimLower lower-cases and trims without importing strings' whole surface
// into every caller's error path (kept local for clarity).
func trimLower(s string) string {
	b := []byte(s)
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t') {
		end--
	}
	out := make([]byte, 0, end-start)
	for _, c := range b[start:end] {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
