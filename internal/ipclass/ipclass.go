package ipclass

import (
	"net"
	"strconv"
	"strings"
)

// Class is the coarse classification of one IP address: the dial-policy
// bucket internal/netpolicy's DialPolicy reaches for. Its values and String
// forms are re-exported unchanged by internal/netpolicy, so a change here is
// a change there.
type Class int

const (
	// ClassForbidden is never dialable under any policy: unspecified,
	// 0.0.0.0/8, link-local unicast (169.254.0.0/16 cloud metadata, fe80::/10),
	// every multicast scope and the deprecated IPv4-compatible ::/96 form.
	ClassForbidden Class = iota
	// ClassLoopback is 127.0.0.0/8 / ::1.
	ClassLoopback
	// ClassPrivate is RFC 1918, RFC 6598 CGNAT shared space and IPv6 ULA
	// (fc00::/7).
	ClassPrivate
	// ClassPublic is everything else - the only class a public-internet
	// upstream ever needs.
	ClassPublic
)

// String renders the class for error text. The strings are load-bearing:
// internal/netpolicy's dial-refusal messages embed them.
func (c Class) String() string {
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

// Kind is the FINER classification the developer-side guard's network rules
// need: it separates the single coarse ClassForbidden/ClassPrivate buckets
// into the specific ranges a verdict names (a metadata endpoint vs a plain
// link-local address vs RFC 1918 vs CGNAT vs ULA).
type Kind int

const (
	// KindPublic is a routable public-internet address.
	KindPublic Kind = iota
	// KindMetadata is a cloud instance-metadata endpoint (see
	// metadataAddresses): any encoding resolves here before the broader
	// range that contains it.
	KindMetadata
	// KindLinkLocal is link-local unicast (169.254.0.0/16, fe80::/10) that
	// is not a metadata address.
	KindLinkLocal
	// KindLoopback is 127.0.0.0/8 / ::1.
	KindLoopback
	// KindUnspecified is 0.0.0.0 / :: and the rest of 0.0.0.0/8 ("this
	// network"), plus the deprecated IPv4-compatible ::/96 form.
	KindUnspecified
	// KindPrivate is RFC 1918 (10/8, 172.16/12, 192.168/16).
	KindPrivate
	// KindCGNAT is RFC 6598 shared address space (100.64/10) minus the
	// metadata address it contains.
	KindCGNAT
	// KindULA is IPv6 unique-local (fc00::/7) that is not a metadata address.
	KindULA
	// KindMulticast is any multicast scope.
	KindMulticast
)

// String renders a Kind for verdict detail text.
func (k Kind) String() string {
	switch k {
	case KindMetadata:
		return "cloud-metadata"
	case KindLinkLocal:
		return "link-local"
	case KindLoopback:
		return "loopback"
	case KindUnspecified:
		return "unspecified"
	case KindPrivate:
		return "private-network"
	case KindCGNAT:
		return "carrier-NAT"
	case KindULA:
		return "unique-local"
	case KindMulticast:
		return "multicast"
	default:
		return "public"
	}
}

// Private reports whether the Kind is one R-175 treats as a non-public
// internal address: private, link-local, CGNAT or ULA. Loopback, unspecified
// and metadata are deliberately NOT here — loopback and unspecified are
// excluded by R-175 and metadata is R-174's.
func (k Kind) Private() bool {
	switch k {
	case KindPrivate, KindLinkLocal, KindCGNAT, KindULA:
		return true
	default:
		return false
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

// metadataAddresses is the closed set of cloud instance-metadata endpoints,
// in both IPv4 and IPv6 forms:
//
//   - 169.254.169.254 - AWS / GCP / Azure / OpenStack link-local metadata.
//   - 169.254.170.2, 169.254.170.23 - AWS ECS task-metadata / credential
//     relays.
//   - 100.100.100.200 - Alibaba Cloud metadata (inside CGNAT space).
//   - fd00:ec2::254, fd00:ec2::23 - AWS IMDS over IPv6 (inside ULA space).
//
// Table-driven: a new provider endpoint is one more row. Each is a metadata
// endpoint before it is anything else, so Detail tests this set first.
var metadataAddresses = func() []net.IP {
	raw := []string{
		"169.254.169.254", "169.254.170.2", "169.254.170.23",
		"100.100.100.200", "fd00:ec2::254", "fd00:ec2::23",
	}
	out := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		out = append(out, net.ParseIP(s))
	}
	return out
}()

// isMetadata reports whether ip (already To4-normalized by the caller) is one
// of the metadata endpoints, in either IPv4 or IPv6 form.
func isMetadata(ip net.IP) bool {
	for _, m := range metadataAddresses {
		if m.Equal(ip) {
			return true
		}
	}
	return false
}

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

// isULA reports whether ip is IPv6 unique-local (fc00::/7).
func isULA(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

// Classify buckets one address into the coarse Class. It is byte-equivalent
// to the classification internal/netpolicy shipped: IPv4-mapped IPv6
// (::ffff:10.0.0.1) is normalized through To4 FIRST so the hand-written
// 0.0.0.0/8 rule (which indexes ip[0]) reads the same address the stdlib
// predicates do. The other IPv4-in-IPv6 forms are handled after the
// unspecified/loopback rules so `::` and `::1` keep their own verdicts:
// IPv4-compatible ::/96 is forbidden outright; NAT64 and 6to4 are unwrapped
// and classified as the IPv4 they carry.
func Classify(ip net.IP) Class {
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
			return Classify(v4)
		}
		return ClassPublic
	}
}

// Detail buckets one address into the finer Kind the guard's network rules
// need. It unwraps the same IPv4-in-IPv6 forms Classify does and tests the
// metadata set FIRST, so a metadata endpoint that lives inside link-local,
// CGNAT or ULA space (169.254.169.254, 100.100.100.200, fd00:ec2::254) is
// named metadata rather than its containing range.
func Detail(ip net.IP) Kind {
	if ip == nil {
		return KindUnspecified
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if isMetadata(ip) {
		return KindMetadata
	}
	switch {
	case ip.IsUnspecified():
		return KindUnspecified
	case ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return KindMulticast
	case ip.IsLinkLocalUnicast(): // 169.254/16 + fe80::/10
		return KindLinkLocal
	case ip.IsLoopback():
		return KindLoopback
	case len(ip) == net.IPv4len && ip[0] == 0:
		// 0.0.0.0/8 "this network" - IsUnspecified covers only 0.0.0.0.
		return KindUnspecified
	case len(ip) == net.IPv6len && ipv4CompatPrefix.Contains(ip):
		return KindUnspecified
	case cgnatBlock.Contains(ip):
		return KindCGNAT
	case isULA(ip):
		return KindULA
	case ip.IsPrivate(): // RFC 1918 (ULA already handled above)
		return KindPrivate
	default:
		if v4, ok := embeddedIPv4(ip); ok {
			return Detail(v4)
		}
		return KindPublic
	}
}

// IsLoopbackHost reports whether a URL host is a loopback LITERAL or the
// conventional name "localhost". Nothing else counts: a name that merely
// happens to resolve to 127.0.0.1 does not relax any rule, and the dialer
// still verifies the resolved address for every host.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ParseHostIP parses the loose IP spellings curl, wget and browsers accept
// and returns the address they would dial. It accepts, in addition to the
// canonical dotted-quad and IPv6 forms net.ParseIP handles: a bracketed IPv6
// literal ([::1]); a trailing zone id (fe80::1%eth0), stripped; and the
// inet_aton short / alternate-radix IPv4 forms - a single 32-bit value
// (decimal 2852039166, hex 0xa9fea9fe), the 2-part a.b and 3-part a.b.c
// forms, and octal (leading 0) or hex (leading 0x) components
// (0251.0376.0251.0376). ok is false when s is not an address at all (a host
// name), so a caller can treat "not an IP" and "an IP" apart.
func ParseHostIP(s string) (net.IP, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i] // zone id
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip, true
	}
	return parseInetAton(s)
}

// parseInetAton parses the loose IPv4 forms net.ParseIP rejects (leading
// zeros, hex, and the 1-, 2- and 3-part short forms), by the same rules the C
// inet_aton the tools wrap uses.
func parseInetAton(s string) (net.IP, bool) {
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := parseCInt(p)
		if !ok {
			return nil, false
		}
		vals[i] = v
	}
	var addr uint32
	switch len(parts) {
	case 1:
		if vals[0] > 0xffffffff {
			return nil, false
		}
		addr = uint32(vals[0])
	case 2:
		// a.b: a is the high byte, b fills the low 24 bits.
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return nil, false
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])
	case 3:
		// a.b.c: a, b are the high two bytes, c fills the low 16 bits.
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return nil, false
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])
	case 4:
		for _, v := range vals {
			if v > 0xff {
				return nil, false
			}
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])<<8 | uint32(vals[3])
	}
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)), true
}

// parseCInt parses one address component as C would: a 0x/0X prefix is hex, a
// leading 0 is octal, anything else is decimal. An empty or malformed
// component is not a number.
func parseCInt(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(p) >= 2 && (p[0:2] == "0x" || p[0:2] == "0X"):
		base, p = 16, p[2:]
		if p == "" {
			return 0, false
		}
	case len(p) >= 2 && p[0] == '0':
		base, p = 8, p[1:]
	}
	v, err := strconv.ParseUint(p, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
