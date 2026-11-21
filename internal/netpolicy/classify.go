package netpolicy

import (
	"net"

	"github.com/marmutapp/superbased-observer/internal/ipclass"
)

// NetworkClass is the resolved classification of one dialed IP address. It is
// a re-export of ipclass.Class, the one owner of IP classification: the type,
// its four values and their String forms live in internal/ipclass now, so a
// change there is a change here and classification can never fork. Every
// existing importer (DialPolicy, the SSRF guards, the mcpgw egress proxy) is
// unaffected.
type NetworkClass = ipclass.Class

// The four address classes, re-exported from internal/ipclass unchanged.
const (
	// ClassForbidden is never dialable under any policy: unspecified,
	// 0.0.0.0/8, link-local unicast (169.254.0.0/16 cloud metadata, fe80::/10),
	// every multicast scope and the deprecated IPv4-compatible ::/96 form.
	ClassForbidden = ipclass.ClassForbidden
	// ClassLoopback is 127.0.0.0/8 / ::1.
	ClassLoopback = ipclass.ClassLoopback
	// ClassPrivate is RFC 1918, RFC 6598 CGNAT shared space and IPv6 ULA
	// (fc00::/7).
	ClassPrivate = ipclass.ClassPrivate
	// ClassPublic is everything else - the only class a public-internet
	// upstream ever needs.
	ClassPublic = ipclass.ClassPublic
)

// ClassifyIP buckets one address. It delegates to ipclass.Classify, which is
// byte-equivalent to the classification this package used to hold itself:
// IPv4-mapped IPv6 is normalized through To4 first, NAT64 and 6to4 are
// unwrapped to the IPv4 they carry, and the deprecated IPv4-compatible ::/96
// form is forbidden outright.
func ClassifyIP(ip net.IP) NetworkClass { return ipclass.Classify(ip) }

// IsLoopbackHost reports whether a URL host is a loopback LITERAL or the
// conventional name "localhost". It delegates to ipclass.IsLoopbackHost;
// nothing else counts, and the dialer still verifies the resolved address for
// every host.
func IsLoopbackHost(host string) bool { return ipclass.IsLoopbackHost(host) }
