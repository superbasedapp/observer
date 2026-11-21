package secdast

import (
	"net/netip"
	"strings"
)

// The loopback rule, owned here rather than borrowed from internal/netpolicy
// (which belongs to the agentaccess.relay component, so security.dast may not
// import it, tests/invariant/components_fence_test.go). It is the stricter of
// the two: netpolicy unwraps NAT64 (64:ff9b::/96) and 6to4 (2002::/16)
// addresses and classifies the IPv4 they embed, so 64:ff9b::7f00:1 reads as
// loopback there; here it does not, because a dial to it goes through a
// translator, not to this machine. Loopback is 127.0.0.0/8 and ::1 (an
// IPv4-mapped ::ffff:127.x.y.z is unmapped first), with no zone.

// IsLoopbackHost reports whether a URL host is "localhost" or a loopback IP
// literal. A name that merely resolves to 127.0.0.1 does not count; the lane
// checks every resolved and dialed address again (IsLoopbackAddr).
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && IsLoopbackAddr(a)
}

// IsLoopbackAddr reports whether a is a loopback address: 127.0.0.0/8 or ::1
// (an IPv4-mapped form unmapped first), without a zone.
func IsLoopbackAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.Zone() == "" && a.IsLoopback()
}
