package connectflow

import (
	"net/netip"
)

// IPv4PrefixBits and IPv6PrefixBits are how much of an address is kept: the
// network a request came from, never the address itself.
const (
	IPv4PrefixBits = 24
	IPv6PrefixBits = 48
)

// NetworkPrefix masks a textual client address to its approximate network
// ("203.0.113.0/24", "2001:db8:1::/48"). It returns "" for anything that is
// not one address.
func NetworkPrefix(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	bits := IPv6PrefixBits
	if addr.Is4() {
		bits = IPv4PrefixBits
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// SameNetwork reports whether the browser at browserIP is on the network a
// request was made from (both masked the same way). An unknown side is never
// the same network.
func SameNetwork(requestNetwork, browserIP string) bool {
	if requestNetwork == "" {
		return false
	}
	return NetworkPrefix(browserIP) == requestNetwork
}
