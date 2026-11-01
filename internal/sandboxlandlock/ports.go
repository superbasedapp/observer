package sandboxlandlock

import (
	"fmt"
	"sort"
)

// ports.go is the TCP allow-list (section 4.1, Opus M10): Landlock's network
// rules are ALLOW-lists of TCP ports, so "deny Observer's ports" is "allow
// connect and bind on every TCP port except Observer's own". The ports are
// ports, not addresses: a denied port is denied on every host, and every
// other service on the host's loopback stays reachable (disclosed).

// PortRange is an inclusive range of allowed TCP ports.
type PortRange struct {
	Low, High uint16
}

// AllowedPorts returns the ranges covering 1 to 65535 minus denied (port 0
// is never a rule). An out-of-range or zero denied entry is refused.
func AllowedPorts(denied []int) ([]PortRange, error) {
	set := map[int]bool{}
	for _, p := range denied {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("sandboxlandlock: port %d is not 1 to 65535", p)
		}
		set[p] = true
	}
	ds := make([]int, 0, len(set))
	for p := range set {
		ds = append(ds, p)
	}
	sort.Ints(ds)
	var out []PortRange
	next := 1
	for _, p := range ds {
		if p > next {
			out = append(out, PortRange{Low: uint16(next), High: uint16(p - 1)}) //nolint:gosec // G115: 1..65535 checked above
		}
		next = p + 1
	}
	if next <= 65535 {
		out = append(out, PortRange{Low: uint16(next), High: 65535}) //nolint:gosec // G115: 1..65535
	}
	return out, nil
}

// PortCount is the number of ports the ranges allow.
func PortCount(rs []PortRange) int {
	n := 0
	for _, r := range rs {
		n += int(r.High) - int(r.Low) + 1
	}
	return n
}

// Allows reports whether the ranges allow port.
func Allows(rs []PortRange, port int) bool {
	for _, r := range rs {
		if port >= int(r.Low) && port <= int(r.High) {
			return true
		}
	}
	return false
}
