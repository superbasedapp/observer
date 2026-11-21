package cidrcanon

import "net/netip"

// Canonical is the one CIDR rule of the org-hosted OpenShell network lists
// (allow_cidrs, blocked_cidrs): s must be a masked prefix (no host bits
// set), in any spelling netip parses, and the answer is netip's canonical
// string (so "::ffff:0:0/96" answers "::ffff:0.0.0.0/96"). ok is false for
// anything else.
func Canonical(s string) (string, bool) {
	pre, err := netip.ParsePrefix(s)
	if err != nil || pre.Masked() != pre {
		return "", false
	}
	return pre.String(), true
}
