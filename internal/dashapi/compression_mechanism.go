package dashapi

import (
	"sort"
)

// lossyEvictionMechanisms is the set of compression-event mechanisms
// that remove content outright rather than compressing it. Membership
// is a capability (compressed_bytes == 0 by construction), not a
// display heuristic - extend this set if a new evicting mechanism is
// added upstream.
var LossyEvictionMechanisms = map[string]bool{
	"drop": true,
}

// LossyEvictionMechanismList returns the lossy-eviction mechanisms as a
// deterministically-ordered slice so SQL callers can build an IN(...)
// set from the SAME classifier table (lossyEvictionMechanisms) that
// mechanismIsLossy consults. Keeping the SQL set derived from this one
// owner means adding a new evicting mechanism upstream updates every
// surface - the per-event display AND the byte-subtraction paths -
// from a single edit.
func LossyEvictionMechanismList() []string {
	out := make([]string, 0, len(LossyEvictionMechanisms))
	for m := range LossyEvictionMechanisms {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
