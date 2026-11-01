package orgcontract

import "strconv"

// seclookup_pace.go names the relay's per-node budget header (SECP-26, lane
// LEFT-SHARED): the org relay sends its per-node lookup rate on every answer
// (200 and 429) so a managed node paces its dependency scan to half of the
// rate in force rather than half of the default; an org that lowered its
// rate no longer drives the scan into the 429 path. Optional both ways: an
// older server sends none (the node keeps the default) and an older node
// ignores it.
const SecurityLookupPerMinuteHeader = "X-Observer-Lookup-Per-Minute"

// MaxSecurityLookupPerMinute bounds a header value a node accepts.
const MaxSecurityLookupPerMinute = 6000

// ParseSecurityLookupPerMinute reads the header: a positive whole number up
// to MaxSecurityLookupPerMinute, else 0 (not sent, or not usable).
func ParseSecurityLookupPerMinute(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > MaxSecurityLookupPerMinute {
		return 0
	}
	return n
}
