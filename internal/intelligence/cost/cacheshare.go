package cost

// CacheReadShare is the ONE formula for the cache read share of a token
// bundle, the fraction of input-side tokens served from prompt cache,
//
//	cache_read / (input + cache_read + cache_creation)
//
// Input is NET of cache reads (the TokenBundle contract) and CacheCreation
// is the total cache-write count (CacheCreation1h is a subset of it, so it
// is not added again). ok is false when the bundle has no input-side tokens:
// a rate over nothing is unknown, not zero. The share card (`observer
// report share`) and `observer chart cache-share` read it; the statusline's
// session share uses the same three columns. It is distinct from the
// dashboard Cache page's read/write ratio and from Analysis's Cache
// Efficacy (read / (read + write)).
func CacheReadShare(b TokenBundle) (share float64, ok bool) {
	denom := b.Input + b.CacheRead + b.CacheCreation
	if denom <= 0 || b.CacheRead < 0 {
		return 0, false
	}
	return float64(b.CacheRead) / float64(denom), true
}
