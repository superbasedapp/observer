//go:build race

package guard

// raceLatencyMultiplier widens TestScanProxyRequest_LatencyRegression's
// CI regression ceiling under the race detector (FIX-3, round-2
// re-review) — the mirror of internal/scrub's own race_on_test.go,
// same rationale: CI runs `go test -race ./...`, and the plain
// ceiling's ~7x headroom does not comfortably absorb the race
// detector's own per-access instrumentation cost on this hot path.
const raceLatencyMultiplier = 6
