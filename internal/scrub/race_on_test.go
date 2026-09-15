//go:build race

package scrub

// raceLatencyMultiplier widens TestDetectPII_LatencyRegression's CI
// regression ceiling under the race detector (FIX-3, round-2
// re-review). `make test`/CI runs `go test -race ./...`, and the race
// detector's per-memory-access instrumentation can cost several times
// on a PII-suppression-heavy hot path — but the plain (non-race)
// ceiling (piiLatencyTestCeiling, 50ms against a ~7ms measured
// baseline) only carries ~7x headroom, not enough margin once race
// overhead is added on top. Without this the test was a source of CI
// flakes on a slower/shared race-instrumented runner, not a real
// regression signal. This build tag is the sentinel FIX-3 asked for:
// it identifies the SAME regression class (the O(n·m) PII-suppression
// blowup B4 originally fixed) rather than skipping the assertion
// outright, so a genuine order-of-magnitude regression is still caught
// under -race, just with realistic headroom for the detector's own
// overhead.
const raceLatencyMultiplier = 6
