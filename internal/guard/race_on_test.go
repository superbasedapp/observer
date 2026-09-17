//go:build race

package guard

// raceLatencyMultiplier widens TestScanProxyRequest_LatencyRegression's
// (and TestExtractLatestUserPromptText_LatencyRegression's) CI
// regression ceiling under the race detector (FIX-3, round-2
// re-review) — the mirror of internal/scrub's own race_on_test.go,
// same rationale: CI runs `go test -race ./...`, and the plain
// ceiling's ~7x headroom does not comfortably absorb the race
// detector's own per-access instrumentation cost on this hot path.
//
// Widened 6 -> 12 (2026-09-17): TestExtractLatestUserPromptText_LatencyRegression
// still flaked on the 2-core GitHub ubuntu runner at 6x (264.857663ms/op
// against a 180ms=5ms*6*6 ceiling; also flaked 2026-09-10) — a 2-core
// box gives the race detector's happens-before bookkeeping less
// parallelism to hide behind than the CPU count this multiplier was
// originally tuned against, and shares those 2 cores with the rest of
// the CI job. 12x (360ms) keeps the previously-observed failing sample
// comfortably under ceiling with margin left for run-to-run noise, and
// only loosens both regression tests' race-build ceilings (this one and
// TestScanProxyRequest_LatencyRegression's, 50ms -> 600ms); the
// non-race ceiling (race_off_test.go) is untouched.
const raceLatencyMultiplier = 12

// raceDetectorOn reports whether this test binary was built with -race.
// The two wall-clock latency regressions skip under it: the detector
// inflates CPU-bound work 2-10x and the shared 2-core CI runner adds its
// own noise (431 ms measured against a 360 ms ceiling on 2026-09-16 even at
// a 12x multiplier), so the ceiling is gated by ci.yml's static `go` job,
// which runs `-run LatencyRegression` WITHOUT -race.
const raceDetectorOn = true
