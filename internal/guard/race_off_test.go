//go:build !race

package guard

// raceLatencyMultiplier is the FIX-3 (round-2 re-review) build-tag
// sentinel: the ordinary (non-race) build applies no extra headroom to
// TestScanProxyRequest_LatencyRegression — see race_on_test.go for the
// race-build counterpart and the rationale.
const raceLatencyMultiplier = 1

// raceDetectorOn reports whether this test binary was built with -race.
// The two wall-clock latency regressions skip under it: the detector
// inflates CPU-bound work 2-10x and the shared 2-core CI runner adds its
// own noise (431 ms measured against a 360 ms ceiling on 2026-09-16 even at
// a 12x multiplier), so the ceiling is gated by ci.yml's static `go` job,
// which runs `-run LatencyRegression` WITHOUT -race.
const raceDetectorOn = false
