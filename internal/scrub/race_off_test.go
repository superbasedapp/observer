//go:build !race

package scrub

// raceLatencyMultiplier is the FIX-3 (round-2 re-review) build-tag
// sentinel: the ordinary (non-race) build applies no extra headroom to
// the wall-clock latency regression tests — see race_on_test.go for
// the race-build counterpart and the rationale.
const raceLatencyMultiplier = 1
