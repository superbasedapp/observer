//go:build !race

package routing

// decideLatencyRaceMultiplier is the F3 build-tag sentinel: an ordinary
// (non-race) build applies no extra headroom to the §R25 wall-clock p99
// budget — see race_on_test.go for the race-build counterpart and the
// rationale.
const decideLatencyRaceMultiplier = 1
