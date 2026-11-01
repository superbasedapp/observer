//go:build race

package secipc

// raceDetector reports a -race build: its instrumentation slows the round
// trip several times over, so a wall-clock budget is not measured there.
const raceDetector = true
