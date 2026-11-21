//go:build race

package main

// raceDetectorOn reports whether this test binary was built with -race (the
// mirror of internal/guard's race_on_test.go). A wall-clock latency test
// skips under it: the detector inflates the measured work and the shared
// 2-vCPU CI runner adds its own noise, so the bound is gated by ci.yml's
// no-race latency step instead (scripts/ci/latency-tests.txt).
const raceDetectorOn = true
