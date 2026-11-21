//go:build !race

package main

// raceDetectorOn reports whether this test binary was built with -race; see
// race_on_test.go.
const raceDetectorOn = false
