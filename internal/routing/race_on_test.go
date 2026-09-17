//go:build race

package routing

// decideLatencyRaceMultiplier widens TestDecideHotPathBudget's §R25 p99
// ceiling under the race detector (F3, codebase audit 2026-09-16).
// `make test` / the ci.yml `go test -race -timeout 40m ./...` gate runs
// the whole tree under -race on a 2-core shared runner, and the race
// detector's per-memory-access instrumentation costs several times on
// Decide's rule walk — while the plain ceiling (5 ms against a
// microsecond-scale baseline) carried no stated headroom at all and was
// observed failing at 6.18 ms under load.
//
// Same sentinel shape as internal/scrub/race_on_test.go: it keeps the
// SAME regression class under -race (an accidental I/O or quadratic
// blow-up on the hot path is still orders of magnitude away from the
// widened ceiling) rather than skipping the assertion outright.
const decideLatencyRaceMultiplier = 3
