// Package latencygate gates the wall-clock latency tests: tests that fail
// when an operation takes longer than an absolute time bound (item 20 of
// the test-time plan).
//
// Such a bound holds on an idle host and flakes on a loaded one, and a CI
// test shard runs dozens of packages at once on two cores. So a latency test
// calls Gate first, and Gate:
//
//   - fails the test when it is not listed in scripts/ci/latency-tests.txt,
//     because ci.yml's no-race latency step runs exactly that list and an
//     unlisted latency test would run nowhere;
//   - skips it under -short (the lane tier of the test-time plan);
//   - skips it when SBO_SKIP_LATENCY_TESTS=1, which the CI test shards set.
//
// The latency step in ci.yml's go job runs the listed tests without -race
// and without that variable, on a runner that is otherwise idle. A test that
// also skips under the race detector (internal/guard) keeps that skip.
//
// TEST SUPPORT ONLY: no production command or package may import it
// (tests/invariant/vendormock_boundary_test.go).
package latencygate
