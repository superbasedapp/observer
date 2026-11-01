// Package seccifetch is the CI fetch job's client for org.security.ci
// (security plan 7.9 F2 and 7.10, lane SEC-F2B): with the CI credential it
// fetches the org's signed CI policy, asks for the change records of a
// pull request's commits with a bounded wait (backoff, then the commits
// read as unknown_provenance), and downloads a pinned CI driver from the
// org's security mirror, refusing bytes whose SHA-256 is not the pin.
//
// It verifies no org signature: the verdict job does that against the org
// key the protected workflow pins (internal/secverify org mode). It never
// reads the repository under test. Egress lane security.ci.fetch
// (tests/invariant/egress_lanes_test.go): only `observer security verify
// fetch` reaches it, a command a CI job runs; no daemon path links it.
package seccifetch
