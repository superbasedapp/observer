// Package policystate is the pure-logic collector for the Plane-A P0-6
// "effective policy state" reverse channel
// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §4.1). It turns a
// per-enforcement-point PointFacts snapshot into one frozen
// orgcontract.PolicyStateRow via the §3.2 ordered decision table, and
// assembles a full four-point snapshot from injected readers.
//
// Discipline (CLAUDE.md §1 / spec §24.1): NO SQL, NO HTTP, NO fsnotify. All
// I/O is injected at the boundary (the readers in cmd/observer/policystate_wire.go
// and the store seams); this package is table-driven pure logic, pinned free of
// forbidden imports by imports_test.go.
package policystate
