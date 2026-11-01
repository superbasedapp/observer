// Package secscan is the security pillar's driver contract (security
// pillar plan docs/plans/security-pillar-plan-2026-10-19.md section 4.4):
// the Driver interface, its registry data row, the target and budget a run
// gets, and the result and coverage it returns.
//
// It is pure: no database, HTTP, fsnotify or exec. A driver wraps one
// detection engine and never decides an outcome; Guard decides. Dispatch
// is on the driver's Kind and capability columns, never on the engine's
// name (CLAUDE.md module rule 3). External engines run through the shared
// hardened runner internal/extrun (roadmap F0-2); the exec or link side of
// each driver lives in cmd/observer behind its own omit tag.
//
// The package belongs to the `security` module root and is compiled out
// with sbo_omit_security.
package secscan
