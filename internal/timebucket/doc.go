// Package timebucket is the ONE owner of chart time granularity: the
// vocabulary (5m / 1h / 1d / 1w), the Auto rule that picks a granularity
// from a window span, the 2000-point cap that refuses a too-fine choice
// (typed error, never a silent coarsening), viewer-zone bucket flooring
// (IANA zone, DST-correct; the zone database is embedded, tzdata.go), the
// zero-fill grid, and the exact UTC-slot SQL grouping (Spec.Slot: SQLite
// and portable SQLite/PostgreSQL renderings) whose slots Go re-floors into
// buckets, plus per-surface Auto caps (Request.AutoCaps).
//
// Plan of record: docs/plans/chart-time-granularity-plan-2026-09-29.md.
//
// The TypeScript mirror lives in shared/lib/granularity.ts; both sides are
// pinned by ONE fixture, shared/lib/granularity.fixture.json, which the Go
// tests and the web tests read.
//
// Pure: no database/sql, net/http or fsnotify (pinned by imports_test.go).
// Callers resolve an HTTP request into a Request and get a Spec back; the
// Spec carries everything a handler needs (the granularity, the viewer
// zone, the resolved window, Key/Grid/Meta helpers).
package timebucket
