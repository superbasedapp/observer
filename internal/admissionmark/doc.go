// Package admissionmark folds a trace's admission verdicts into the one
// decision a trace list row shows (Plane A fix lane FX-C, B-1 / U-20): an
// admission-denied trace used to read "ok" with no marker, because neither
// the node's /api/obs/traces rows nor the org's ObsTraceListRow carried the
// decision.
//
// It is pure (no SQL, HTTP or fsnotify) and sits outside internal/obs so both
// the node obs store and the org rollup can share the one rank table without
// crossing the obs reverse-import boundary (tests/invariant/obs_boundary_test.go).
// Content-free: a Mark carries only enums and the criterion id, never the
// verdict prose.
package admissionmark
