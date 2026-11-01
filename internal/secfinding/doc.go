// Package secfinding is the security pillar's normalized finding model
// (security pillar plan docs/plans/security-pillar-plan-2026-10-19.md
// section 4.5): one Go type every detector and driver converts into
// through its semantic adapter, and the only finding shape that crosses
// the pillar's seams (CLAUDE.md module rule 2).
//
// It is pure: no database, HTTP, fsnotify, exec or file I/O. It belongs to
// the `security` module root and is compiled out with sbo_omit_security.
// The closed vocabularies a finding is spelled in (category, severity,
// confidence, scope, baseline, status, attribution) are owned by
// internal/policy, because core code (the guard engine, the hook context
// seam, the org wire) consults them in every build (section 4.3); this
// package re-exports them as aliases so callers write
// secfinding.Category, not policy.FindingCategory.
//
// A finding never holds file contents or a secret value (section 4.6,
// CLAUDE.md "Don't store file contents"): it keeps paths, line numbers,
// redacted and capped evidence, and hashes.
package secfinding
