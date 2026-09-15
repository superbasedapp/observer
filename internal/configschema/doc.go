// Package configschema is THE owner of the dashboard-facing description of
// config.Config: which dotted TOML keys exist, what kind each one is, and —
// the load-bearing half — how each one is CLASSIFIED for the settings
// surface (docs/plans/dashboard-config-management-plan-2026-08-28.md §1–§4).
//
// The structure is derived by a reflect walk over config.Config's `toml`
// struct tags (walk.go), so it can never drift from the Go type. The
// classification lives in a data TABLE (annotations.go) keyed by dotted path
// with prefix rules — never in struct tags (CLAUDE.md #6: 500+ field edits
// in a file a dozen packages import) and never as control flow (CLAUDE.md
// #5). Every leaf carries:
//
//   - a security TIER (§4.1): plain / sensitive (confirm token + audit) /
//     secret (never rendered, never writable) / owner-elsewhere (read-only,
//     naming the owning command);
//   - a RESTART class (§3.1): live / live_persist / next_spawn / restart,
//     from which the UI chip text is DERIVED, never authored per form;
//   - a Settings SECTION, a member of nodegov.SettingsSectionIDs, so the
//     governance guard can refuse a batched write by section (§4.5);
//   - a PROMINENCE (primary / advanced / expert) so 500 keys are not a flat
//     list (§1.5).
//
// TestEveryLeafKeyClassified (classified_test.go) is the gate that makes the
// operator's ruling durable: a config key whose tier, restart class or
// section the table cannot resolve FAILS THE BUILD. There is deliberately
// no tier/restart default — a new top-level block forces a decision.
//
// The package is pure: no os, net/http, database/sql or fsnotify (pinned by
// imports_test.go). It imports internal/config for the type and nothing
// else. The runtime consumers are the dashboard (redaction, tier gating,
// validation, restart honesty) and web/cfgschema, the generator that
// serializes this owner plus the Go doc comments into the artifacts the
// SPA reads.
package configschema
