// Package settingsgate is the D19 rule for an AI agent's settings write
// (docs/plans/plane-a-sdk-buildout/02-plan-of-record-2026-11-19.md D19,
// principle 10): reads are always allowed; an ordinary key may be applied
// directly; a security-sensitive key (guard, capture and content, sharing,
// egress, admission mode, budgets, and an SDK destination that sends data
// online) is never applied by the agent: it becomes a proposal the user
// approves on the dashboard or the CLI. A credential, and a key another
// surface owns, are refused outright.
//
// The rule is ONE ordered table (gate.go, CLAUDE.md #5), walked top-down,
// over the configschema leaf (its tier) and the requested value. The MCP
// set_setting tool (internal/mcp) and the proposal approver in cmd/observer
// both dispatch on it, never on a key literal of their own.
//
// Pure: no database/sql, net/http, os or fsnotify (imports_test.go). It
// imports internal/config (the destination predicate) and
// internal/configschema (the leaf classification) only.
package settingsgate
