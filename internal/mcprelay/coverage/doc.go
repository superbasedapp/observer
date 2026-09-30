// Package coverage is the Agent Access node-side coverage-honesty matrix
// (doc3 §12.7, finding-28 / doc2-17 / doc2-18): WHICH client x transport x
// method combination is actually MEDIATED by the node relay, which is only
// caught post-hoc or pre-execution by a best-effort control (the proxy
// tools[] filter, the PreToolUse hook deny, the config projection), and
// which is honestly UNCOVERED — a local admin or a raw client that bypasses
// relay + hooks + projection is a gap, not health.
//
// Everything here is DATA. The client set and its per-client capability
// shape come from internal/integration (does the client keep an MCP
// registry we project into; can its hook block pre-execution; is it
// proxy-routable), never from a tool-name switch (CLAUDE.md rule 3). The
// method rows are ONE row per relay serving mode over the canonical
// governed / catalogue partition (R8.26.b) - derived, not re-authored. The
// published matrix separates "writer exists TODAY" from "planned (phase)"
// (R8.23.o).
//
// The effective hash (R8.15 / doc2-B5) is defined here too: SHA-256 over
// the canonical JSON of {policy_version, compiled_subset_hash,
// point_capability_set, client_id+version, client_config_state}. A point
// missing ANY required capability reports `ineffective`, never `effective`
// (a mixed-version / capability gap is a gap, not health).
//
// Pure package: no database/sql, net/http, fsnotify, os (pinned by
// imports_test.go). Rendered by `observer mcp-relay status`.
package coverage
