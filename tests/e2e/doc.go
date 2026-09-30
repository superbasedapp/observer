// Package e2e holds the repository's end-to-end gates that run a whole
// product vertical in one process. The Agent Access A2 vertical
// (agentaccess_a2_test.go, build tag agentgateway_boot, AGENTGATEWAY_BIN) is
// the §18 production-readiness gate run of doc3
// (docs/plans/agent-access-implementation-plan-2026-09-23.md): SQLite stores
// -> STS mint -> observer-mcpgw front -> in-process PDP -> loopback hop ->
// the REAL pinned agentgateway -> echo upstream, with the audit chain, the
// observe / enforce partition, PDP unavailability, the R11.13 audit
// boundary and the SIGTERM drain asserted. The sub-directories (orgserver,
// oneshot, statusline) are the older per-surface suites.
package e2e
