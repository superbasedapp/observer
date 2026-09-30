// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

// Package discover is the PURE core of Agent Access P11 item (c), shadow-MCP
// discovery (docs/plans/agent-access-implementation-plan-2026-09-23.md
// §11.12b (c) + the §3.2 P11 DDL; rulings R10.10, R11.9, R12.10, R13.7,
// R13.8, R14.6). It owns four things and nothing else:
//
//   - the CANONICAL LOCATOR identity both sides must agree on byte-for-byte:
//     LocatorFingerprint (sha256 over the remote {transport, normalized url}
//     or the stdio {transport, command, scrubbed args, config_path_hash}),
//     NormalizeURL, ConfigPathHash, and the typed keyed ServerNameHash
//     ("hmac-sha256:v1:<hex>", keyed per org). The node computes them when it
//     builds an orgcontract.MCPInventoryRow (internal/store/mcpinventory.go);
//     the org server recomputes the name hash over its own registry names to
//     recognise a hash-only (share-off) row as already registered;
//   - the DIFF (Diff) of the node inventory (MCPInventoryRow) and the legacy
//     pin feed (GuardPinRow, kind mcp_server) against the Agent Access
//     registry, yielding the discovery candidates the ONE ingest owner
//     (internal/orgserver/ingest/mcpinventory.go) upserts into
//     mcp_discovery_candidate;
//   - the REGISTRY MATCH (MatchRegistry), a table walked top-down (url, exact
//     name, name suffix, keyed name hash), shared by the ingest diff and the
//     admin list's read-time annotation;
//   - the ADOPTION PLAN (PlanAdopt), a table of refusal rules walked
//     top-down: a candidate carrying only server_name_hash (a share-off /
//     hash-only individual row) is refused "needs node disclosure", never
//     adopted (R14.6); a remote candidate adopts as mcp_server
//     (streamable_http / sse_legacy), a stdio candidate as a NODE-RELAY
//     managed mcp_server (node_local_stdio) keyed by its (source_scope,
//     locator_fingerprint) (R12.10 / R13.7).
//
// The package is pure logic (CLAUDE.md module rule 1): no database/sql, no
// net/http, no fsnotify, no clock (every time is handed in as unix seconds)
// and no randomness. imports_test.go pins that. It never reads a config file
// (the node's extraction stays in internal/guard/mcpsec) and never scrubs
// (the node scrubs args / URLs before calling LocatorFingerprint, so the
// fingerprint is stable across a rotated secret that scrub redacts). It is
// DISTINCT from internal/intelligence/discover, which imports SQL (R10.12).
package discover
