// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

// Package record is the node-local relay record store: the ONE owner of the
// three mcp_relay_* tables that agent migration 131 adds (docs/plans/
// agent-access-implementation-plan-2026-09-23.md §3.2 "Node migration",
// rulings R8.18 / R8.27.a / R12.7 / R13.4 / R13.5 / R14.2 / R14.3 / R14.4).
//
//   - mcp_relay_record - the ONE append-only, hash-chained relay record
//     table. Every record kind (decision / completion / gap / gap_resolution)
//     draws its seq from the same id space and links into the same
//     chain_prev / chain_hash chain, so verification walks ONE chain from the
//     node's genesis. It is the SOURCE of the two org-wire families
//     (orgcontract.MCPRelayActivityRow + MCPRelayEventRow), composed by
//     internal/store/mcprelaysummary.go through this package - the table name
//     never appears in internal/store/orgpush.go.
//   - mcp_relay_state - the applied policy state per family plus the DURABLE
//     pending-loss twin of the relay's in-memory failed-append counter.
//   - mcp_relay_launch_spec - the crash-safe journal of each AI client's
//     ORIGINAL MCP server launch, written BEFORE a config rewrite.
//
// Chain construction mirrors the gateway chain (internal/mcpgw/audit):
// genesis = SHA-256("sbo-mcp-relay-genesis-v1" || node key), canonical bytes
// are domain-prefixed "name=len:value" lines in DDL order, and chain_hash =
// SHA-256(canonical || chain_prev).
//
// The package is a store seam over the node's *sql.DB (database/sql is its
// only I/O); it imports no HTTP, no fsnotify, and never internal/store (which
// imports it). The sidecar file the relay keeps for pending loss (R14.4) is
// the relay's own (internal/mcprelay); this package only persists the fold.
package record
