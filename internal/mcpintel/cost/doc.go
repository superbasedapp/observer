// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

// Package cost is the PURE core of Agent Access P11 item (b): the per-MCP-
// server / per-MCP-tool ESTIMATED cost of a governed MCP call
// (docs/plans/agent-access-implementation-plan-2026-09-23.md §11.12b (b);
// rulings R10.8, R11.9, R12.11). It owns four things and nothing else:
//
//   - the TOKENIZER ESTIMATE (EstimateTokens / TokensForBytes): the repo's
//     own provider-neutral heuristic, ceil(bytes/4) over canonical bytes -
//     internal/cachetrack.EstimateTokens, the same estimate the cache
//     tracker prices blocks with - stamped with TokenizerVersion so a stored
//     number always names the estimator that produced it;
//   - the SCHEMA CATALOGUE (CatalogFromToolsJSON): per-tool token estimates
//     of the model-facing projection {name, description, inputSchema} of
//     every descriptor in an approved snapshot's tools_json - the schema
//     overhead each tool adds to a model's context;
//   - the ATTRIBUTION rule table (Attribute), walked top-down, one test case
//     per row: which of attribution_method {direct, allocated, inferred} and
//     attribution_confidence {exact, inferred, none} a call carries, its
//     schema-overhead tokens and the tokens its quota reservation holds
//     before the result is known;
//   - the SETTLEMENT (Settle) once the result size is known, and the
//     MULTI-TOOL ALLOCATION (Allocate): a catalogue call's result (the
//     listing IS the schema overhead of every tool it lists) is split across
//     those tools in proportion to their descriptor weights, by the largest-
//     remainder method, so the shares sum EXACTLY to the total.
//
// Every number here is an ESTIMATE, never a measurement: an MCP call has no
// metered price, only the model-context tokens its schema and its result are
// estimated to add. Estimate.Estimated is always true and every persisted
// row carries tokenizer_version, so no surface can present one as metered.
//
// The package takes plain values and returns plain values: no database/sql,
// no net/http, no fsnotify, no store (pinned by internal/mcpintel's
// recursive imports_test.go and by this package's own imports_test.go). The
// callers are the MCP gateway PDP (internal/mcpgw/pdp, which stamps the
// attribution on the Decision), the policy front (internal/mcpgw/mcpfront,
// which settles it into the mcp_audit completion record and the quota
// ledger) and the org rollup (the Budgets page).
package cost
