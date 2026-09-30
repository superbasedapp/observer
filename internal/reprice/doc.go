// Package reprice is the PURE planner behind opt-in retroactive re-pricing of
// stored spend rows (gap PRICE-REPRICE-1, docs/pricing.md "Re-pricing stored
// costs").
//
// Cost is stamped at capture: the proxy writes api_turns.cost_usd as a turn
// lands, the rolling summariser writes summary_calls.cost_usd, the push-time
// pricer stamps token_usage.estimated_cost_usd as a row leaves on the org
// wire. A price corrected later (a vendor list price the feed restated, an
// org rate authored after the fact) therefore never reached a row captured
// before it. This package decides, row by row, what the price in force AT THAT
// ROW'S OWN TIMESTAMP says the row should cost, and whether the stored figure
// may be replaced by it.
//
// It is PURE: no database/sql, no net/http, no fsnotify, and no cost engine
// import (imports_test.go pins it). Rows arrive already loaded with their
// provenance RESOLVED AT THE BOUNDARY into plain flags (Row.SourceReported,
// Row.FastUnknown) - this package never names a tool, a capture source or a
// table's writer. The price arrives as an injected [PriceFunc], so the node
// (its one process cost engine under internal/orgpricing.Mode's precedence)
// and the org server (seed + org_model_prices) plan with the SAME rules.
//
// Decisions are TABLE-DRIVEN (CLAUDE.md "decision logic is table-driven"):
// [skipRules] is an ordered rule set walked top-down, first match wins, one
// test case per row; a row no rule skips is re-priced. Reverting a run walks
// [revertRules] the same way.
//
// The invariants every rule preserves:
//
//   - A cost the capture source stated itself (a vendor's own billed figure,
//     a gateway's settled ledger figure) is never overwritten.
//   - A row with no price stays unknown: it is never written as $0, and a
//     captured price is never erased because today's table lacks the model.
//   - The price is the one in force at the row's timestamp; a row whose
//     timestamp does not parse is skipped rather than priced at today's rate.
//   - A tier the planner cannot see (the fast / priority premium on a copy
//     that did not keep the flag) is never guessed: such a row is skipped
//     when its model has a fast tier, so a re-price can never under-bill it.
package reprice
