// Package cursorusage explains WHY a Cursor session has no captured token
// usage, from evidence the store already holds. It is pure logic (no SQL,
// no HTTP, no fsnotify; pinned by imports_test.go). Three loaders select
// plain rows - the node store seam
// (internal/store/cursor_usage.go::CursorUsageEvidence), the doctor check
// (internal/diag/cursorusage.go) and the org session drawer
// (internal/orgserver/rollup/sessiontokensnote.go) - and all three hand
// them to Tally, whose row identity is action_type + source_event_id (the
// only identity the org receives in every share mode). Classify / Explain
// then turn the Evidence into one Reason through an ordered rule table, so
// the node page and the org drawer print the same sentence.
//
// # Where Cursor reports usage (grounded 2026-09-27, cursor-agent
// 2026.09.18 + 2026.09.26 bundles and demo node-1 logs)
//
//	surface                      usage carrier                              when
//	---------------------------  -----------------------------------------  -------------------------
//	cursor-agent, interactive    stop + afterAgentResponse hook payloads    only when a turn FINISHES
//	cursor-agent, headless (-p)  agent_cli.turn.outcome debug-log record    only when a turn finishes
//	Cursor IDE                   stop / afterAgentResponse hooks, and the   per response
//	                             IDE hooks output-channel log (replay)
//
// The interactive CLI never writes usage to disk (its turn-outcome record
// carries no token fields and no conversation id), and the headless CLI
// never runs stop / afterAgentResponse. A turn that never finishes - a
// retry loop the user quits out of, a killed process - therefore has NO
// local usage anywhere, and the honest state is unknown, never zero. The
// cursor adapter records such turns from the cursor-agent debug log as
// turn_aborted rows (SourceEventID prefix SourceEventTurnPrefix) and each
// failed request attempt as an api_error row (SourceEventAttemptPrefix),
// which is the evidence this package reads.
package cursorusage
