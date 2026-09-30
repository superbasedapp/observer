// Package correlate is Agent Access P11(a): best-effort MCP call <->
// coding-session correlation with an HONEST confidence (doc3 §11.12b (a),
// rulings R10.7 / R11.8 / R12.7).
//
// Pure derivation, shared by the node and the org exactly like
// internal/sessionmsg: each side loads its own rows with its own SQL (the
// node store seam internal/store/mcpcorrelate.go over mcp_relay_record +
// actions; the org rollup seam internal/orgserver/rollup/sessionmcp.go over
// mcp_decision / mcp_audit / mcp_node_decision_event + actions), maps them
// onto the plain Record / Action values here, and calls Derive. The node
// session-detail MCP panel and the org session drawer therefore render the
// SAME join from the SAME rules (the node->org trickle-up rule).
//
// Anchors (R11.8). The node relay stamps, per call, the `sbo_corr` anchor set
// {coding_session_id, turn_ref, action_ref, call_id} into its signed DPoP
// proof; the org front trusts it ONLY on a relay-originated node token. Repo
// mapping: coding_session_id <- sessions.id (the AI client's tree-inherited
// session env); action_ref <- actions.source_event_id (the tool-use id the
// client puts in the MCP request's _meta) or actions.message_id; turn_ref <-
// token_usage.turn_id / actions.turn_index.
//
// Confidence. A link is reported at the finest LEVEL it reaches (action |
// turn | session) with a confidence for THAT level: exact when an id anchor
// the relay carried pins it; inferred when a heuristic (tool name + time
// proximity inside an anchored session, an anchored turn with an ambiguous
// action, or - for a call that carried NO anchor - the unanchored tier's
// node / owner-wide name + time match, see unanchored.go) picked it; none
// when the carrier is untrusted (a direct OAuth / API-key client), the
// anchors point at another session, or an unanchored call matches no
// session or several too closely. No surface may claim exact correlation it
// does not have, so a call whose link is none is never attached to a
// session.
//
// De-duplication. The same call can arrive more than once - the org front's
// mcp_decision row and the node's pushed mcp_node_decision_event row for one
// relay-forwarded call, or a re-pushed node event - and every copy shares
// the relay-minted call_id; Derive folds them into one call.
package correlate
