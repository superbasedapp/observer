// mcpCalls.ts - the PURE half of the session-detail "MCP calls" panel
// (Agent Access P11(a), doc3 §11.12b (a), rulings R10.7 / R11.8).
//
// Both drawers render the SAME wire shape: the node's
// GET /api/session/<id>/mcp-calls and the org's
// GET /api/org/sessions/{id}/mcp-calls both return
// internal/mcpintel/correlate.Result, derived by one shared Go engine, so a
// call's link can never read differently on the node and in the org drawer.
// This module is the one owner of how that shape is WORDED on screen.
//
// Honesty rules this file makes structural (IA report §4):
//   - a link is rendered as its level AND its confidence together
//     ("turn 4 (exact)", "session (inferred)"); a session-level link is never
//     worded as a turn or an action;
//   - a call whose confidence is anything but exact / inferred is never
//     listed (the server already omits them; this is the defence in depth);
//   - unlinked calls are only ever COUNTED ("N MCP calls could not be tied to
//     this session"), never listed;
//   - token figures are always labelled as estimates, and an omitted key
//     means "not captured", never zero.
//
// No React, no fetch, no imports: the node and org test runners import it
// directly (node --experimental-strip-types).

/** The derived correlation of one call (correlate.Link). */
export interface MCPCallLinkLike {
  confidence: string;
  level: string;
  method: string;
  action_key?: string;
  message_id?: string;
  turn_index?: number;
  turn_id?: string;
  prompt_key?: string;
}

/** One de-duplicated MCP call attached to the session (correlate.Call). */
export interface MCPCallLike {
  call_id?: string;
  sources: string[] | null;
  ts: number;
  virtual_server?: string;
  server?: string;
  tool?: string;
  method?: string;
  decision?: string;
  reason?: string;
  coding_session_id?: string;
  turn_ref?: string;
  action_ref?: string;
  stored_corr_confidence?: string;
  capture_level?: string;
  args_excerpt?: string;
  args_full?: string;
  args_scrub_status?: string;
  completed: boolean;
  result_status?: string;
  latency_ms?: number;
  result_size_bytes?: number;
  result_full?: string;
  result_scrub_status?: string;
  error_full?: string;
  error_scrub_status?: string;
  schema_tokens_est?: number;
  result_tokens_est?: number;
  tokens_estimated?: boolean;
  tokenizer_version?: string;
  attribution_method?: string;
  attribution_confidence?: string;
  correlation: MCPCallLinkLike;
  folded_duplicate_records?: number;
}

/** correlate.Totals. */
export interface MCPCallTotalsLike {
  calls: number;
  exact: number;
  inferred: number;
  unlinked: number;
  /**
   * ambiguous is the subset of unlinked that came with no anchor and matched
   * this session AND another one too closely to tell apart (shown on
   * neither). Omitted by an older server: treat as 0.
   */
  ambiguous?: number;
  folded_duplicates: number;
}

/** correlate.Result: one session's MCP calls, oldest first. */
export interface SessionMCPCallsLike {
  session_id: string;
  calls: MCPCallLike[] | null;
  totals: MCPCallTotalsLike;
  truncated: boolean;
}

export type MCPTone = "success" | "warn" | "danger" | "info" | "neutral";

// LINKED_CONFIDENCES is the closed set a listed call may carry. "none" (and
// any value this build does not know) is never listed.
const LINKED_CONFIDENCES: readonly string[] = ["exact", "inferred"];

/** isLinked reports whether a call may be listed at all. */
export function isLinked(c: Pick<MCPCallLike, "correlation">): boolean {
  return LINKED_CONFIDENCES.includes(c.correlation?.confidence ?? "");
}

/** linkedCalls returns the listable calls, oldest first (stable). */
export function linkedCalls(r: Pick<SessionMCPCallsLike, "calls"> | null | undefined): MCPCallLike[] {
  const calls = (r?.calls ?? []).filter(isLinked);
  return calls
    .map((c, i) => ({ c, i }))
    .sort((a, b) => a.c.ts - b.c.ts || a.i - b.i)
    .map((x) => x.c);
}

// LEVEL_WORDS is how each correlation level is named. Adding a level is a row
// here, never a branch in a component.
const LEVEL_WORDS: Record<string, (l: MCPCallLinkLike) => string> = {
  action: (l) => (l.turn_index != null ? `action in turn ${l.turn_index}` : "action"),
  turn: (l) => (l.turn_index != null ? `turn ${l.turn_index}` : "turn"),
  session: () => "session",
};

/**
 * correlationLabel words a link as its level and confidence together, e.g.
 * "turn 4 (exact)" or "session (inferred)". A session-level link is always
 * "session", whatever turn fields ride along, so it can never read as finer
 * than it is.
 */
export function correlationLabel(l: MCPCallLinkLike): string {
  const word = LEVEL_WORDS[l.level];
  const where = word ? word(l) : l.level || "unknown level";
  return `${where} (${l.confidence || "unknown"})`;
}

/** correlationTone: exact reads as settled, inferred as a caution. */
export function correlationTone(confidence: string): MCPTone {
  if (confidence === "exact") return "success";
  if (confidence === "inferred") return "warn";
  return "neutral";
}

// METHOD_TEXT explains the rule that produced a link (correlate's rules
// table, one row per method). An unknown method is echoed, never guessed.
const METHOD_TEXT: Record<string, string> = {
  action_ref: "the client sent the tool-use id of this action",
  action_ref_message: "the client sent the id of this message",
  action_ref_unresolved: "the relay anchored the session; the action it named is not captured yet",
  turn_ref: "the relay named this turn",
  turn_ref_tool: "the relay named the turn; the tool name picked the action",
  session_tool_time: "nearest same-tool MCP action in time within the anchored session",
  session_time: "the only MCP action in the time window of the anchored session",
  session_only: "the relay anchored the session and nothing finer resolved",
  unanchored_tool_time:
    "the client sent no anchor; this session's captured tool call with the same tool and server name, nearest in time, picked it",
  unanchored_server_time:
    "the client sent no anchor and no tool name was captured; the only tool call naming this server in the time window picked it",
  unanchored_session:
    "the client sent no anchor; this session owns the call by tool name and time, but its matching action is already linked to another call",
  unanchored_protocol:
    "the client sent no anchor; a protocol message (not a tool call) belongs to the session whose tool calls name this server in time, so it is never linked to an action",
};

/** methodText explains a correlation method in words. */
export function methodText(method: string): string {
  return METHOD_TEXT[method] ?? method;
}

/** unlinkedNote is the honest count of calls that could not be tied here. */
export function unlinkedNote(t: Pick<MCPCallTotalsLike, "unlinked" | "ambiguous"> | null | undefined): string | null {
  const n = t?.unlinked ?? 0;
  if (n <= 0) return null;
  const base =
    n === 1
      ? "1 MCP call could not be tied to this session, so it is not listed."
      : `${n} MCP calls could not be tied to this session, so they are not listed.`;
  const a = Math.min(t?.ambiguous ?? 0, n);
  if (a <= 0) return base;
  return a === 1
    ? `${base} 1 of them matched another session just as well, so it is shown on neither.`
    : `${base} ${a} of them matched another session just as well, so they are shown on neither.`;
}

// DECISION_TONES colours the verdict vocabulary of both capture sides
// (node: allow / deny / ask; gateway: pass / deny / error / mutated).
const DECISION_TONES: Record<string, MCPTone> = {
  allow: "success",
  pass: "success",
  ask: "warn",
  mutated: "info",
  deny: "danger",
  error: "danger",
};

/** decisionTone colours a decision; an unknown one stays neutral. */
export function decisionTone(decision: string | undefined): MCPTone {
  return DECISION_TONES[decision ?? ""] ?? "neutral";
}

/**
 * tokensEstimateLabel renders the P11(b) token ESTIMATES of a gateway
 * completion, always labelled as estimated. An omitted figure is left out
 * (not captured), never rendered as 0. Returns null when neither is set.
 */
export function tokensEstimateLabel(
  c: Pick<MCPCallLike, "schema_tokens_est" | "result_tokens_est" | "tokenizer_version">,
): string | null {
  const parts: string[] = [];
  if (c.result_tokens_est != null) parts.push(`~${c.result_tokens_est.toLocaleString("en-US")} result tokens`);
  if (c.schema_tokens_est != null) parts.push(`~${c.schema_tokens_est.toLocaleString("en-US")} schema tokens`);
  if (parts.length === 0) return null;
  const tk = c.tokenizer_version ? `, ${c.tokenizer_version}` : "";
  return `${parts.join(", ")} (estimated${tk})`;
}

/** sourcesLabel names where the call was captured (gateway / node / both). */
export function sourcesLabel(sources: string[] | null | undefined): string {
  const s = (sources ?? []).filter(Boolean);
  if (s.length === 0) return "source unknown";
  return s.join(" + ");
}

/** callTarget is the "server / tool" a row is titled with. */
export function callTarget(c: Pick<MCPCallLike, "server" | "virtual_server" | "tool" | "method">): string {
  const server = c.server || c.virtual_server || "";
  const what = c.tool || c.method || "call";
  return server ? `${server} / ${what}` : what;
}

/** MCPCallsPanelState is what the panel shows before any row. */
export type MCPCallsPanelState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "empty"; message: string }
  | { kind: "rows" };

/**
 * panelState decides the panel's frame from the load flags. An empty panel
 * says why it is empty: with unlinked calls the count is stated, otherwise
 * the session simply made no MCP call Observer could tie to it.
 */
export function panelState(
  r: SessionMCPCallsLike | null | undefined,
  loading: boolean,
  error: string | null | undefined,
): MCPCallsPanelState {
  if (error) return { kind: "error", message: error };
  if (!r) return loading ? { kind: "loading" } : { kind: "empty", message: "No MCP call data for this session." };
  if (linkedCalls(r).length > 0) return { kind: "rows" };
  return {
    kind: "empty",
    message:
      unlinkedNote(r.totals) ??
      "No MCP calls are tied to this session. Only calls that went through the SuperBased MCP relay or gateway can be shown, and a call the client sent without an anchor only when a captured tool call of this session names it.",
  };
}
