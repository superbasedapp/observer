import { useState, type ReactNode } from "react";
import { Pill } from "../../primitives";
import type { RenderMessageLink } from "./ProcessTree";
import { ChartState } from "../../charts/ChartState";
import { fmtBytes, fmtDateTime } from "../../lib/format";
import {
  callTarget,
  correlationLabel,
  correlationTone,
  decisionTone,
  linkedCalls,
  methodText,
  panelState,
  sourcesLabel,
  tokensEstimateLabel,
  unlinkedNote,
  type MCPCallLike,
  type SessionMCPCallsLike,
} from "../../lib/mcpCalls";

// MCP calls panel - one session's MCP tool calls, each tied to the action /
// turn / session it belongs to (Agent Access P11(a)). The node drawer
// (GET /api/session/<id>/mcp-calls) and the org drawer
// (GET /api/org/sessions/{id}/mcp-calls) render this SAME component over the
// SAME wire shape (correlate.Result), so a call's link reads identically on
// both. All wording rules live in lib/mcpCalls.ts.
//
// PURE: the caller fetches (the org route is an AUDITED deeper disclosure, so
// each app loads it lazily on first tab visit) and passes the result plus the
// load flags. `renderMessageLink` (ProcessTree's seam) lets an app turn the
// matched message id into a jump to its own Messages tab; absent, the ids
// render as plain text.

export type MCPCallsPanelProps = {
  result: SessionMCPCallsLike | null | undefined;
  loading?: boolean;
  error?: string | null;
  /** The read was a denial (HTTP 403, the apps' useApi `denied`): the panel
   *  renders the shared permission-denied state instead of an error. */
  denied?: boolean;
  /** The permission key the server's 403 named, when it named one. */
  deniedPermission?: string | null;
  renderMessageLink?: RenderMessageLink;
  /** Extra content rendered under the list (e.g. the org audit notice). */
  footer?: ReactNode;
};

export function MCPCallsPanel({
  result,
  loading = false,
  error = null,
  denied = false,
  deniedPermission = null,
  renderMessageLink,
  footer,
}: MCPCallsPanelProps) {
  const state = panelState(result, loading, error);
  const calls = linkedCalls(result);
  const unlinked = unlinkedNote(result?.totals);
  return (
    <div className="space-y-3">
      <p className="text-[11px] text-fg-3">
        MCP tool calls that went through the SuperBased MCP relay or gateway, each tied to where it happened in this
        session. <span className="text-fg-2">exact</span> means an id the client sent pins the link;{" "}
        <span className="text-fg-2">inferred</span> means a heuristic picked it: the nearest matching action inside the
        anchored session, or - for a client that sends no anchor - the captured tool call with the same tool and server
        name, nearest in time. Token figures are estimates.
      </p>
      <ChartState
        loading={state.kind === "loading"}
        error={state.kind === "error" ? new Error(state.message) : null}
        empty={state.kind === "empty"}
        emptyHint={state.kind === "empty" ? state.message : undefined}
        height={96}
        denied={denied}
        deniedPermission={deniedPermission}
      >
        <ul className="divide-y divide-line-2 rounded border border-line-2">
          {calls.map((c, i) => (
            <MCPCallRow key={c.call_id || `${c.ts}-${i}`} c={c} renderMessageLink={renderMessageLink} />
          ))}
        </ul>
        {(unlinked || result?.truncated) && (
          <p className="mt-2 text-[11px] text-fg-3">
            {unlinked}
            {unlinked && result?.truncated ? " " : ""}
            {result?.truncated ? "The list is capped; older calls are not shown." : ""}
          </p>
        )}
      </ChartState>
      {footer}
    </div>
  );
}

function MCPCallRow({ c, renderMessageLink }: { c: MCPCallLike; renderMessageLink?: RenderMessageLink }) {
  const [open, setOpen] = useState(false);
  const link = c.correlation;
  const tokens = tokensEstimateLabel(c);
  const hasPayload = Boolean(c.args_full || c.args_excerpt || c.result_full || c.error_full);
  // A session-level link names no action or message, so none is shown even if
  // a field rides along (it must never read finer than it is).
  const actionKey = link.level !== "session" ? link.action_key : undefined;
  const messageID = link.level !== "session" ? link.message_id : undefined;
  return (
    <li className="px-3 py-2 text-[12px]">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-fg-1">{callTarget(c)}</span>
            {c.decision && <Pill variant={decisionTone(c.decision)}>{c.decision}</Pill>}
            {c.completed ? (
              c.result_status && <Pill variant={c.result_status === "ok" ? "success" : "warn"}>{c.result_status}</Pill>
            ) : (
              <Pill>no completion recorded</Pill>
            )}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-fg-3">
            <Pill variant={correlationTone(link.confidence)} title={methodText(link.method)}>
              {correlationLabel(link)}
            </Pill>
            {actionKey && <span className="font-mono text-fg-4">{actionKey}</span>}
            {messageID &&
              (renderMessageLink ? (
                renderMessageLink(messageID)
              ) : (
                <span className="font-mono text-fg-4">message {messageID}</span>
              ))}
            <span>{sourcesLabel(c.sources)}</span>
            {c.capture_level && <span>capture {c.capture_level}</span>}
            {c.latency_ms != null && <span>{c.latency_ms} ms</span>}
            {c.result_size_bytes != null && <span>result {fmtBytes(c.result_size_bytes)}</span>}
            {(c.folded_duplicate_records ?? 0) > 0 && <span>{c.folded_duplicate_records} duplicate records folded</span>}
          </div>
          {c.reason && <div className="mt-0.5 text-[11px] text-fg-3">reason: {c.reason}</div>}
          {tokens && <div className="mt-0.5 text-[11px] text-fg-3">{tokens}</div>}
        </div>
        <div className="shrink-0 text-right text-[10.5px] text-fg-4">
          <div>{fmtDateTime(new Date(c.ts * 1000).toISOString())}</div>
          {c.call_id && <div className="font-mono">{c.call_id}</div>}
          {hasPayload && (
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              className="mt-1 text-[11px] text-fg-3 hover:text-accent"
            >
              {open ? "Hide payload" : "Show payload"}
            </button>
          )}
        </div>
      </div>
      {open && hasPayload && (
        <div className="mt-2 space-y-2">
          <Payload label="arguments" body={c.args_full || c.args_excerpt} scrub={c.args_scrub_status} />
          <Payload label="result" body={c.result_full} scrub={c.result_scrub_status} />
          <Payload label="error" body={c.error_full} scrub={c.error_scrub_status} />
        </div>
      )}
    </li>
  );
}

function Payload({ label, body, scrub }: { label: string; body?: string; scrub?: string }) {
  if (!body) return null;
  return (
    <div>
      <div className="mb-0.5 text-[10.5px] uppercase tracking-wide text-fg-4">
        {label}
        {scrub ? ` · scrub ${scrub}` : ""}
      </div>
      <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-line-2 bg-bg-2 p-2 font-mono text-[10.5px] text-fg-2">
        {body}
      </pre>
    </div>
  );
}
