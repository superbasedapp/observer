import { useState, type ReactNode } from "react";
import { ChartState } from "../../charts/ChartState";
import { fmtCompact, fmtInt, fmtUSD } from "../../lib/format";
import { fmtDate } from "../../lib/sessionElapsed";
import type { RenderCost } from "./cost";
import type { SubAgentLike } from "../../lib/types";

// SubAgentsSection lists separately linked child sessions and legacy inline
// sidechain windows. Exact child identities keep concurrent runtime transcripts
// and usage separate; linked rows open the normal Messages view.
//
// Token/cost rollups (input_tokens/output_tokens/cost_usd) ride the same
// windows since node migration 087 flagged token_usage.is_sidechain; they are
// omitted (zero) until a post-087 ingest or an `observer scan --force`
// re-parse heals pre-existing transcripts.
//
// PURE: this component fetches nothing and owns no data state or persistence.
// The caller owns the open/closed state (the node persists it in localStorage)
// and does the lazy fetch when `open` flips — a closed section makes no
// request, exactly as before. Three injected seams:
//   * renderCost      — the org's <Money>; defaults to the node's ≈$x.xx text.
//   * linkChildSession — how a linked child session becomes a link (the node
//     hrefs /sessions?session=…, the org uses EntityLink; no router coupling).
//   * fetchFullText   — the hook-only row's "view captured final output"
//     lazy load. Omitted => that affordance is not offered.

/** FetchSubAgentFullText mirrors MessagesTable's FetchFullText seam. */
export type FetchSubAgentFullText = (
  actionId: number,
) => Promise<{ raw_tool_output?: string | null }>;

export type SubAgentsSectionProps = {
  /** Whether the section is expanded. Owned by the caller. */
  open: boolean;
  /** Toggle handler for the header button. */
  onToggleOpen: () => void;
  /** The loaded rows (empty while closed / loading). */
  rows: SubAgentLike[];
  /** Total the payload reported; falls back to rows.length when absent. */
  total?: number;
  /** True once a response has arrived (drives the honest empty state). */
  loaded: boolean;
  loading?: boolean;
  error?: Error | null;
  renderCost?: RenderCost;
  /**
   * Renders a linked child session. Receives the child's session id and its
   * display label; returns the whole link node. Default: the node's
   * /sessions?session=<id>&tab=messages anchor.
   */
  linkChildSession?: (sessionId: string, label: string) => ReactNode;
  /** Lazy loader for a hook-only row's captured final output. */
  fetchFullText?: FetchSubAgentFullText;
};

export function SubAgentsSection({
  open,
  onToggleOpen,
  rows,
  total,
  loaded,
  loading = false,
  error = null,
  renderCost,
  linkChildSession = defaultLinkChildSession,
  fetchFullText,
}: SubAgentsSectionProps) {
  const count = total ?? rows.length;
  const summary = loaded
    ? `${fmtInt(count)} sub-agent${count === 1 ? "" : "s"}${
        rows.some((r) => r.open) ? " · some stops unobserved" : ""
      }`
    : open
      ? "Loading…"
      : "click to load sub-agent activity";

  return (
    <section className="space-y-2">
      <h3>
        <button
          type="button"
          onClick={onToggleOpen}
          className="flex w-full items-center justify-between gap-2 text-left focus:outline-none"
          aria-expanded={open}
        >
          <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            <span className="select-none text-fg-3">{open ? "▾" : "▸"}</span>
            Sub-agents
          </span>
          <span className="text-[10.5px] text-fg-3">{summary}</span>
        </button>
      </h3>

      {open && (
        <ChartState
          loading={loading && !loaded}
          error={error}
          empty={loaded && rows.length === 0}
          emptyHint="No sub-agent activity on this session."
        >
          <ul className="flex flex-col gap-1.5">
            {rows.map((r, i) => (
              <li
                key={`${r.id ?? "window"}-${i}`}
                className="rounded-md border border-line-2 bg-bg-2 px-3 py-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2 text-[12px] font-medium text-fg-1">
                    {r.session_id
                      ? linkChildSession(r.session_id, r.label)
                      : r.label}
                    {r.type && (
                      <span className="rounded-pill border border-line-2 bg-bg-3 px-[7px] py-[1px] text-[10px] font-semibold text-fg-2">
                        {r.type}
                      </span>
                    )}
                    {r.open && (
                      <span className="rounded-pill border border-accent/30 bg-accent-soft px-[7px] py-[1px] text-[10px] font-semibold text-accent">
                        no stop observed
                      </span>
                    )}
                    {r.hook_only && (
                      <span className="text-[10px] font-normal text-fg-3">lifecycle hooks only</span>
                    )}
                  </span>
                  <span className="text-[10.5px] text-fg-3">
                    {r.action_count} action{r.action_count === 1 ? "" : "s"}
                    {r.error_count > 0 && (
                      <span className="ml-1 text-warn">· {r.error_count} failed</span>
                    )}
                  </span>
                </div>
                <div className="mt-0.5 text-[10.5px] text-fg-3">
                  {fmtDate(r.start)}
                  {r.end ? ` → ${fmtDate(r.end)}` : " → …"}
                  {((r.input_tokens ?? 0) > 0 || (r.output_tokens ?? 0) > 0) && (
                    <span className="ml-2">
                      · {fmtCompact(r.input_tokens)} in / {fmtCompact(r.output_tokens)} out
                    </span>
                  )}
                  {(r.cost_usd ?? 0) > 0 &&
                    (renderCost ? (
                      <span className="ml-1.5">
                        ·{" "}
                        {renderCost(r.cost_usd ?? 0, {
                          kind: "total",
                          tokens: subAgentTokenTotal(r),
                        })}
                      </span>
                    ) : (
                      <span className="ml-1.5" title={fmtUSD(r.cost_usd, true)}>
                        · ≈{fmtUSD(r.cost_usd)}
                      </span>
                    ))}
                  {((r.cache_read_tokens ?? 0) > 0 || (r.cache_creation_tokens ?? 0) > 0) && (
                    <span className="ml-2">· {fmtCompact(r.cache_read_tokens)} cache read / {fmtCompact(r.cache_creation_tokens)} cache write</span>
                  )}
                </div>
                {r.hook_only && (
                  <div className="mt-1 text-[10.5px] text-fg-3">
                    No transcript or usage captured for this agent.
                    {r.stop_action_id && fetchFullText ? (
                      <HookFinalOutput
                        actionId={r.stop_action_id}
                        fetchFullText={fetchFullText}
                      />
                    ) : null}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </ChartState>
      )}
    </section>
  );
}

// defaultLinkChildSession is the node's link: a plain anchor into the node's
// own sessions route with the Messages tab preselected. An app with a router
// (the org's EntityLink) passes its own.
function defaultLinkChildSession(sessionId: string, label: string): ReactNode {
  return (
    <a
      className="text-accent hover:underline"
      href={`/sessions?session=${encodeURIComponent(sessionId)}&tab=messages`}
      title="Open agent transcript"
    >
      {label}
    </a>
  );
}

function subAgentTokenTotal(r: SubAgentLike): number {
  return (
    (r.input_tokens ?? 0) +
    (r.output_tokens ?? 0) +
    (r.cache_read_tokens ?? 0) +
    (r.cache_creation_tokens ?? 0)
  );
}

// HookFinalOutput lazily loads the stop hook's captured final output through
// the injected fetch. Local expand state only — the same pattern MessagesTable
// uses for its per-row full text.
function HookFinalOutput({
  actionId,
  fetchFullText,
}: {
  actionId: number;
  fetchFullText: FetchSubAgentFullText;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && text === null && err === null && !loading) {
      setLoading(true);
      fetchFullText(actionId)
        .then((r) => setText(r.raw_tool_output ?? ""))
        .catch((e: unknown) =>
          setErr(e instanceof Error ? e.message : String(e)),
        )
        .finally(() => setLoading(false));
    }
  }

  return (
    <div className="mt-1">
      <button
        type="button"
        className="text-accent hover:underline"
        aria-expanded={open}
        onClick={toggle}
      >
        {open ? "Hide captured final output" : "View captured final output"}
      </button>
      {open && (
        <div className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-line-2 p-2 text-fg-2">
          {err || (loading ? "Loading…" : text || "No final output captured.")}
        </div>
      )}
    </div>
  );
}
