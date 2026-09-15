import { useState } from "react";
import clsx from "clsx";
import type { SessionDetail } from "@/lib/types";
import { fmtCompact, fmtUSD } from "@/lib/format";

// LineageBanner — codex fork / subagent lineage. Extracted VERBATIM from
// SessionDetailPanel.tsx during the tab split. It renders ABOVE the tab strip
// (with the KPI band), not inside a tab: lineage is a fact about the session's
// identity, so hiding it behind a tab would make "this is a fork" discoverable
// only by accident.


// shortSid is the panel's short-session-id convention (mirrors the
// header's `id.slice(0, 8)`), used for the lineage badge labels.
function shortSid(id: string): string {
  id = id.split(":agent:").at(-1) ?? id;
  return id.length > 8 ? id.slice(0, 8) : id;
}

// lineagePillCls matches the Pill primitive's visual tokens so the
// clickable lineage badges read as chips consistent with the rest of the
// panel (border + soft bg + 10px semibold), while remaining <button>s.
const lineagePillCls =
  "inline-flex items-center gap-1 rounded-pill border px-[7px] py-[1px] text-[10px] font-semibold leading-[1.4] tracking-[0.02em] transition-colors";

// LineageBanner surfaces a codex session's fork/subagent lineage: an
// upward "parent" badge (subagent-of / forked-from) and a downward list
// of the sessions spawned from this one. Renders nothing for a normal
// (non-lineage) session. Reuses onOpenSession to navigate.
export function LineageBanner({
  d,
  onOpenSession,
}: {
  d: SessionDetail;
  onOpenSession?: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const isSubagent = d.thread_source === "subagent";
  const parentId = d.forked_from_id || d.parent_thread_id || "";
  const hasParent = parentId !== "";
  const children = d.children ?? [];
  // Inline sub-agent activity (claude-code same-session sidechain model):
  // no separate child session rows exist, so the banner notes the volume
  // and points at the System tab's per-sub-agent breakdown.
  const sidechainCount = d.sidechain_action_count ?? 0;
  if (!hasParent && children.length === 0 && sidechainCount === 0) return null;

  const canOpenParent = hasParent && d.parent_in_db && !!onOpenSession;
  const parentLabel = isSubagent
    ? `Subagent of ${shortSid(parentId)}`
    : `⑂ Forked from ${shortSid(parentId)}`;

  return (
    <div className="mb-3 flex flex-col gap-2">
      {sidechainCount > 0 && !hasParent && children.length === 0 && (
        <div className="rounded-md border border-accent/30 bg-accent-soft px-3 py-2 text-[11px] text-fg-2">
          Contains{" "}
          <span className="font-semibold text-fg-1">{sidechainCount}</span>{" "}
          sidechain action{sidechainCount === 1 ? "" : "s"} from inline
          sub-agents - see the System tab for the per-sub-agent breakdown.
        </div>
      )}
      {hasParent && (
        <div>
          <button
            type="button"
            disabled={!canOpenParent}
            onClick={
              canOpenParent ? () => onOpenSession!(parentId) : undefined
            }
            title={
              !d.parent_in_db
                ? "Parent session not in this database"
                : !onOpenSession
                  ? "Session navigation unavailable here"
                  : `Open parent session ${parentId}`
            }
            className={clsx(
              lineagePillCls,
              isSubagent
                ? "border-accent/30 bg-accent-soft text-accent"
                : "border-info/30 bg-info-soft text-info",
              canOpenParent
                ? "cursor-pointer hover:brightness-110 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
                : "cursor-not-allowed opacity-55",
            )}
          >
            {parentLabel}
          </button>
        </div>
      )}
      {children.length > 0 && (
        <div className="rounded-md border border-line-2 bg-bg-2 px-3 py-2">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="flex w-full items-center justify-between text-left text-[11px] font-medium text-fg-2 hover:text-fg-1 focus:outline-none"
          >
            <span>
              Spawned {children.length}{" "}
              {children.every((c) => c.thread_source === "subagent")
                ? "subagent"
                : children.some((c) => c.thread_source === "subagent")
                  ? "subagent/fork"
                  : "fork"}{" "}
              {children.length === 1 ? "session" : "sessions"}
            </span>
            <span className="font-mono text-fg-3">{expanded ? "−" : "+"}</span>
          </button>
          {expanded && (
            <ul className="mt-2 flex flex-col gap-1">
              {children.map((c) => {
                const openable = !!onOpenSession;
                return (
                  <li key={c.id}>
                    <button
                      type="button"
                      disabled={!openable}
                      onClick={
                        openable ? () => onOpenSession!(c.id) : undefined
                      }
                      title={
                        openable
                          ? `Open session ${c.id}`
                          : "Session navigation unavailable here"
                      }
                      className={clsx(
                        "flex w-full items-center gap-2 rounded px-2 py-1 text-left text-[11px] transition-colors",
                        openable
                          ? "cursor-pointer hover:bg-bg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
                          : "cursor-default",
                      )}
                    >
                      <span
                        className={clsx(
                          lineagePillCls,
                          c.thread_source === "subagent"
                            ? "border-accent/30 bg-accent-soft text-accent"
                            : "border-info/30 bg-info-soft text-info",
                        )}
                      >
                        {c.thread_source === "subagent" ? "subagent" : "fork"}
                      </span>
                      <span className="font-mono text-fg-2">
                        {shortSid(c.id)}…
                      </span>
                      {(c.input_tokens ?? 0) > 0 || (c.output_tokens ?? 0) > 0 ? (
                        <span className="ml-auto shrink-0 font-mono text-[10px] text-fg-3">
                          {fmtCompact((c.input_tokens ?? 0) + (c.output_tokens ?? 0))} tok
                          {(c.cost_usd ?? 0) > 0 ? ` · ${fmtUSD(c.cost_usd)}` : ""}
                        </span>
                      ) : (c.action_count ?? 0) > 0 ? (
                        <span className="ml-auto shrink-0 font-mono text-[10px] text-fg-3">
                          {c.action_count} action{(c.action_count ?? 0) === 1 ? "" : "s"}
                        </span>
                      ) : null}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
