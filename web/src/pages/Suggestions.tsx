import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  HeroStat,
  PageHeader,
  Pill,
  SegmentedControl,
} from "@/components/primitives";
import { Pagination } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import { HelpInd } from "@/components/HelpInd";
import { HeroWordmark } from "@/components/HeroWordmark";
import { CoinsIcon } from "@/components/icons";
import { useApi } from "@/lib/useApi";
import { useFilters, windowLabel, windowParams } from "@/lib/filters";
import { fmtShortId, fmtUSD } from "@/lib/format";
import type { AdvisorListResponse, AdvisorSuggestion } from "@/lib/types";

const PAGE_LIMIT = 20;

const CATEGORIES = [
  { value: "all", label: "All" },
  { value: "cost", label: "Cost" },
  { value: "latency", label: "Latency" },
  { value: "quality", label: "Quality" },
  { value: "hygiene", label: "Hygiene" },
];

const SEVERITY_TONE: Record<string, string> = {
  warning: "text-danger",
  advice: "text-accent",
  info: "text-fg-2",
};

export function SuggestionsPage() {
  // Global filters (TopBar): window, tool, project — the suggestions
  // surface honors all three like every other page (no local duplicate
  // window control; operator feedback 2026-06-10).
  const { win, customRange, tool, project } = useFilters();
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;
  // "all" maps to a far horizon (matches every sibling page; the backend
  // window is uncapped so this genuinely means all-time).
  const winParams = windowParams(win, customRange);
  const spendLabel =
    win === "all"
      ? "Avoidable spend - all time"
      : `Avoidable spend - last ${windowLabel(win, customRange)}`;
  const [category, setCategory] = useState("all");
  const [page, setPage] = useState(1);

  // Reset to page 1 whenever any query-affecting filter changes (global
  // window/tool/project or the local category) so a narrowed result set
  // never strands the user on an out-of-range, blank page. Mirrors
  // Actions.tsx / Sessions.tsx.
  const filterKey = `${win}|${JSON.stringify(customRange)}|${tool}|${project}|${category}`;
  useMemo(() => setPage(1), [filterKey]);

  const data = useApi<AdvisorListResponse>(
    "/api/suggestions",
    {
      ...winParams,
      project: projectParam,
      tool: toolParam,
      category: category === "all" ? undefined : category,
      page,
      limit: PAGE_LIMIT,
    },
    // Every control re-fires the query (useApi refetches on deps, not on
    // params identity — the original page missed this and the window
    // control was dead).
    [win, customRange, projectParam, toolParam, category, page],
  );
  const rep = data.data;
  const suggestions = rep?.suggestions ?? [];
  const totalCount = rep?.total_count ?? 0;

  return (
    <div className="space-y-4 p-5">
      <PageHeader
        title="Suggestions"
        sub="Prescriptive, dollar-quantified recommendations computed locally from your captured activity. Every number's arithmetic is shown."
        helpId="tab.suggestions"
      />

      {/* Camera-ready pass (growth-review §4): "avoidable spend" is the
          screenshot-shaped headline number on this page — a subtle
          corner wordmark carries the crop. */}
      <div className="relative grid grid-cols-1 gap-3 pb-4 sm:grid-cols-3">
        <HeroWordmark />
        <HeroStat
          label={spendLabel}
          helpId="tile.suggestions.avoidable"
          icon={<CoinsIcon />}
          loading={data.loading}
          value={rep ? fmtUSD(rep.total_savings_usd) : "-"}
          sub={
            rep && rep.total_savings_min > 0
              ? `+ ~${Math.round(rep.total_savings_min)} min of recoverable time`
              : undefined
          }
          variant="danger"
        />
        <HeroStat
          label="Open suggestions"
          helpId="tile.suggestions.open"
          loading={data.loading}
          value={rep ? String(totalCount) : "-"}
          sub={
            rep
              ? Object.entries(rep.by_detector ?? {})
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 3)
                  .map(([k, n]) => `${k.replaceAll("_", " ")} ×${n}`)
                  .join(" · ")
              : undefined
          }
        />
        <HeroStat
          label="Sessions scanned"
          helpId="tile.suggestions.scanned"
          loading={data.loading}
          value={rep ? String(rep.sessions_scanned) : "-"}
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="inline-flex items-center">
          <SegmentedControl options={CATEGORIES} value={category} onChange={setCategory} size="sm" />
          <HelpInd id="glossary.suggestion_card" />
        </span>
        {rep && category === "all" ? (
          <div className="flex flex-wrap gap-2 text-[11px] text-fg-3">
            {Object.entries(rep.by_category ?? {})
              .filter(([, usd]) => usd > 0)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, usd]) => (
                <span key={cat}>
                  {cat}: <span className="text-fg-2">{fmtUSD(usd)}</span>
                </span>
              ))}
          </div>
        ) : null}
      </div>

      <ChartState
        loading={data.loading}
        error={data.error}
        empty={!data.loading && suggestions.length === 0}
        emptyHint="No suggestions above the confidence and savings floors - nothing worth nagging about in this window."
      >
        <div className="space-y-3">
          {suggestions.map((s) => (
            <SuggestionCard key={s.dedup_key} s={s} onStateChange={data.reload} />
          ))}
          <Pagination
            page={page}
            total={totalCount}
            limit={PAGE_LIMIT}
            onPage={setPage}
          />
        </div>
      </ChartState>
    </div>
  );
}

function ScopeChip({ s }: { s: AdvisorSuggestion }) {
  if (s.scope === "session" && s.scope_id) {
    return (
      <Link
        to={`/sessions?session=${encodeURIComponent(s.scope_id)}`}
        className="font-mono text-[10px] text-accent underline decoration-dotted underline-offset-2 hover:text-accent-strong"
        title={`Open session detail (${s.scope_id})`}
      >
        session: {fmtShortId(s.scope_id, 8)}
      </Link>
    );
  }
  return (
    <Pill title={s.scope_id || undefined}>
      {s.scope_id ? `${s.scope}: ${fmtShortId(s.scope_id, 24)}` : s.scope}
    </Pill>
  );
}

// actionHref maps a suggestion's schema-level Action (C3) to a
// dashboard route. One renderer for every detector; unknown kinds
// return null and render nothing (forward compatible — an older web
// build never breaks on a newer daemon's action vocabulary). The
// action only NAVIGATES: any write happens behind the target
// surface's own consent flow (route preview/confirm, wizard steps).
function actionHref(a: NonNullable<AdvisorSuggestion["action"]>): string | null {
  switch (a.kind) {
    case "settings_section":
      return `/settings?section=${encodeURIComponent(a.target)}`;
    case "page":
      return a.target.startsWith("/") ? a.target : null;
    default:
      return null;
  }
}

function SuggestionCard({
  s,
  onStateChange,
}: {
  s: AdvisorSuggestion;
  onStateChange: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [gone, setGone] = useState(false);
  const setState = async (status: "dismissed" | "snoozed") => {
    try {
      await fetch("/api/suggestions/state", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dedup_key: s.dedup_key, status }),
      });
      setGone(true);
      onStateChange();
    } catch {
      /* leave the card in place */
    }
  };
  if (gone) return null;
  return (
    <div className="rounded-lg border border-line-1 bg-bg-1 p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-[13px] font-semibold ${SEVERITY_TONE[s.severity] ?? "text-fg-1"}`}>
              {s.title}
            </span>
            <Pill>{s.category}</Pill>
            <Pill>{s.detector.replaceAll("_", " ")}</Pill>
            <ScopeChip s={s} />
          </div>
          <p className="mt-2 text-[12px] leading-relaxed text-fg-2">{s.nudge}</p>
          {open && s.evidence?.math ? (
            <p className="mt-2 rounded bg-bg-2 px-2 py-1 font-mono text-[11px] text-fg-3">
              {s.evidence.math}
            </p>
          ) : null}
        </div>
        <div className="shrink-0 text-right">
          {s.savings_usd ? (
            <div className="text-[15px] font-semibold text-danger">{fmtUSD(s.savings_usd)}</div>
          ) : null}
          {!s.savings_usd && s.savings_min ? (
            <div className="text-[15px] font-semibold text-warn">~{Math.round(s.savings_min)} min</div>
          ) : null}
          <div className="text-[10px] uppercase tracking-wide text-fg-3">
            {Math.round(s.confidence * 100)}% confidence
          </div>
          {s.action && actionHref(s.action) ? (
            <div className="mt-1">
              <Link
                to={actionHref(s.action)!}
                className="inline-block rounded-2 bg-accent px-2 py-0.5 text-[11px] font-semibold text-accent-on transition-opacity hover:opacity-90"
              >
                {s.action.label}
              </Link>
            </div>
          ) : null}
          {s.evidence?.math ? (
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              className="mt-1 text-[11px] text-accent hover:underline"
            >
              {open ? "hide math" : "show math"}
            </button>
          ) : null}
          <div className="mt-1 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setState("snoozed")}
              className="text-[11px] text-fg-3 hover:underline"
            >
              snooze 7d
            </button>
            <button
              type="button"
              onClick={() => setState("dismissed")}
              className="text-[11px] text-fg-3 hover:underline"
            >
              dismiss
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
