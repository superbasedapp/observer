import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  AnimatedValue,
  LiveDot,
  Meter,
  ObsJobRider,
  ObsLanding,
  Skeleton,
  ToolGlyphFrame,
} from "@/components/primitives";
import type { FirstRunResponse } from "@/lib/firstRun";
import { toolBadge } from "@/lib/firstRun";
import { dollarsShown, fmtCost } from "@/lib/format";
import {
  activeLine,
  glanceFacts,
  monotonic,
  revealCounters,
  toolsWithSessions,
  type GlanceResponse,
} from "@/lib/firstRunDoors";

// HistoryReveal - door B of the Overview welcome band (local dashboard
// first-run design, section 8 step 1). While the watcher reads this
// machine's existing AI-tool history it shows that work as it happens: each
// tool's files read, and counters that move only when a new reading from GET
// /api/firstrun arrives (AnimatedValue tweens between the two real values
// and snaps under reduced motion). When the pass is done it settles into
// "your AI coding at a glance" (GET /api/firstrun/glance). Every decision is
// in lib/firstRunDoors.ts; this file only renders it.

/** useClimbing keeps a counter from stepping back within one page view. */
function useClimbing(value: number): number {
  const ref = useRef<number | null>(null);
  ref.current = monotonic(ref.current, value);
  return ref.current;
}

const fmt = (n: number) => n.toLocaleString("en-US");

export function RevealProgress({ data }: { data: FirstRunResponse | null }) {
  const c = revealCounters(data);
  const sessions = useClimbing(c.sessions);
  const projects = useClimbing(c.projects);
  const filesRead = useClimbing(c.filesRead);
  const tools = (data?.tools ?? []).filter((t) => t.detected || t.sessions > 0 || t.history.files_found > 0);
  const projectTiles = (data?.projects ?? []).slice(0, 6);
  return (
    <div className="space-y-4">
      <ObsJobRider ratio={c.ratio} size={24} className="w-full" />
      <dl className="grid grid-cols-3 gap-2 sm:gap-3">
        <Counter label="Sessions" value={sessions} />
        <Counter label="Projects" value={projects} />
        <Counter
          label="Files read"
          value={filesRead}
          sub={c.filesFound > 0 ? `of ${fmt(c.filesFound)}` : undefined}
        />
      </dl>
      {tools.length > 0 && (
        <ul className="flex flex-wrap gap-2" aria-label="AI tools found here">
          {tools.map((t) => {
            const h = t.history;
            const ratio = h.state === "done" ? 1 : h.files_found > 0 ? (h.files_processed + h.files_failed) / h.files_found : 0;
            return (
              <li
                key={t.tool}
                className="sb-fade-up flex min-w-[10rem] items-center gap-2 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1.5"
              >
                <ToolGlyphFrame tool={t.tool} size={18} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2 text-[11.5px]">
                    <span className="truncate font-medium text-fg-1">{t.name}</span>
                    <span className="shrink-0 tabular-nums text-fg-3">{fmt(t.sessions)}</span>
                  </div>
                  <Meter ratio={Math.min(1, ratio)} label={`${t.name}: ${toolBadge(t).label}`} className="mt-1" />
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {projectTiles.length > 0 && (
        <ul className="flex flex-wrap gap-1.5" aria-label="Projects found so far">
          {projectTiles.map((p) => (
            <li
              key={p.root}
              className="sb-fade-up rounded-pill border border-line-1 bg-bg-2 px-2 py-0.5 text-[11px] text-fg-2"
              title={p.root}
            >
              {p.name} <span className="tabular-nums text-fg-4">{fmt(p.sessions)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Counter({ label, value, sub }: { label: string; value: number; sub?: string }) {
  return (
    <div className="min-w-0 rounded-2 border border-line-1 bg-bg-2 px-2.5 py-2 sm:px-3">
      <dt className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">{label}</dt>
      <dd className="mt-0.5 flex flex-wrap items-baseline gap-x-1">
        <AnimatedValue value={fmt(value)} className="text-[20px] font-semibold tabular-nums text-fg-0" />
        {sub && <span className="text-[11px] text-fg-3">{sub}</span>}
      </dd>
    </div>
  );
}

export function GlanceCard({
  glance,
  loading,
  error,
  landed,
}: {
  glance: GlanceResponse | null;
  loading: boolean;
  error: Error | null;
  /** The reveal finished in front of the person this visit: Obs lands once. */
  landed: boolean;
}) {
  const facts = glanceFacts(glance, { format: (usd, tokens) => fmtCost(usd, tokens), dollars: dollarsShown() });
  const live = activeLine(glance);
  // ObsLanding plays once per settle; it is gone again a few seconds later
  // so the card is not a standing mascot (one Obs at a time, never on a
  // polling surface).
  const [showObs, setShowObs] = useState(landed);
  useEffect(() => {
    if (!landed) return;
    setShowObs(true);
    const t = window.setTimeout(() => setShowObs(false), 4000);
    return () => window.clearTimeout(t);
  }, [landed]);

  if (!glance && loading) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5" aria-busy="true">
        {Array.from({ length: 5 }, (_, i) => (
          <Skeleton key={i} className="h-16 rounded-2" />
        ))}
      </div>
    );
  }
  if (!glance) {
    return error ? <p className="text-[11.5px] text-fg-3">The summary could not be read. The pages below have the details.</p> : null;
  }
  return (
    <div className="space-y-3">
      {showObs && <ObsLanding size={32} />}
      {facts.length > 0 ? (
        <ul className="sb-stagger grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {facts.map((f) => (
            <li key={f.key}>
              <Link
                to={f.href}
                className="sb-press block h-full rounded-2 border border-line-1 bg-bg-2 px-3 py-2 hover:border-line-3 hover:bg-bg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
              >
                <span className="block text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">{f.label}</span>
                <span className="mt-0.5 block truncate text-[16px] font-semibold tabular-nums text-fg-0" title={f.value}>
                  {f.value}
                </span>
                {f.sub && <span className="mt-0.5 block text-[11px] text-fg-3">{f.sub}</span>}
              </Link>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[11.5px] text-fg-3">Nothing to summarise yet.</p>
      )}
      {live && (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11.5px] text-fg-2">
          <LiveDot tone="success" still size="sm" label="Recently active" />
          <span>{live}</span>
          <Link to="/live" className="text-accent hover:underline">
            See Live
          </Link>
        </p>
      )}
    </div>
  );
}

/** The tool names the honest line uses, most-used first. */
export function revealToolNames(data: FirstRunResponse | null): string[] {
  return toolsWithSessions(data?.tools ?? []).map((t) => t.name);
}
