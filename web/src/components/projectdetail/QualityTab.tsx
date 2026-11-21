import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { StatCard } from "@/components/primitives";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";
import { ChartState } from "@/components/ChartState";
import { windowKey, type WindowParams } from "@/lib/projectDrawer";
import { useApi } from "@/lib/useApi";
import { fmtDateOnly, fmtInt, fmtRelative } from "@/lib/format";
import {
  changeText,
  complexityFilesNote,
  complexityHeadline,
  coverageHeadline,
  duplicationHeadline,
  formatLabel,
  isMeasured,
  pct,
  problemText,
  stateLabel,
  type ProjectQuality,
  type QualityComplexity,
  type QualityCoverage,
  type QualityDay,
  type QualityDuplication,
} from "@/lib/codeQuality";

// QualityTab: the Projects-detail Quality tab (docs/projects-page.md
// "Quality metrics"; plan item 8, M3L-2 and M3L-4): line coverage from the
// report files the project's own test runs wrote, duplication from the code
// intelligence near-clone index, complexity from the cyclomatic complexity
// code intelligence counts per function, and the daily trend of all three. Every figure
// names its source and its age; a metric the server did not measure shows
// "not measured" and the server's reason, never a zero. Ungraded and
// uncoloured, like the Overview tiles: a coverage or duplication number is
// a fact about the code, not a score.

export function QualityTab({ projectId, win }: { projectId: number; win: WindowParams }) {
  const q = useApi<ProjectQuality>(`/api/project/${projectId}/quality`, { ...win }, [projectId, windowKey(win)]);
  return (
    <ChartState
      loading={q.loading && !q.data}
      error={q.error}
      denied={q.denied}
      deniedPermission={q.deniedPermission}
      onRetry={q.reload}
      empty={!q.loading && !q.data}
      emptyHint="No quality data for this project"
      height={160}
    >
      {q.data && <QualityView q={q.data} />}
    </ChartState>
  );
}

/** QualityView renders a loaded response (exported for the component test). */
export function QualityView({ q, now = Date.now() }: { q: ProjectQuality; now?: number }) {
  return (
    <div className="space-y-5">
      {!q.enabled && (
        <p className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11px] text-fg-3">
          Quality metrics are off. Turn them on in{" "}
          <Link to="/settings?section=intelligence" className="text-accent hover:underline">
            Settings &gt; Intelligence
          </Link>{" "}
          (under More settings){" "}
          <HelpTooltip technical subject="the quality metrics switch" content="[projects].quality_metrics = true" className="align-middle" />{" "}
          to read coverage reports and measure duplication and complexity.
        </p>
      )}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <StatCard
          label="Line coverage"
          value={coverageHeadline(q.coverage)}
          sub={coverageSub(q.coverage, now)}
        />
        <StatCard
          label="Duplicated lines"
          value={duplicationHeadline(q.duplication)}
          sub={duplicationSub(q.duplication, now)}
        />
        <StatCard
          label={`Functions over complexity ${q.complexity.method.threshold}`}
          value={complexityHeadline(q.complexity)}
          sub={complexitySub(q.complexity, now)}
        />
      </div>

      <CoverageSection c={q.coverage} />
      <DuplicationSection d={q.duplication} />
      <ComplexitySection c={q.complexity} />
      <TrendSection q={q} />
    </div>
  );
}

function coverageSub(c: QualityCoverage, now: number): string {
  if (!isMeasured(c.state)) return `${stateLabel(c.state)}: ${c.reason}`;
  const counted = c.reports.filter((r) => r.use === "counted").length;
  const age = c.newest_report_at ? `newest report ${fmtRelative(c.newest_report_at, now)}` : "report age unknown";
  return `${fmtInt(c.covered)} of ${fmtInt(c.lines)} lines, ${fmtInt(counted)} report${counted === 1 ? "" : "s"}; ${age}`;
}

function duplicationSub(d: QualityDuplication, now: number): string {
  if (!isMeasured(d.state)) return `${stateLabel(d.state)}: ${d.reason}`;
  const age = d.last_indexed_at ? `indexed ${fmtRelative(d.last_indexed_at, now)}` : "index age unknown";
  const stale = d.stale ? "; from the last index, code intelligence is now off" : "";
  return `${fmtInt(d.cloned_lines)} of ${fmtInt(d.eligible_lines)} function lines in ${fmtInt(d.groups)} near-clone group${d.groups === 1 ? "" : "s"}; ${age}${stale}`;
}

function complexitySub(c: QualityComplexity, now: number): string {
  if (!isMeasured(c.state)) return `${stateLabel(c.state)}: ${c.reason}`;
  const age = c.last_indexed_at ? `indexed ${fmtRelative(c.last_indexed_at, now)}` : "index age unknown";
  const stale = c.stale ? "; from the last index, code intelligence is now off" : "";
  return `${fmtInt(c.over)} of ${fmtInt(c.functions)} functions; p90 ${fmtInt(c.p90)}, max ${fmtInt(c.max)}; ${age}${stale}`;
}

function SectionTitle({ children }: { children: ReactNode }) {
  return <div className="mb-2 text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">{children}</div>;
}

function CoverageSection({ c }: { c: QualityCoverage }) {
  return (
    <section>
      <SectionTitle>Coverage reports</SectionTitle>
      {c.reports.length === 0 && c.problems.length === 0 ? (
        <div className="text-[11px] text-fg-3">
          <p>{c.reason}</p>
          {c.state !== "off" && c.locations.length > 0 && (
            <p className="mt-1">
              Looked for: {c.locations.map((l) => l.path).join(", ")} (at the project root and in its top-level folders).
            </p>
          )}
        </div>
      ) : (
        <ul className="space-y-1 text-[11px]">
          {c.reports.map((r) => (
            <li key={r.path} className="text-fg-2">
              <span className="font-mono">{r.path}</span> · {formatLabel(r.format)} · {fmtInt(r.covered)}/{fmtInt(r.lines)} lines
              {r.totals_only ? " (summary totals only)" : ""} · written {fmtDateOnly(r.modified_at)}
              {r.use === "same_run" && <span className="text-fg-3"> · not counted again: same test run as {r.same_run_as}</span>}
            </li>
          ))}
          {c.problems.map((p) => (
            <li key={p.path} className="text-fg-3">
              <span className="font-mono">{p.path}</span> · {problemText(p.kind)}
            </li>
          ))}
        </ul>
      )}
      {isMeasured(c.state) && c.least_covered.length > 0 && (
        <div className="mt-3">
          <SectionTitle>Least-covered files</SectionTitle>
          <ul className="space-y-0.5 text-[11px] text-fg-2">
            {c.least_covered.map((f) => (
              <li key={`${f.report}:${f.path}`}>
                <span className="font-mono">{f.path}</span> · {pct(f.percent)} of {fmtInt(f.lines)} lines
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="mt-2 text-[10.5px] text-fg-4">
        Observer reads report files your test runs already wrote; it never runs your tests. Coverage is as fresh as
        the newest report.
      </p>
    </section>
  );
}

function DuplicationSection({ d }: { d: QualityDuplication }) {
  if (!isMeasured(d.state)) {
    return (
      <section>
        <SectionTitle>Duplication</SectionTitle>
        <p className="text-[11px] text-fg-3">{d.reason}</p>
      </section>
    );
  }
  return (
    <section>
      <SectionTitle>Largest near-clone groups</SectionTitle>
      {d.top_groups.length === 0 ? (
        <p className="text-[11px] text-fg-3">
          No near-clone functions among {fmtInt(d.eligible_symbols)} functions and methods.
        </p>
      ) : (
        <ul className="space-y-2 text-[11px]">
          {d.top_groups.map((g, i) => (
            <li key={i} className="text-fg-2">
              <div>
                {fmtInt(g.size)} functions, {fmtInt(g.lines)} lines
              </div>
              <ul className="ml-3 text-fg-3">
                {g.members.map((m) => (
                  <li key={`${m.file}:${m.start_line}`}>
                    <span className="font-mono">{m.name}</span> · <span className="font-mono">{m.file}</span>:{m.start_line}-{m.end_line}
                  </li>
                ))}
                {g.size > g.members.length && <li>and {fmtInt(g.size - g.members.length)} more</li>}
              </ul>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-[10.5px] text-fg-4">
        Approximate: functions and methods of at least {d.method.min_lines} lines whose bodies share at least{" "}
        {d.method.min_shared_bands} of {d.method.total_bands} MinHash bands in the code intelligence index. Every
        member of a group counts as duplicated, the original included.
        {d.skipped_buckets > 0 ? ` ${fmtInt(d.skipped_buckets)} boilerplate buckets shared by too many bodies were skipped.` : ""}
        {d.truncated ? " The symbol read hit its cap, so the figure covers part of the project." : ""}
      </p>
    </section>
  );
}

function ComplexitySection({ c }: { c: QualityComplexity }) {
  const note = complexityFilesNote(c);
  if (!isMeasured(c.state)) {
    return (
      <section>
        <SectionTitle>Complexity</SectionTitle>
        <p className="text-[11px] text-fg-3">{c.reason}</p>
        {note && c.state !== "off" && <p className="mt-1 text-[11px] text-fg-3">{note}.</p>}
      </section>
    );
  }
  return (
    <section>
      <SectionTitle>Most complex functions</SectionTitle>
      <ul className="space-y-0.5 text-[11px] text-fg-2">
        {c.top.map((f) => (
          <li key={`${f.file}:${f.start_line}`}>
            <span className="tabular-nums">{fmtInt(f.complexity)}</span> · <span className="font-mono">{f.name}</span> ·{" "}
            <span className="font-mono">{f.file}</span>:{f.start_line}-{f.end_line}
          </li>
        ))}
      </ul>
      {c.per_language.length > 1 && (
        <div className="mt-3">
          <SectionTitle>By language</SectionTitle>
          <ul className="space-y-0.5 text-[11px] text-fg-2">
            {c.per_language.map((l) => (
              <li key={l.lang}>
                {l.lang} · {fmtInt(l.over)} of {fmtInt(l.functions)} over {c.method.threshold} · p90 {fmtInt(l.p90)}, max{" "}
                {fmtInt(l.max)}
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="mt-2 text-[10.5px] text-fg-4">
        Cyclomatic complexity: decision points + 1 (if, loops, case arms, catch, &amp;&amp; and ||, ternaries) per function
        and method, counted by code intelligence from exact parse spans; the median is {fmtInt(c.p50)}.
        {note ? ` Not in the figure: ${note}.` : ""}
        {c.truncated ? " The read hit its cap, so the figure covers part of the project." : ""}
      </p>
    </section>
  );
}

function dayCoverage(p: QualityDay): string {
  return isMeasured(p.coverage_state) ? pct(p.coverage_percent) : stateLabel(p.coverage_state);
}

function dayDuplication(p: QualityDay): string {
  return isMeasured(p.dup_state) ? pct(p.dup_line_share) : stateLabel(p.dup_state);
}

function dayComplexity(p: QualityDay): string {
  return isMeasured(p.complexity_state) ? pct(p.complexity_over_share) : stateLabel(p.complexity_state);
}

function TrendSection({ q }: { q: ProjectQuality }) {
  const days = [...q.history].reverse();
  return (
    <section>
      <SectionTitle>Trend, last {q.window_days} days</SectionTitle>
      <ul className="mb-2 space-y-0.5 text-[11px] text-fg-2">
        <li>Coverage: {changeText(q.trend.coverage)}</li>
        <li>Duplicated lines: {changeText(q.trend.duplication)}</li>
        <li>
          Functions over complexity {q.complexity.method.threshold}: {changeText(q.trend.complexity)}
        </li>
      </ul>
      {days.length === 0 ? (
        <p className="text-[11px] text-fg-3">
          No daily points yet. The daemon records one per active project a day (and again after six hours).
        </p>
      ) : (
        <table className="w-full text-[11px]">
          <thead>
            <tr className="text-left text-fg-3">
              <th className="py-1 font-medium">Day</th>
              <th className="py-1 text-right font-medium">Coverage</th>
              <th className="py-1 text-right font-medium">Duplicated lines</th>
              <th className="py-1 text-right font-medium">Over complexity {q.complexity.method.threshold}</th>
            </tr>
          </thead>
          <tbody>
            {days.map((p) => (
              <tr key={p.day} className="border-t border-line-2 text-fg-2">
                <td className="py-1 tabular-nums">{p.day}</td>
                <td className="py-1 text-right tabular-nums">{dayCoverage(p)}</td>
                <td className="py-1 text-right tabular-nums">{dayDuplication(p)}</td>
                <td className="py-1 text-right tabular-nums">{dayComplexity(p)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
