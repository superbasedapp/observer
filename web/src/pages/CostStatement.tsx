import { useMemo, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import { useFilters } from "@/lib/filters";
import { costLabel, dollarsShown, fmtBytes, fmtCompact, fmtDateTime, fmtInt, fmtUSD, fmtYearMonth } from "@/lib/format";
import { HeroWordmark } from "@/components/HeroWordmark";
import {
  ComboChip,
  ErrorState,
  InlineLoading,
  ModelId,
  Table,
  type ComboOption,
} from "@/components/primitives";
import { withParams } from "@shared/lib/urlParams";
import type { MonthlyReport, ProjectsResponse } from "@/lib/types";

// Monthly statement (P6.6): a print-friendly document over
// /api/report/monthly. Pickers and buttons are screen-only; print CSS
// hides the app chrome so File→Print / Save-as-PDF yields a clean
// client-billable statement.
//
// Since the platform tabs plan (§3 row 9) the statement is the Cost page's
// Statement tab (`/cost?tab=statement&month=&project=`). The old standalone
// `/report` page is retired: App.tsx redirects `/report?month=&project=` to
// that tab with every param kept (nodePageTabs.ts reportToCostSearch).

/**
 * StatementView is the monthly statement document plus its screen-only
 * month / project pickers. `?month=` and `?project=` live in the URL and
 * every other param (the Cost page's `tab`) is kept when they change.
 */
export function StatementView() {
  const [params, setParams] = useSearchParams();
  const month = params.get("month") ?? new Date().toISOString().slice(0, 7);
  const project = params.get("project") ?? "";
  const setParam = (name: "month" | "project", value: string) =>
    setParams((prev) => withParams(prev, { [name]: value || null }));

  // The global Model filter applies (turn grain: the month's spend narrows
  // to that model's turns). The window, tool and global project do not: the
  // statement is a calendar month with its own project picker
  // (lib/filterScope.ts, the cost?tab=statement row).
  const { model } = useFilters();
  const modelArg = model !== "all" ? model : undefined;
  const report = useApi<MonthlyReport>(
    "/api/report/monthly",
    { month, project: project || undefined, model: modelArg },
    [month, project, modelArg],
  );
  const projects = useApi<ProjectsResponse>("/api/projects");
  const months = useMemo(() => lastMonths(12), []);
  // Project roots are long absolute paths: the chip shows the folder name
  // and the popover row carries the full path as its second line.
  const projectOptions = useMemo<ComboOption[]>(
    () => [
      { value: "", label: "All projects", searchable: "all projects" },
      ...(projects.data?.rows ?? []).map((p) => ({
        value: p.root_path,
        label: <span className="font-mono">{baseName(p.root_path)}</span>,
        detail: <span className="break-all font-mono">{p.root_path}</span>,
        searchable: p.root_path.toLowerCase(),
      })),
    ],
    [projects.data],
  );
  const r = report.data;

  return (
    <div className="max-w-3xl space-y-6 print:max-w-none print:p-0">
      {/* Screen-only controls */}
      <div className="flex flex-wrap items-center gap-2 print:hidden">
        <select
          aria-label="Statement month"
          value={month}
          onChange={(e) => setParam("month", e.target.value)}
          className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[12px] text-fg-1"
        >
          {months.map((m) => (
            <option key={m} value={m}>{fmtYearMonth(m)}</option>
          ))}
        </select>
        <ComboChip
          label="Project"
          value={project}
          onChange={(v) => setParam("project", v)}
          options={projectOptions}
          placeholder="Filter projects…"
          popoverWidth={420}
        />
        <button
          type="button"
          onClick={() => window.print()}
          className="rounded-2 border border-accent/40 bg-accent-soft px-3 py-1 text-[11px] font-medium text-accent"
        >
          Print / save as PDF
        </button>
      </div>

      {report.loading ? (
        <InlineLoading label="Building the statement" />
      ) : !r ? (
        <ErrorState
          variant="page"
          title="Couldn't build this statement"
          error={report.error?.message ?? "report unavailable"}
          onRetry={report.reload}
        />
      ) : (
        <article className="space-y-5 rounded-3 border border-line-2 bg-bg-2 p-6 print:border-0 print:bg-transparent print:p-0">
          <header className="border-b border-line-1 pb-3">
            <h1 className="text-[18px] font-semibold tracking-[-0.02em] text-fg-0">
              AI usage statement - {r.month}
            </h1>
            <p className="mt-1 text-[11.5px] text-fg-3">
              {r.project ? (
                <>project <span className="font-mono">{r.project}</span> · </>
              ) : (
                "all projects · "
              )}
              generated {fmtDateTime(r.generated_at)} · superbased
            </p>
          </header>

          {/* Camera-ready pass (growth-review §4): the statement headline
              is the number a client-billable screenshot / PDF travels
              with — a subtle corner wordmark carries it, print-visible. */}
          <section className="relative flex flex-wrap gap-x-8 gap-y-2 pb-3">
            <HeroWordmark />
            {/* The statement's rows carry no token counts, so the org's
                token-usage view drops every dollar figure here (the
                Tokens headline already carries the usage). */}
            {dollarsShown() && <Headline label="Total spend" value={fmtUSD(r.totals?.cost_usd ?? 0)} big />}
            <Headline label="Sessions" value={fmtInt(r.totals?.sessions ?? 0)} />
            <Headline label="API turns" value={fmtInt(r.totals?.turns ?? 0)} />
            <Headline
              label="Tokens (in / out / cache r / cache w)"
              value={`${fmtCompact(r.totals?.tokens?.input ?? 0)} / ${fmtCompact(r.totals?.tokens?.output ?? 0)} / ${fmtCompact(r.totals?.tokens?.cache_read ?? 0)} / ${fmtCompact(r.totals?.tokens?.cache_write ?? 0)}`}
            />
          </section>

          <ReportTable
            title={costLabel("Spend by model", "Usage by model")}
            rows={r.by_model ?? []}
            keyLabel="Model"
            renderKey={(k) => <ModelId model={k} className="max-w-full" />}
          />
          <ReportTable title={costLabel("Spend by tool", "Usage by tool")} rows={r.by_tool ?? []} keyLabel="Tool" sessions />
          {!r.project && (
            <ReportTable title={costLabel("Spend by project", "Usage by project")} rows={r.by_project ?? []} keyLabel="Project" sessions mono />
          )}

          <section>
            <h2 className="mb-1.5 text-[13px] font-semibold text-fg-0">Savings</h2>
            <p className="text-[12px] leading-relaxed text-fg-2">
              Conversation compression trimmed{" "}
              <span className="tabular-nums font-medium">{fmtBytes(r.savings?.compression_bytes ?? 0)}</span>{" "}
              (≈{fmtCompact(r.savings?.compression_tokens ?? 0)} tokens) of retrievable
              payload from upstream requests this month.
              {(r.savings?.compression_evicted_bytes ?? 0) > 0 && (
                <>
                  {" "}A further{" "}
                  <span className="tabular-nums font-medium">{fmtBytes(r.savings?.compression_evicted_bytes ?? 0)}</span>{" "}
                  of low-importance history was evicted (lossy drop) - not counted as
                  savings above; that content stays recoverable via search_past_outputs markers.
                </>
              )}{" "}
              Prompt caching served{" "}
              <span className="tabular-nums font-medium">{fmtCompact(r.savings?.cache_read_tokens ?? 0)}</span>{" "}
              tokens from cache at the provider's reduced cache-read rate.
            </p>
          </section>

          {(r.top_sessions?.length ?? 0) > 0 && (
            <section>
              <h2 className="mb-1.5 text-[13px] font-semibold text-fg-0">
                Top sessions ({Math.min(25, r.top_sessions!.length)})
              </h2>
              <Table
                minWidth={r.project ? 360 : 520}
                head={
                  <tr>
                    <th className="py-1 font-medium">Started</th>
                    <th className="py-1 font-medium">Tool</th>
                    {!r.project && <th className="py-1 font-medium">Project</th>}
                    <th className="py-1 text-right font-medium">Turns</th>
                    {dollarsShown() && <th className="py-1 text-right font-medium">Cost</th>}
                  </tr>
                }
              >
                {r.top_sessions!.map((s) => (
                  <tr key={s.id} className="border-t border-line-1">
                    <td className="whitespace-nowrap py-1 pr-2 tabular-nums">{fmtDateTime(s.started_at)}</td>
                    <td className="whitespace-nowrap py-1 pr-2">{s.tool || "-"}</td>
                    {!r.project && (
                      <td className="max-w-[220px] truncate py-1 pr-2 font-mono text-[10.5px]">{s.project || "-"}</td>
                    )}
                    <td className="py-1 text-right tabular-nums">{fmtInt(s.turns)}</td>
                    {dollarsShown() && <td className="py-1 text-right tabular-nums">{fmtUSD(s.cost_usd)}</td>}
                  </tr>
                ))}
              </Table>
            </section>
          )}

          <footer className="border-t border-line-1 pt-2 text-[10px] text-fg-3">
            {dollarsShown() &&
              "Costs combine provider-reported values and computed pricing over captured token usage (proxy-deduplicated). "}
            Figures cover activity captured by this observer install only.
          </footer>
        </article>
      )}

      {/* Print: hide the app shell around this page. */}
      <style>{`@media print {
        aside, .sb-topbar, .sb-filterbar, header.sb-shell { display: none !important; }
        body { background: white; }
      }`}</style>
    </div>
  );
}

function Headline({ label, value, big }: { label: string; value: string; big?: boolean }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-[0.06em] text-fg-3">{label}</div>
      <div className={big ? "text-[22px] font-semibold tabular-nums text-fg-0" : "text-[14px] font-medium tabular-nums text-fg-1"}>
        {value}
      </div>
    </div>
  );
}

function ReportTable({
  title,
  rows,
  keyLabel,
  sessions,
  mono,
  renderKey,
}: {
  title: string;
  rows: { key: string; cost_usd: number; turns: number; sessions?: number }[];
  keyLabel: string;
  sessions?: boolean;
  mono?: boolean;
  // Optional rich key cell (e.g. ModelId with the family mark); default is
  // the key as plain text.
  renderKey?: (key: string) => ReactNode;
}) {
  if (rows.length === 0) return null;
  return (
    <section>
      <h2 className="mb-1.5 text-[13px] font-semibold text-fg-0">{title}</h2>
      <Table
        minWidth={sessions ? 360 : 300}
        head={
          <tr>
            <th className="py-1 font-medium">{keyLabel}</th>
            {sessions && <th className="py-1 text-right font-medium">Sessions</th>}
            <th className="py-1 text-right font-medium">Turns</th>
            {dollarsShown() && <th className="py-1 text-right font-medium">Cost</th>}
          </tr>
        }
      >
        {rows.map((row) => (
          <tr key={row.key} className="border-t border-line-1">
            <td className={`max-w-[300px] truncate py-1 pr-2 ${mono ? "font-mono text-[10.5px]" : ""}`}>
              {renderKey ? renderKey(row.key) : row.key}
            </td>
            {sessions && <td className="py-1 text-right tabular-nums">{fmtInt(row.sessions ?? 0)}</td>}
            <td className="py-1 text-right tabular-nums">{fmtInt(row.turns)}</td>
            {dollarsShown() && <td className="py-1 text-right tabular-nums">{fmtUSD(row.cost_usd)}</td>}
          </tr>
        ))}
      </Table>
    </section>
  );
}

function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

function lastMonths(n: number): string[] {
  const out: string[] = [];
  const d = new Date();
  for (let i = 0; i < n; i++) {
    out.push(new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - i, 1)).toISOString().slice(0, 7));
  }
  return out;
}
