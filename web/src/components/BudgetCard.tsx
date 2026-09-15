import { useState } from "react";
import { ChartShell, Pill } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { fmtUSD } from "@/lib/format";
import type {
  BudgetResponse,
  BudgetScope,
  ProjectsResponse,
} from "@/lib/types";

// BudgetCard — the Cost page's budget guardrails surface (P6.3).
// Shows month-to-date vs budget with a linear month-end forecast for
// the global budget and every per-project budget. ADVISORY ONLY — the
// card says so and nothing gates traffic.
//
// Edits save through the EXISTING config-section seam
// (PUT /api/config/section/intelligence). Budget values are read
// fresh by /api/budget and the Analysis headline on every load, so a
// save applies on the next poll — no daemon restart, hence no
// restart-pending store write here.
export function BudgetCard() {
  const budget = useApi<BudgetResponse>("/api/budget", undefined, [], {
    refreshMs: 60000,
  });
  const [editing, setEditing] = useState(false);

  return (
    <ChartShell
      title={<TitleWithHelp text="Budget" helpId="card.budget" />}
      sub="Advisory monthly budgets - banners at 80% and 100%, never a gate"
      right={
        <button
          type="button"
          onClick={() => setEditing((e) => !e)}
          className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[11px] text-fg-2 hover:bg-bg-3"
        >
          {editing ? "close" : "edit budgets"}
        </button>
      }
    >
      {editing ? (
        <BudgetEditor
          onSaved={() => {
            setEditing(false);
            budget.reload();
          }}
        />
      ) : !budget.data?.configured ? (
        <p className="py-4 text-center text-[12px] text-fg-3">
          No budgets set. “Edit budgets” to add a monthly cap - you get a
          quiet banner at 80% and 100%, and spend is never blocked.
        </p>
      ) : (
        <div className="space-y-3">
          {budget.data.global && (
            <ScopeBar
              sc={budget.data.global}
              label="All projects"
              daysElapsed={budget.data.days_elapsed}
              daysInMonth={budget.data.days_in_month}
            />
          )}
          {(budget.data.projects ?? []).map((sc) => (
            <ScopeBar
              key={sc.root}
              sc={sc}
              label={sc.root ?? ""}
              daysElapsed={budget.data!.days_elapsed}
              daysInMonth={budget.data!.days_in_month}
            />
          ))}
        </div>
      )}
    </ChartShell>
  );
}

function ScopeBar({
  sc,
  label,
  daysElapsed,
  daysInMonth,
}: {
  sc: BudgetScope;
  label: string;
  daysElapsed: number;
  daysInMonth: number;
}) {
  const pct = Math.min(100, sc.pct);
  const tone =
    sc.threshold === "over100"
      ? "var(--danger)"
      : sc.threshold === "warn80"
        ? "var(--warn)"
        : "var(--success)";
  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between gap-2 text-[12px]">
        <span className="min-w-0 truncate font-mono text-[11px] text-fg-2">
          {label}
        </span>
        <span className="shrink-0 tabular-nums text-fg-1">
          {fmtUSD(sc.mtd_usd)} / {fmtUSD(sc.budget_usd)}
          <span className="ml-1.5 text-[10.5px] text-fg-3">
            ({Math.round(sc.pct)}% · day {daysElapsed}/{daysInMonth} · on pace{" "}
            {fmtUSD(sc.forecast_usd)})
          </span>
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-pill bg-bg-3">
        <span
          className="block h-full"
          style={{ width: `${pct}%`, background: tone }}
        />
      </div>
      {sc.threshold === "over100" && (
        <Pill variant="danger">over budget - advisory only</Pill>
      )}
    </div>
  );
}

// BudgetEditor — loads current values from /api/config, lets the
// operator set the global budget and per-project budgets, and PUTs
// the intelligence section back through the shared seam (always
// sending ProjectBudgetsUSD explicitly — the preserve-on-absent
// contract is for forms that don't know about budgets).
function BudgetEditor({ onSaved }: { onSaved: () => void }) {
  const cfg = useApi<{
    config: {
      Intelligence: {
        CodeGraph: unknown;
        APIKeyEnv: string;
        SummaryModel: string;
        MonthlyBudgetUSD: number;
        ProjectBudgetsUSD?: Record<string, number> | null;
      };
    };
  }>("/api/config");
  const projects = useApi<ProjectsResponse>("/api/projects");
  const [global, setGlobal] = useState<string | null>(null);
  const [perProject, setPerProject] = useState<Record<string, string> | null>(
    null,
  );
  const [addRoot, setAddRoot] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const intel = cfg.data?.config.Intelligence;
  if (!intel) {
    return <p className="py-3 text-[12px] text-fg-3">Loading config…</p>;
  }
  const globalVal = global ?? String(intel.MonthlyBudgetUSD || "");
  const projVals =
    perProject ??
    Object.fromEntries(
      Object.entries(intel.ProjectBudgetsUSD ?? {}).map(([k, v]) => [
        k,
        String(v),
      ]),
    );
  const knownRoots = (projects.data?.rows ?? [])
    .map((r) => r.root_path)
    .filter((r) => r && !(r in projVals));

  const save = async () => {
    setSaving(true);
    setError(null);
    const budgets: Record<string, number> = {};
    for (const [root, v] of Object.entries(projVals)) {
      const n = Number(v);
      if (v.trim() !== "" && Number.isFinite(n) && n > 0) budgets[root] = n;
    }
    try {
      await fetchJSON("/api/config/section/intelligence", undefined, {
        method: "PUT",
        body: JSON.stringify({
          CodeGraph: intel.CodeGraph,
          APIKeyEnv: intel.APIKeyEnv,
          SummaryModel: intel.SummaryModel,
          MonthlyBudgetUSD: Number(globalVal) > 0 ? Number(globalVal) : 0,
          ProjectBudgetsUSD: budgets,
        }),
      });
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-3 text-[12px]">
      <label className="flex items-center justify-between gap-3">
        <span className="text-fg-2">Monthly budget, all projects (USD)</span>
        <input
          type="number"
          min="0"
          step="1"
          value={globalVal}
          onChange={(e) => setGlobal(e.target.value)}
          placeholder="0 = off"
          className="w-28 rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-right tabular-nums text-fg-1 outline-none focus:border-accent/60"
        />
      </label>
      {Object.entries(projVals).map(([root, v]) => (
        <label key={root} className="flex items-center justify-between gap-3">
          <span className="min-w-0 truncate font-mono text-[11px] text-fg-2">
            {root}
          </span>
          <span className="flex shrink-0 items-center gap-1.5">
            <input
              type="number"
              min="0"
              step="1"
              value={v}
              onChange={(e) =>
                setPerProject({ ...projVals, [root]: e.target.value })
              }
              className="w-28 rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-right tabular-nums text-fg-1 outline-none focus:border-accent/60"
            />
            <button
              type="button"
              onClick={() => {
                const next = { ...projVals };
                delete next[root];
                setPerProject(next);
              }}
              className="rounded-2 border border-line-2 bg-bg-2 px-1.5 py-0.5 text-[10.5px] text-fg-3 hover:bg-bg-3"
            >
              remove
            </button>
          </span>
        </label>
      ))}
      <div className="flex items-center gap-2">
        <select
          value={addRoot}
          onChange={(e) => setAddRoot(e.target.value)}
          className="min-w-0 flex-1 rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-2 outline-none"
        >
          <option value="">Add a per-project budget…</option>
          {knownRoots.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <button
          type="button"
          disabled={!addRoot}
          onClick={() => {
            setPerProject({ ...projVals, [addRoot]: "" });
            setAddRoot("");
          }}
          className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3 disabled:opacity-50"
        >
          add
        </button>
      </div>
      {error && <p className="text-[11px] text-danger">{error}</p>}
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10.5px] text-fg-3">
          Saves to config.toml (prior version kept at .bak). Applies on the
          next refresh - no restart.
        </span>
        <button
          type="button"
          disabled={saving}
          onClick={() => void save()}
          className="shrink-0 rounded-2 border border-accent/40 bg-accent-soft px-3 py-1 text-[11px] font-medium text-accent hover:bg-accent-soft/80 disabled:opacity-50"
        >
          {saving ? "saving…" : "save budgets"}
        </button>
      </div>
    </div>
  );
}
