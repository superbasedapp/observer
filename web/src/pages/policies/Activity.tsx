import { useState } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import { ChartShell, EmptyState, HostMark, InlineLoading, ModelId, Pill, Tooltip } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fmtClock } from "@/lib/format";
import { decisionTone, severityTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import { EGRESS_OUTCOME } from "@/lib/vocabTones";
import { Select } from "./ui";

// Activity tab — the read-side audit surfaces that close the author → test →
// observe loop inside the Policies module: the admission VERDICT timeline (every
// shadow/enforce decision the policy recorded) and a compact view of the recent
// egress ROUTING decisions. Both are node-local audit logs (never pushed). The
// full egress decision detail lives on the Egress page; this is the quick glance
// right next to where the policy was authored.

type Verdict = {
  id: number;
  ts: string;
  mode: string;
  decision: string;
  severity: string;
  criterion_id: string;
  judge_used: boolean;
  degraded: string;
  latency_ms: number;
  user: string;
  request_id: string;
  reason_excerpt?: string;
};

type EgressDecisionRow = {
  id: number;
  ts: string;
  mode: string;
  rule_name: string;
  action: string;
  upstream_id?: string;
  model_to?: string;
  effort?: string;
  reason_code: string;
  applied: boolean;
  realized_outcome?: string;
  verdict_decision?: string;
  user?: string;
};

const WINDOWS = [
  { value: "1", label: "1h" },
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
  { value: "720", label: "30d" },
];
const DECISION_FILTER = [
  { value: "", label: "all decisions" },
  { value: "allow", label: "allow" },
  { value: "flag", label: "flag" },
  { value: "ask", label: "ask" },
  { value: "deny", label: "deny" },
];

// tsValue turns an audit timestamp into a sortable epoch-ms value.
function tsValue(iso: string): number {
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : -Infinity;
}

// VERDICT_COLUMNS: rows arrive newest first; time, decision and criterion
// sort on a header click.
const VERDICT_COLUMNS: ColumnDef<Verdict, unknown>[] = [
  {
    id: "time",
    header: "Time",
    accessorFn: (v) => tsValue(v.ts),
    cell: ({ row }) => <span className="whitespace-nowrap text-fg-3">{fmtClock(row.original.ts)}</span>,
  },
  {
    id: "decision",
    header: "Decision",
    accessorKey: "decision",
    cell: ({ row }) => {
      const v = row.original;
      return (
        <span className="inline-flex items-center gap-1">
          <VocabPill vocab="guardDecision" value={v.decision} tone={decisionTone(v.decision)} />
          {v.severity && v.severity !== "info" && <VocabPill vocab="guardSeverity" value={v.severity} tone={severityTone(v.severity)} />}
          {v.mode === "observe" && v.decision !== "allow" && (
            <Pill variant="neutral" title="observe mode - recorded but not enforced">shadow</Pill>
          )}
        </span>
      );
    },
  },
  {
    id: "criterion",
    header: "Criterion",
    accessorFn: (v) => v.criterion_id || "",
    meta: { mono: true },
    cell: ({ row }) => <span className="whitespace-nowrap text-[11px]">{row.original.criterion_id || "-"}</span>,
  },
  {
    id: "judge",
    header: "Judge",
    enableSorting: false,
    cell: ({ row }) => {
      const v = row.original;
      return v.judge_used ? (
        <span className="text-fg-3">{v.latency_ms}ms{v.degraded ? " · degraded" : ""}</span>
      ) : (
        <span className="text-fg-3">deterministic</span>
      );
    },
  },
  {
    id: "user",
    header: "End-user",
    enableSorting: false,
    meta: { mono: true },
    cell: ({ row }) => <span className="whitespace-nowrap text-[11px] text-fg-3">{row.original.user || "-"}</span>,
  },
  {
    id: "reason",
    header: "Reason",
    enableSorting: false,
    cell: ({ row }) => <span className="text-fg-3">{row.original.reason_excerpt || "-"}</span>,
  },
];

// EGRESS_COLUMNS: rows arrive newest first; time, rule and action sort.
const EGRESS_COLUMNS: ColumnDef<EgressDecisionRow, unknown>[] = [
  {
    id: "time",
    header: "Time",
    accessorFn: (d) => tsValue(d.ts),
    cell: ({ row }) => <span className="whitespace-nowrap text-fg-3">{fmtClock(row.original.ts)}</span>,
  },
  {
    id: "rule",
    header: "Rule",
    accessorKey: "rule_name",
    cell: ({ row }) => <span className="font-semibold text-fg-1">{row.original.rule_name}</span>,
  },
  {
    id: "action",
    header: "Action",
    accessorKey: "action",
    meta: { mono: true },
    cell: ({ row }) => (
      <span className="text-[11px]">
        {row.original.action}
        <EgressActionDetail d={row.original} />
      </span>
    ),
  },
  {
    id: "verdict",
    header: "Verdict",
    enableSorting: false,
    cell: ({ row }) =>
      row.original.verdict_decision ? (
        <VocabPill vocab="guardDecision" value={row.original.verdict_decision} tone={decisionTone(row.original.verdict_decision)} />
      ) : (
        <span className="text-fg-3">-</span>
      ),
  },
  {
    id: "realized",
    header: "Realized",
    enableSorting: false,
    cell: ({ row }) =>
      row.original.realized_outcome ? (
        <VocabPill vocab="egressOutcome" table={EGRESS_OUTCOME} value={row.original.realized_outcome} />
      ) : (
        <Tooltip content="advise-mode decisions are recorded but never routed">
          <span tabIndex={0} className="cursor-help text-fg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring">-</span>
        </Tooltip>
      ),
  },
];

export function ActivityTab() {
  const [win, setWin] = useState("24");
  const [decision, setDecision] = useState("");

  const verdicts = useApi<Verdict[]>("/api/obs/admission/verdicts", { win, decision, limit: 200 }, [win, decision]);
  const egress = useApi<{ decisions: EgressDecisionRow[] | null }>("/api/obs/egress/decisions", { limit: 50 });

  const rows = verdicts.data ?? [];
  const egRows = egress.data?.decisions ?? [];

  return (
    <div className="space-y-4">
      <ChartShell
        title="Admission verdicts"
        sub="Every decision the admission policy recorded - the shadow (observe) or enforced verdict, which criterion fired, and whether the judge ran. Node-local audit; never pushed."
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Select value={win} onChange={setWin} options={WINDOWS} />
          <Select value={decision} onChange={setDecision} options={DECISION_FILTER} />
          <button type="button" onClick={() => verdicts.reload()} className="rounded-2 border border-line-2 px-2 py-1 text-caption text-fg-2 hover:text-fg-1">
            Refresh
          </button>
          <span className="text-[11px] text-fg-3">{rows.length} in window</span>
        </div>

        {verdicts.loading && rows.length === 0 ? (
          <InlineLoading label="Loading verdicts" />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="inline"
            illustration="inbox"
            illustrationSize={96}
            title="No verdicts recorded in this window"
            body="Run a request through the app (or the Test tab, which records nothing)."
          />
        ) : (
          <DataTable<Verdict>
            data={rows}
            columns={VERDICT_COLUMNS}
            rowKey={(v) => String(v.id)}
            rowClassName={() => "align-top"}
            minWidth={720}
          />
        )}
      </ChartShell>

      <ChartShell
        title="Recent egress decisions"
        right={<Link to="/egress" className="text-caption font-medium text-accent hover:underline">Full audit on Egress →</Link>}
        sub="Routing directives the egress policy produced. Advise-mode rows are recorded but never routed; enforce rows carry the proxy's realized outcome."
      >
        {egress.loading && egRows.length === 0 ? (
          <InlineLoading label="Loading egress decisions" />
        ) : egRows.length === 0 ? (
          <EmptyState
            variant="inline"
            illustration="inbox"
            illustrationSize={96}
            title="No egress decisions yet"
            body="A row appears when an admission-judged request matches a routing rule."
          />
        ) : (
          <DataTable<EgressDecisionRow>
            data={egRows}
            columns={EGRESS_COLUMNS}
            rowKey={(d) => String(d.id)}
            minWidth={560}
          />
        )}
      </ChartShell>
    </div>
  );
}

// EgressActionDetail renders the action operand: an upstream id with its
// serving-host mark (none when unknown), a target model as ModelId, or an
// effort level.
function EgressActionDetail({ d }: { d: EgressDecisionRow }) {
  if (d.upstream_id) {
    return (
      <span className="inline-flex items-center gap-1 text-fg-3">
        {" "}→ <HostMark host={d.upstream_id} size={11} />
        {d.upstream_id}
      </span>
    );
  }
  if (d.model_to) {
    return (
      <span className="inline-flex items-center gap-1 text-fg-3">
        {" "}→ <ModelId model={d.model_to} markSize={11} className="min-w-0" />
      </span>
    );
  }
  if (d.effort) return <span className="text-fg-3"> → {d.effort}</span>;
  return null;
}
