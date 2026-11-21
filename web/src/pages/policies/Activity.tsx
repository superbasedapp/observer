import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { GatedLink } from "@/components/GatedLink";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import {
  Button,
  ChartShell,
  EmptyState,
  ErrorState,
  HostMark,
  InlineLoading,
  ModelId,
  Pill,
  Tooltip,
  VocabDefPill,
} from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fmtClock, fmtInt } from "@/lib/format";
import { severityTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import { ADMISSION_DECISION, ADMISSION_DEGRADED } from "@shared/lib/obsVocab";
import { EGRESS_OUTCOME } from "@/lib/vocabTones";
import { Select } from "./ui";
import {
  EGRESS_ACTION_LABEL,
  EGRESS_OUTCOME_LABEL,
  VERDICT_PATH_LABEL,
  isGenuineDegraded,
  wordsFor,
} from "./vocab";

// Activity tab - the read-side audit surfaces that close the author → test →
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
  { value: "", label: "All decisions" },
  { value: "allow", label: "Allow" },
  { value: "flag", label: "Flag" },
  { value: "ask", label: "Ask" },
  { value: "deny", label: "Deny" },
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
          <VocabDefPill of={ADMISSION_DECISION} value={v.decision} />
          {v.severity && v.severity !== "info" && <VocabPill vocab="guardSeverity" value={v.severity} tone={severityTone(v.severity)} />}
          {v.mode === "observe" && v.decision !== "allow" && (
            <Pill variant="neutral" title="The policy only observes: recorded, not enforced.">not enforced</Pill>
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
      // `degraded` is a code: only a genuine fail-open means the judge was
      // unavailable; any other code names the deterministic layer that decided.
      if (isGenuineDegraded(v.degraded)) return <VocabDefPill of={ADMISSION_DEGRADED} value={v.degraded} />;
      return v.judge_used ? (
        <span className="whitespace-nowrap text-fg-3">{fmtInt(v.latency_ms)} ms</span>
      ) : (
        <span className="text-fg-3">{v.degraded ? wordsFor(VERDICT_PATH_LABEL, v.degraded) : "deterministic"}</span>
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
    cell: ({ row }) => (
      <span className="text-[12px] text-fg-2">
        {wordsFor(EGRESS_ACTION_LABEL, row.original.action)}
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
        <VocabDefPill of={ADMISSION_DECISION} value={row.original.verdict_decision} />
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
        <VocabPill vocab="egressOutcome" table={EGRESS_OUTCOME} value={row.original.realized_outcome}>
          {wordsFor(EGRESS_OUTCOME_LABEL, row.original.realized_outcome)}
        </VocabPill>
      ) : (
        <Tooltip content="Advise-only decisions are recorded but never routed.">
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
        sub="Every decision the admission policy recorded, which criterion fired and whether the judge ran. Kept on this machine."
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Select value={win} onChange={setWin} options={WINDOWS} ariaLabel="Time window" />
          <Select value={decision} onChange={setDecision} options={DECISION_FILTER} ariaLabel="Decision" />
          <Button size="sm" variant="ghost" iconLeft={RefreshCw} onClick={() => verdicts.reload()}>
            Refresh
          </Button>
          <span className="text-[11px] text-fg-3">{fmtInt(rows.length)} in window</span>
        </div>

        {verdicts.loading && rows.length === 0 ? (
          <InlineLoading label="Loading verdicts" />
        ) : verdicts.error && rows.length === 0 ? (
          <ErrorState title="Couldn't load the verdicts" error={verdicts.error} onRetry={verdicts.reload} />
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
        right={<GatedLink to="/egress" managed={null} className="text-caption font-medium text-accent hover:underline">Full log on Egress</GatedLink>}
        sub="What the routing policy decided. Advise-only rows are never routed; enforced rows show what the proxy did."
      >
        {egress.loading && egRows.length === 0 ? (
          <InlineLoading label="Loading egress decisions" />
        ) : egress.error && egRows.length === 0 ? (
          <ErrorState title="Couldn't load the routing decisions" error={egress.error} onRetry={egress.reload} />
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
