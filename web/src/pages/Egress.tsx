import { type ReactNode } from "react";
import {
  ChartShell,
  EmptyState,
  ErrorState,
  HeroStat,
  HostMark,
  InlineLoading,
  ModelId,
  PageHeader,
  Pill,
  Stagger,
  Tooltip,
} from "@/components/primitives";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import { ObsDisabled } from "@/components/ObsDisabled";
import { useApi } from "@/lib/useApi";
import { ApiError } from "@/lib/api";
import { fmtClock, fmtInt, fmtShortId } from "@/lib/format";
import { decisionTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import { EGRESS_OUTCOME, POLICY_MODE } from "@/lib/vocabTones";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";

// Egress page (G22 Plane-A policy egress routing): the read-only node surface
// over the installed [observability.egress] policy and the NODE-LOCAL
// obs_egress_decisions audit log — the decision half (rule / action / verdict)
// plus the realized outcome the proxy reported back (applied / fail_closed /
// realized_outcome). Everything renders VERBATIM from the store; this page
// computes nothing. The data never rides the org push (design §8: no org
// tier), so this node view — like `observer obs egress` — is the ONLY place
// the audit log is viewable. Distinct from the Security page's Plane-B guard
// (the developer's own coding-agent tool calls); this governs a hosted app's
// end-user traffic.

type EgressRule = {
  name: string;
  action: string;
  target?: string;
  reason_code: string;
  on_unavailable: string;
  pinned: boolean;
};
type EgressTarget = { id: string; url: string; shape: string };
type EgressChain = { rows: number; ok: boolean; detail?: string };
type EgressStatus = {
  enabled: boolean;
  mode: string;
  policy_hash?: string;
  rules: EgressRule[] | null;
  targets: EgressTarget[] | null;
  decisions_by_action: Record<string, number>;
  decisions_24h: number;
  chain: EgressChain;
};
type EgressDecision = {
  id: number;
  ts: string;
  mode: string;
  rule_name: string;
  policy_hash: string;
  action: string;
  upstream_id?: string;
  target_shape?: string;
  model_from?: string;
  model_to?: string;
  effort?: string;
  reason_code: string;
  must_use_target: boolean;
  applied: boolean;
  fail_closed: boolean;
  switch_held: boolean;
  realized_outcome?: string;
  degraded?: string;
  verdict_decision?: string;
  criterion_id?: string;
  request_id?: string;
  session_id?: string;
  user?: string;
};
type DecisionsResponse = { decisions: EgressDecision[] | null };

// The realized-outcome tone table is EGRESS_OUTCOME (@/lib/vocabTones) and
// the verdict tone is the guard decision's (@shared/lib/guardCatalog); an
// unknown label renders neutral with the CircleHelp glyph, never invented.

export function EgressPage() {
  const status = useApi<EgressStatus>("/api/obs/egress/status");
  const decisions = useApi<DecisionsResponse>("/api/obs/egress/decisions", { limit: 200 });

  // The /api/obs/* routes are registered only when [observability] is
  // enabled. When they are absent, the dashboard's SPA catch-all serves the
  // index.html shell with a 200 — so "obs off" manifests as a JSON parse
  // error (a non-ApiError), or as a 404 from an older/stricter mux. A real
  // handler failure is an ApiError with a 5xx and renders as an error below.
  const obsOff = [status.error, decisions.error].some(
    (e) => e != null && (!(e instanceof ApiError) || e.status === 404),
  );

  const st = status.data;
  const rows = decisions.data?.decisions ?? [];
  const totalDecisions = st
    ? Object.values(st.decisions_by_action).reduce((a, n) => a + n, 0)
    : 0;

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("egress")}
        title="Egress"
        sub="Plane-A policy egress routing: route a hosted app's end-user requests to another resource by admission verdict, end-user budget, or cohort. This audit log is node-local - it never rides the org push - so this page (and observer obs egress) is its only view. Read-only; policy is authored in config.toml."
      />
      {obsOff ? (
        <ObsDisabled>
          Egress routing rides the observability subsystem, and its API routes are not registered.
        </ObsDisabled>
      ) : status.error ? (
        <ErrorNote label="status" error={status.error} onRetry={status.reload} page />
      ) : (
        <>
          <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <HeroStat
              label="Mode"
              icon={<MetricIcon metric="policyMode" />}
              loading={status.loading}
              variant={st?.mode === "enforce" ? "warn" : "accent"}
              value={st ? st.mode : "-"}
              sub={
                st?.enabled
                  ? st.policy_hash
                    ? <span title={st.policy_hash}>{`policy ${fmtShortId(st.policy_hash, 12)}`}</span>
                    : "policy installed"
                  : "no egress policy installed"
              }
            />
            <HeroStat
              label="Rules / targets"
              icon={<MetricIcon metric="rules" />}
              loading={status.loading}
              stale={status.isStale}
              value={st ? `${(st.rules ?? []).length} / ${(st.targets ?? []).length}` : "-"}
              sub="first-match-wins · typed targets"
            />
            <HeroStat
              label="Decisions"
              icon={<MetricIcon metric="verdicts" />}
              loading={status.loading}
              stale={status.isStale}
              value={st ? fmtInt(totalDecisions) : "-"}
              sub={st ? `${fmtInt(st.decisions_24h)} in the last 24h` : ""}
            />
            <HeroStat
              label="Audit chain"
              icon={<MetricIcon metric={st && !st.chain.ok ? "auditChainBroken" : "auditChain"} />}
              loading={status.loading}
              stale={status.isStale}
              variant={st && !st.chain.ok ? "danger" : "accent"}
              value={st ? (st.chain.ok ? "intact" : "BROKEN") : "-"}
              sub={
                st
                  ? st.chain.ok
                    ? `${fmtInt(st.chain.rows)} hash-chained rows`
                    : (st.chain.detail ?? "verification failed")
                  : ""
              }
            />
          </Stagger>

          {st && !st.enabled && <EgressDisabled />}

          {st && st.enabled && (
            <ChartShell
              title="Policy"
              sub="The installed (compiled) policy - authored node-side in [observability.egress]; there is no dashboard write path."
            >
              <PolicyTables rules={st.rules ?? []} targets={st.targets ?? []} />
            </ChartShell>
          )}

          <ChartShell
            title="Decisions"
            sub="Newest first. Each row is the immutable decision plus the realized outcome the proxy reported back after the forward."
          >
            {decisions.loading ? (
              <InlineLoading label="Loading decisions" block />
            ) : decisions.error ? (
              <ErrorNote label="decisions" error={decisions.error} onRetry={decisions.reload} />
            ) : rows.length === 0 ? (
              <DecisionsEmpty enabled={!!st?.enabled} mode={st?.mode ?? "off"} />
            ) : (
              <DecisionsTable rows={rows} />
            )}
          </ChartShell>
        </>
      )}
    </div>
  );
}

// Rules evaluate top-down, so the policy table keeps the config order
// (sorting disabled); the typed-target list and the decision log sort.
const RULE_COLUMNS: ColumnDef<EgressRule, unknown>[] = [
  {
    id: "name",
    header: "Rule",
    accessorKey: "name",
    enableSorting: false,
    cell: ({ row }) => <span className="font-semibold text-fg-1">{row.original.name}</span>,
  },
  {
    id: "action",
    header: "Action",
    accessorKey: "action",
    enableSorting: false,
    cell: ({ row }) => <span className="font-mono text-[11px] text-fg-2">{row.original.action}</span>,
  },
  {
    id: "target",
    header: "Target",
    accessorFn: (r) => r.target ?? "",
    enableSorting: false,
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-1 font-mono text-[11px] text-fg-2">
        <HostMark host={row.original.target} size={11} />
        {row.original.target || "-"}
      </span>
    ),
  },
  {
    id: "on_unavailable",
    header: "On unavailable",
    accessorKey: "on_unavailable",
    enableSorting: false,
    cell: ({ row }) => {
      const r = row.original;
      return (
        <>
          <Pill variant={r.on_unavailable === "deny" ? "danger" : "neutral"}>{r.on_unavailable}</Pill>
          {r.pinned && (
            <Pill
              variant="warn"
              className="ml-1"
              title="Proxy-pinned: retries never substitute another target; if the target is unavailable the request fails CLOSED (provider-shaped 403), never leaking to the default upstream."
            >
              pinned
            </Pill>
          )}
        </>
      );
    },
  },
  {
    id: "reason_code",
    header: "Reason code",
    accessorKey: "reason_code",
    enableSorting: false,
    cell: ({ row }) => <span className="font-mono text-[11px] text-fg-3">{row.original.reason_code}</span>,
  },
];

const TARGET_COLUMNS: ColumnDef<EgressTarget, unknown>[] = [
  {
    id: "id",
    header: "Typed target",
    accessorKey: "id",
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-1.5 font-semibold text-fg-1">
        <HostMark host={`${row.original.id} ${row.original.url}`} size={12} />
        {row.original.id}
      </span>
    ),
  },
  {
    id: "shape",
    header: "Shape",
    accessorKey: "shape",
    cell: ({ row }) => <Pill variant="info">{row.original.shape}</Pill>,
  },
  {
    id: "url",
    header: "URL",
    accessorKey: "url",
    cell: ({ row }) => <span className="font-mono text-[11px] text-fg-3">{row.original.url}</span>,
  },
];

function PolicyTables({ rules, targets }: { rules: EgressRule[]; targets: EgressTarget[] }) {
  return (
    <div className="space-y-4">
      {rules.length === 0 ? (
        <p className="py-2 text-[12px] text-fg-3">
          No rules - add <code className="rounded-1 bg-bg-3 px-1 font-mono">[[observability.egress.rules]]</code>{" "}
          entries to config.toml.
        </p>
      ) : (
        <DataTable<EgressRule>
          data={rules}
          columns={RULE_COLUMNS}
          rowKey={(r) => r.name}
          minWidth={620}
        />
      )}
      {targets.length > 0 && (
        <DataTable<EgressTarget>
          data={targets}
          columns={TARGET_COLUMNS}
          rowKey={(t) => t.id}
          minWidth={480}
        />
      )}
    </div>
  );
}

const DECISION_COLUMNS: ColumnDef<EgressDecision, unknown>[] = [
  {
    id: "ts",
    header: "When",
    accessorKey: "ts",
    cell: ({ row }) => <span className="whitespace-nowrap text-fg-3">{fmtClock(row.original.ts)}</span>,
  },
  {
    id: "mode",
    header: "Mode",
    accessorKey: "mode",
    cell: ({ row }) => <VocabPill vocab="guardMode" table={POLICY_MODE} value={row.original.mode} />,
  },
  {
    id: "rule_name",
    header: "Rule",
    accessorKey: "rule_name",
    cell: ({ row }) => <span className="font-semibold text-fg-1">{row.original.rule_name}</span>,
  },
  {
    id: "action",
    header: "Action",
    accessorKey: "action",
    cell: ({ row }) => {
      const d = row.original;
      return (
        <span className="font-mono text-[11px] text-fg-2">
          {d.action}
          <ActionDetail d={d} />
          {d.must_use_target && (
            <Pill variant="warn" className="ml-1">
              pinned
            </Pill>
          )}
          {d.switch_held && (
            <Pill variant="neutral" className="ml-1">
              held
            </Pill>
          )}
        </span>
      );
    },
  },
  {
    id: "verdict",
    header: "Verdict",
    accessorFn: (d) => d.verdict_decision ?? "",
    cell: ({ row }) =>
      row.original.verdict_decision ? (
        <VocabPill
          vocab="guardDecision"
          value={row.original.verdict_decision}
          tone={decisionTone(row.original.verdict_decision)}
        />
      ) : (
        <span className="text-fg-3">-</span>
      ),
  },
  {
    id: "realized",
    header: "Realized",
    accessorFn: (d) => d.realized_outcome ?? "",
    cell: ({ row }) => <RealizedCell d={row.original} />,
  },
  {
    id: "request",
    header: "Request",
    accessorFn: (d) => d.request_id ?? "",
    enableSorting: false,
    cell: ({ row }) => (
      <span className="font-mono text-[10px] text-fg-3" title={row.original.request_id || undefined}>
        {row.original.request_id ? fmtShortId(row.original.request_id, 12) : "-"}
      </span>
    ),
  },
  {
    id: "user",
    header: "End-user",
    accessorFn: (d) => d.user ?? "",
    cell: ({ row }) => <span className="font-mono text-[11px] text-fg-3">{row.original.user || "-"}</span>,
  },
];

function DecisionsTable({ rows }: { rows: EgressDecision[] }) {
  return (
    <DataTable<EgressDecision>
      data={rows}
      columns={DECISION_COLUMNS}
      rowKey={(d) => String(d.id)}
      minWidth={820}
    />
  );
}

// ActionDetail renders the action's operator-config operand verbatim: an
// upstream id with its serving-host mark (none when unknown), a model switch
// as ModelId -> ModelId (family marks), or an effort level.
function ActionDetail({ d }: { d: EgressDecision }) {
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
        {" "}
        {d.model_from ? <ModelId model={d.model_from} markSize={11} className="min-w-0" /> : "?"} →{" "}
        <ModelId model={d.model_to} markSize={11} className="min-w-0" />
      </span>
    );
  }
  if (d.effort) return <span className="text-fg-3"> → {d.effort}</span>;
  return null;
}

// RealizedCell renders the proxy-reported outcome VERBATIM, or an honest
// pending dash when the proxy has not (yet) reported one — advise-mode rows
// are never routed, so they legitimately stay unreported.
function RealizedCell({ d }: { d: EgressDecision }) {
  if (!d.realized_outcome) {
    return (
      <Tooltip content="No realized outcome reported - advise-mode decisions are recorded but never routed, so the proxy reports nothing back.">
        <span tabIndex={0} className="cursor-help text-fg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring">
          -
        </span>
      </Tooltip>
    );
  }
  return (
    <>
      <VocabPill vocab="egressOutcome" table={EGRESS_OUTCOME} value={d.realized_outcome} />
      {d.fail_closed && d.realized_outcome !== "fail_closed" && (
        <Pill variant="danger" className="ml-1">
          fail-closed
        </Pill>
      )}
    </>
  );
}

// --- empty / error states ---------------------------------------------------

// EgressDisabled names the exact gate: [observability.egress] enabled (and its
// admission dependency — egress composes on the admission verdict).
function EgressDisabled() {
  return (
    <EmptyCard title="No egress policy installed">
      <p>
        Egress is default-off. It needs{" "}
        <code className="rounded-1 bg-bg-2 px-1 font-mono">[observability.egress] enabled = true</code>{" "}
        plus at least one rule, and{" "}
        <code className="rounded-1 bg-bg-2 px-1 font-mono">[observability.admission] enabled = true</code>{" "}
        - egress composes on the admission verdict. A policy that fails to compile is also reported
        here as not installed (the daemon logs the compile error and keeps admission running).
      </p>
      <p className="mt-2">
        Validate with <code className="rounded-1 bg-bg-2 px-1 font-mono">observer obs egress lint</code>.
      </p>
    </EmptyCard>
  );
}

function DecisionsEmpty({ enabled, mode }: { enabled: boolean; mode: string }) {
  return (
    <EmptyState
      variant="inline"
      illustration="inbox"
      title="No egress decisions recorded"
      body={
        enabled ? (
          <>
            The policy is installed in <b>{mode}</b> mode. A row appears when an admission-judged
            request matches a rule - {mode === "advise" ? "advise records the directive without applying it" : "enforce applies it on the proxy path and reports the realized outcome back"}.
          </>
        ) : (
          "Decisions are recorded only while an egress policy is installed."
        )
      }
    />
  );
}

// ErrorNote renders a failed egress read through the shared ErrorState
// (CircleAlert + Retry); `page` is the page-level status failure.
function ErrorNote({
  label,
  error,
  onRetry,
  page,
}: {
  label: string;
  error: Error;
  onRetry?: () => void;
  page?: boolean;
}) {
  return (
    <ErrorState
      title={`Couldn't load egress ${label}`}
      error={error}
      onRetry={onRetry}
      variant={page ? "page" : "inline"}
      className={page ? undefined : "py-6"}
    />
  );
}

// EmptyCard: the page-level "not configured" state, through the shared
// EmptyState with the connect illustration. The children carry the exact
// config gate to flip.
function EmptyCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <EmptyState illustration="connect" title={title}>
      <div className="mx-auto max-w-xl text-[12px] leading-relaxed text-fg-3">{children}</div>
    </EmptyState>
  );
}
