import { useState } from "react";
import { GatedLink } from "@/components/GatedLink";
import {
  Button,
  ChartShell,
  EmptyState,
  ErrorState,
  HostMark,
  InlineEmpty,
  InlineLoading,
  ModelId,
  PageHeader,
  Pill,
  StatCard,
  StatStrip,
  Tooltip,
  buttonClasses,
} from "@/components/primitives";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import { ObsDisabled } from "@/components/ObsDisabled";
import { useApi } from "@/lib/useApi";
import { ApiError, fetchJSON } from "@/lib/api";
import { fmtClock, fmtInt, fmtShortId } from "@/lib/format";
import { decisionTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import { EGRESS_OUTCOME, POLICY_MODE } from "@/lib/vocabTones";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";
import {
  EGRESS_ACTION_LABEL,
  EGRESS_OUTCOME_LABEL,
  EGRESS_REASON_LABEL,
  ON_UNAVAILABLE_LABEL,
  POLICY_MODE_LABEL,
  TARGET_SHAPE_LABEL,
  wordsFor,
} from "./policies/vocab";

// Egress page (G22 Plane-A policy egress routing): the read-only node surface
// over the installed [observability.egress] policy and the NODE-LOCAL
// obs_egress_decisions audit log: the decision half (rule / action / verdict)
// plus the realized outcome the proxy reported back (applied / fail_closed /
// realized_outcome). Every value renders from the store through the
// policies/vocab.ts words; this page computes nothing. The data never rides
// the org push (design section 8: no org tier), so this node view (like
// `observer obs egress`) is the ONLY place the audit log is viewable.
// Distinct from the Security page's Plane-B guard (the developer's own
// coding-agent tool calls); this governs a hosted app's end-user traffic.

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

const ROUTING_HREF = "/policies?tab=routing";
const ROUTING_MANAGED = "Policies > Routing (managed by your organization)";

// The realized-outcome tone table is EGRESS_OUTCOME (@/lib/vocabTones) and
// the verdict tone is the guard decision's (@shared/lib/guardCatalog); an
// unknown label renders neutral with the CircleHelp glyph, never invented.

export function EgressPage() {
  const status = useApi<EgressStatus>("/api/obs/egress/status");
  const decisions = useApi<DecisionsResponse>("/api/obs/egress/decisions", { limit: 200 });

  // The /api/obs/* routes are registered only when [observability] is
  // enabled. When they are absent, the dashboard's SPA catch-all serves the
  // index.html shell with a 200, so "obs off" manifests as a JSON parse
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
  const ruleCount = (st?.rules ?? []).length;
  const targetCount = (st?.targets ?? []).length;

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("egress")}
        title="Egress"
        sub="Where your AI apps' end-user requests were routed, by verdict, budget or cohort. Kept on this machine."
        right={
          <GatedLink to={ROUTING_HREF} managed={null} className={buttonClasses({ size: "sm" })}>
            Edit routing
          </GatedLink>
        }
      />
      {obsOff ? (
        <ObsDisabled>
          Egress routing is part of AI Apps, which is not running on this machine.
        </ObsDisabled>
      ) : status.error ? (
        <ErrorState
          title="Couldn't load egress status"
          error={status.error}
          onRetry={status.reload}
          variant="page"
        />
      ) : (
        <>
          <StatStrip cols={4} ariaLabel="Egress summary" className="">
            <StatCard
              label="Mode"
              icon={<MetricIcon metric="policyMode" />}
              loading={status.loading}
              stale={status.isStale}
              value={st ? wordsFor(POLICY_MODE_LABEL, st.mode) : "-"}
              sub={
                st
                  ? st.enabled
                    ? st.policy_hash
                      ? <span title={st.policy_hash}>{`Policy ${fmtShortId(st.policy_hash, 12)}`}</span>
                      : "Policy installed"
                    : "No policy installed"
                  : undefined
              }
              linkTo={st && !st.enabled ? ROUTING_HREF : undefined}
            />
            <StatCard
              label="Rules"
              icon={<MetricIcon metric="rules" />}
              loading={status.loading}
              stale={status.isStale}
              value={st ? fmtInt(ruleCount) : "-"}
              sub={st ? `${fmtInt(targetCount)} ${targetCount === 1 ? "target" : "targets"}, first match wins` : undefined}
            />
            <StatCard
              label="Decisions"
              icon={<MetricIcon metric="verdicts" />}
              loading={status.loading}
              stale={status.isStale}
              value={st ? fmtInt(totalDecisions) : "-"}
              sub={st ? `${fmtInt(st.decisions_24h)} in the last 24h` : undefined}
            />
            <StatCard
              label="Audit log"
              icon={<MetricIcon metric={st && !st.chain.ok ? "auditChainBroken" : "auditChain"} />}
              loading={status.loading}
              stale={status.isStale}
              warn={!!st && !st.chain.ok}
              value={st ? (st.chain.ok ? "Intact" : "Broken") : "-"}
              cornerPill={
                st && !st.chain.ok ? <Pill variant="danger">tampered or damaged</Pill> : undefined
              }
              sub={
                st
                  ? st.chain.ok
                    ? `${fmtInt(st.chain.rows)} hash-chained rows`
                    : (st.chain.detail ?? "Verification failed")
                  : undefined
              }
            />
          </StatStrip>

          {st && !st.enabled && <EgressDisabled />}

          {st && st.enabled && (
            <ChartShell title="Policy" sub="The installed policy. Rules are checked top to bottom.">
              <PolicyTables rules={st.rules ?? []} targets={st.targets ?? []} />
            </ChartShell>
          )}

          <ChartShell
            title="Decisions"
            sub="Newest first. Each row is the decision and what the proxy did with it."
          >
            {decisions.loading && !decisions.data ? (
              <InlineLoading label="Loading decisions" block />
            ) : decisions.error ? (
              <ErrorState
                title="Couldn't load egress decisions"
                error={decisions.error}
                onRetry={decisions.reload}
                className="py-6"
              />
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
    cell: ({ row }) => <span className="text-fg-2">{wordsFor(EGRESS_ACTION_LABEL, row.original.action)}</span>,
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
    header: "If unavailable",
    accessorKey: "on_unavailable",
    enableSorting: false,
    cell: ({ row }) => {
      const r = row.original;
      return (
        <span className="inline-flex flex-wrap items-center gap-1">
          <span className="text-fg-2">{wordsFor(ON_UNAVAILABLE_LABEL, r.on_unavailable)}</span>
          {r.pinned && (
            <Pill
              variant="info"
              title="Pinned: retries never use another target. If this one is down the request is refused, never sent to the default upstream."
            >
              pinned
            </Pill>
          )}
        </span>
      );
    },
  },
  {
    id: "reason_code",
    header: "Reason",
    accessorKey: "reason_code",
    enableSorting: false,
    cell: ({ row }) => <span className="text-fg-3">{wordsFor(EGRESS_REASON_LABEL, row.original.reason_code)}</span>,
  },
];

const TARGET_COLUMNS: ColumnDef<EgressTarget, unknown>[] = [
  {
    id: "id",
    header: "Target",
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
    header: "API shape",
    accessorKey: "shape",
    cell: ({ row }) => <Pill variant="neutral" case="none">{wordsFor(TARGET_SHAPE_LABEL, row.original.shape)}</Pill>,
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
        <InlineEmpty
          message="No rules yet"
          body={
            <GatedLink to={ROUTING_HREF} managed={ROUTING_MANAGED} className="text-accent hover:underline">
              Add a rule on Policies &gt; Routing
            </GatedLink>
          }
        />
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

function ModeWords({ mode }: { mode: string }) {
  return (
    <VocabPill vocab="guardMode" table={POLICY_MODE} value={mode}>
      {wordsFor(POLICY_MODE_LABEL, mode)}
    </VocabPill>
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
    cell: ({ row }) => <ModeWords mode={row.original.mode} />,
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
        <span className="inline-flex flex-wrap items-center gap-1 text-fg-2">
          {wordsFor(EGRESS_ACTION_LABEL, d.action)}
          <ActionDetail d={d} />
          {d.must_use_target && <Pill variant="info">pinned</Pill>}
          {d.switch_held && (
            <Pill variant="neutral" title="A recent model switch is still cooling down, so this one was held.">
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
    header: "Outcome",
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
    header: "End user",
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
        <span className="font-mono text-[11px]">{d.upstream_id}</span>
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

// RealizedCell renders the proxy-reported outcome through its words, or an
// honest pending dash when the proxy has not (yet) reported one: advise-only
// rows are never routed, so they legitimately stay unreported.
function RealizedCell({ d }: { d: EgressDecision }) {
  if (!d.realized_outcome) {
    return (
      <Tooltip content="No outcome reported. Advise-only decisions are recorded but never routed.">
        <span tabIndex={0} className="cursor-help text-fg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring">
          -
        </span>
      </Tooltip>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <VocabPill vocab="egressOutcome" table={EGRESS_OUTCOME} value={d.realized_outcome}>
        {wordsFor(EGRESS_OUTCOME_LABEL, d.realized_outcome)}
      </VocabPill>
      {d.fail_closed && d.realized_outcome !== "fail_closed" && <Pill variant="danger">refused</Pill>}
    </span>
  );
}

// --- empty / error states ---------------------------------------------------

// EgressDisabled names where the policy is turned on: Policies > Routing
// saves the rules and sets [observability.egress] enabled, and egress needs
// admission on (it composes on the admission verdict), which the Policies
// page's own empty state turns on (B-S1).
function EgressDisabled() {
  return (
    <EmptyState
      illustration="connect"
      title="No routing policy installed"
      body="Routing is off until a policy with at least one rule is saved. It also needs admission checks on."
    >
      <div className="flex justify-center">
        <GatedLink to={ROUTING_HREF} managed={ROUTING_MANAGED} className={buttonClasses({ variant: "primary", size: "sm" })}>
          Add a rule on Policies &gt; Routing
        </GatedLink>
      </div>
      <EgressLintCheck />
    </EmptyState>
  );
}

type EgressLintResponse = { ok: boolean; fatal: boolean; issues: string[] };

// EgressLintCheck runs `observer obs egress lint` over the SAVED config
// (GET /api/obs/egress/lint, the same lint the CLI prints), so a policy that
// failed to install can be diagnosed here. Read-only, so no confirm step.
function EgressLintCheck() {
  const [res, setRes] = useState<EgressLintResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    setErr(null);
    try {
      setRes(await fetchJSON<EgressLintResponse>("/api/obs/egress/lint"));
    } catch (e) {
      setRes(null);
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="mx-auto mt-3 max-w-xl text-[12px] text-fg-3">
      <p>A saved policy that fails to compile also shows here as not installed.</p>
      <div className="mt-2 flex justify-center">
        <Button size="sm" onClick={() => void run()} loading={busy} disabled={busy}>
          {busy ? "Checking" : "Check the saved policy"}
        </Button>
      </div>
      {err && <ErrorState className="mt-2" variant="compact" title="Couldn't check the policy" error={err} onRetry={() => void run()} />}
      {res && res.ok && <p className="mt-2 text-success">The saved policy compiles with no findings.</p>}
      {res && !res.ok && (
        <ul className="mt-2 space-y-1 text-left font-mono text-[11px] text-fg-2">
          {res.issues.map((is) => (
            <li key={is} className="flex items-start gap-1.5">
              <Pill variant={is.includes("FATAL") ? "danger" : "warn"}>{is.includes("FATAL") ? "error" : "warning"}</Pill>
              <span className="pt-0.5">{is}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function DecisionsEmpty({ enabled, mode }: { enabled: boolean; mode: string }) {
  return (
    <EmptyState
      variant="inline"
      illustration="inbox"
      title="No egress decisions recorded"
      body={
        enabled
          ? `The policy is ${wordsFor(POLICY_MODE_LABEL, mode).toLowerCase()}. A row appears when a checked request matches a rule.`
          : "Decisions are recorded only while a routing policy is installed."
      }
    />
  );
}
