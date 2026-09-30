import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import {
  ChartShell,
  ComboChip,
  EmptyState,
  type ComboOption,
  HeroStat,
  Icon,
  InlineLoading,
  PageHeader,
  Pill,
  SegmentedControl,
  Tooltip,
  Stagger,
  Table,
} from "@/components/primitives";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import { TitleWithHelp } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import { GuardOverrideCard } from "@/components/GuardOverrideCard";
import { useApi, type ApiState } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { markRestartPending } from "@/lib/restartPending";
import { fmtClock, fmtDateTime, fmtShortId } from "@/lib/format";
import type {
  GuardPolicyLint,
  GuardPolicyView,
  GuardRule,
  GuardRulesResponse,
  ProjectsResponse,
} from "@/lib/types";
import { RuleManager } from "./security/RuleManager";
import { MCPAccessSection } from "@/components/security/MCPAccessSection";
import { StatusTile } from "@/components/security/StatusTile";
import {
  ChartColumnStacked,
  Check,
  FileCheck2,
  FileCode2,
  ListChecks,
  MessageSquareWarning,
  Plug,
  ShieldCheck,
  SlidersHorizontal,
  Stamp,
  Wallet,
  X,
  type LucideIcon,
} from "lucide-react";
import { decisionTone, severityTone } from "@shared/lib/guardCatalog";
import { toneOf, type Tone } from "@shared/lib/tone";
import { JOB_STATUS } from "@shared/lib/sessionVocab";
import { VocabPill } from "@shared/lib/vocabPill";
import {
  CHECK_STATUS,
  POLICY_MODE,
  PROMPT_GUARD_OUTCOME,
  promptGuardOutcomeKey,
} from "@/lib/vocabTones";
import { navIcon } from "@/lib/nav";

// One glyph per Security section title, drawn before the heading text.
const SECURITY_SECTION_ICONS = {
  verdictTimeline: ChartColumnStacked,
  enforcementCoverage: ShieldCheck,
  complianceEvidence: FileCheck2,
  mcpServers: Plug,
  mode: SlidersHorizontal,
  enforceReadiness: ListChecks,
  budgetGuardrails: Wallet,
  policyLayers: FileCode2,
  approvals: Stamp,
  promptGuard: MessageSquareWarning,
} satisfies Record<string, LucideIcon>;
import { MetricIcon } from "@/components/MetricIcon";

// Security page (guard spec §11.2, G7): guard posture header, the
// verdict timeline with severity/decision filters, the §6.5
// coverage/conformance matrix, and the §10.4 audit-chain status.
// Approvals queue, posture panel (sandbox/yolo), budget burn-down and
// the MCP pin inventory join with their respective arcs (G8/G10–G12).

type GuardCounts = {
  total: number;
  enforced: number;
  by_decision: Record<string, number> | null;
  by_severity: Record<string, number> | null;
  by_category: Record<string, number> | null;
};

type GuardSummary = {
  enabled: boolean;
  mode: string;
  strict: boolean;
  counts_24h: GuardCounts;
  counts_7d: GuardCounts;
  chain: { ok: boolean; checked: number; divergence_id?: number; detail?: string };
};

type GuardEvent = {
  id: number;
  ts: string;
  session_id?: string;
  action_id?: number;
  tool?: string;
  event_kind?: string;
  rule_id: string;
  category?: string;
  severity?: string;
  decision?: string;
  degraded_from?: string;
  enforced: boolean;
  source?: string;
  reason?: string;
  target_excerpt?: string;
  taint_origin?: string;
  // Org-granted override posture of this row's RULE under the org
  // policy bundle currently on disk (Track B). Absent on an
  // un-enrolled node and on older daemons.
  overridable?: boolean;
  org_locked?: boolean;
};

type GuardEventsResponse = { events: GuardEvent[] | null; count: number };

type ConformanceEntry = {
  client: string;
  channel: string;
  pre_execution: boolean;
  can_block: boolean;
  can_ask: boolean;
  notes: string;
};

type ConformanceResponse = { entries: ConformanceEntry[] | null };

// GuardRule / GuardRulesResponse now live in @/lib/types (shared with the
// new RuleManager.tsx structured editor — see the import above).

// GuardSimulate is GET /api/guard/simulate — the pre-enforce evidence
// replay (G1.2). would_block counts deny/ask-class verdicts under the
// enforce projection; by_rule_blocking (G2.1) splits that count per
// rule (by_rule alone conflates flag-only noise with blocking load).
type GuardSimulate = {
  window_hours: number;
  mode: string;
  scanned: number;
  verdicts: number;
  would_block: number;
  capped: boolean;
  by_rule: Record<string, number> | null;
  by_rule_blocking?: Record<string, number> | null;
  by_decision: Record<string, number> | null;
};

// GuardApproval is one §6.3 exception-register row (G1.3).
type GuardApproval = {
  id: number;
  ts: string;
  rule_id: string;
  scope: string;
  session_id?: string;
  project_root_hash?: string;
  granted_by?: string;
  expires_at?: string;
};

type GuardApprovalsResponse = { approvals: GuardApproval[] | null };

// GuardMCPServer is one §9 MCP-inventory row (G1.6).
type GuardMCPServer = {
  client: string;
  name: string;
  transport?: string;
  status: string;
  tools_seen: boolean;
  command?: string;
  present: boolean;
};

type GuardMCPResponse = { servers: GuardMCPServer[] | null; issues: string[] | null };

// GuardPolicyLayer / GuardPolicyView / GuardPolicyLint now live in
// @/lib/types (extended for the trusted_project layer — see the import
// above); RuleManager.tsx and PolicyLayersCard below share them.

// ApproveSeed hands a verdict row to the Approvals card's grant form
// ("approve…" on a timeline row pre-fills rule + session).
type ApproveSeed = { rule: string; session: string };

type SeverityFilter = "all" | "warn" | "high" | "critical";
type DecisionFilter = "all" | "flag" | "ask" | "deny";
type WindowFilter = "24" | "168" | "720";

export function SecurityPage() {
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [decision, setDecision] = useState<DecisionFilter>("all");
  const [hours, setHours] = useState<WindowFilter>("168");
  const [ruleFilter, setRuleFilter] = useState("");
  const [sessionFilter, setSessionFilter] = useState("");
  const [approveSeed, setApproveSeed] = useState<ApproveSeed | null>(null);

  const summary = useApi<GuardSummary>("/api/guard/summary");
  const events = useApi<GuardEventsResponse>(
    "/api/guard/events",
    {
      hours,
      severity: severity === "all" ? undefined : severity,
      decision: decision === "all" ? undefined : decision,
      rule_id: ruleFilter || undefined,
      session_id: sessionFilter || undefined,
      limit: 200,
    },
    [hours, severity, decision, ruleFilter, sessionFilter],
  );
  const conformance = useApi<ConformanceResponse>("/api/guard/conformance");
  // effective=1 (G1.5): the install's real table — overrides applied,
  // disabled rules removed, user/project/org rules included with their
  // source — so custom-rule verdicts resolve too. Older daemons ignore
  // the param and serve the built-in catalog (graceful).
  const rulesApi = useApi<GuardRulesResponse>("/api/guard/rules", { effective: 1 });
  const approvals = useApi<GuardApprovalsResponse>("/api/guard/approvals");
  // Lifted here (rather than fetched inside RuleManager/PolicyLayersCard
  // separately) so the structured rule manager and the raw-TOML advanced
  // editor below it share ONE /api/guard/policy read — a save in either one
  // reloads the same ApiState the other reads from.
  const policyApi = useApi<GuardPolicyView>("/api/guard/policy");
  const projectsApi = useApi<ProjectsResponse>("/api/projects");

  // rule_id → catalog rows, so the timeline can show each verdict's
  // actual definition instead of a bare "R-151". Unknown IDs (user/
  // project/org layer rules, or an older daemon without the endpoint)
  // degrade to the bare mono ID.
  const ruleDefs = useMemo(() => {
    const m = new Map<string, GuardRule[]>();
    for (const r of rulesApi.data?.rules ?? []) {
      const list = m.get(r.id) ?? [];
      list.push(r);
      m.set(r.id, list);
    }
    return m;
  }, [rulesApi.data]);

  const sum = summary.data;
  const rows = events.data?.events ?? [];
  const matrix = conformance.data?.entries ?? [];
  const hookRows = matrix.filter((e) => e.channel !== "watcher");
  const watcherCount = matrix.filter((e) => e.channel === "watcher").length;

  // Top noisy rules over the LOADED window rows (≤ the fetch limit) —
  // a drill-down affordance, not an exact census; clicking one filters
  // the timeline server-side.
  const topRules = useMemo(() => {
    if (ruleFilter) return [];
    const counts = new Map<string, number>();
    for (const ev of rows) counts.set(ev.rule_id, (counts.get(ev.rule_id) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [rows, ruleFilter]);

  // Verdict timeline columns. Rebuilt per render: the rule cell reads the
  // catalog map and the session cell's buttons set this page's filters.
  // Rows arrive newest first; a header click re-sorts (When sorts by the
  // raw timestamp, not the clock label).
  const verdictColumns: ColumnDef<GuardEvent, unknown>[] = [
    {
      id: "when",
      header: "When",
      accessorFn: (ev) => new Date(ev.ts).getTime(),
      cell: ({ row }) => <span className="whitespace-nowrap text-fg-3">{fmtClock(row.original.ts)}</span>,
    },
    {
      id: "rule",
      header: "Rule",
      accessorKey: "rule_id",
      cell: ({ row }) => (
        <RuleCell
          id={row.original.rule_id}
          category={row.original.category}
          defs={ruleDefs.get(row.original.rule_id)}
          compact
        />
      ),
    },
    {
      id: "decision",
      header: "Decision",
      accessorFn: (ev) => ev.decision ?? "",
      cell: ({ row }) => {
        const ev = row.original;
        return (
          <>
            <VocabPill vocab="guardDecision" value={ev.decision} tone={decisionTone(ev.decision)}>
              {ev.decision}
              {ev.enforced && <Icon icon={Check} size={10} label="enforced" />}
            </VocabPill>
            {ev.degraded_from && (
              <Pill
                variant="neutral"
                className="ml-1"
                title={`The verdict wanted ${ev.degraded_from} but this channel cannot express it (§6.2 degradation - recorded, never silent).`}
              >
                from {ev.degraded_from}
              </Pill>
            )}
          </>
        );
      },
    },
    {
      id: "severity",
      header: "Severity",
      accessorFn: (ev) => ev.severity ?? "",
      cell: ({ row }) => (
        <VocabPill vocab="guardSeverity" value={row.original.severity} tone={severityTone(row.original.severity)} />
      ),
    },
    {
      id: "tool",
      header: "Tool",
      accessorFn: (ev) => ev.tool ?? "",
      cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{row.original.tool || "-"}</span>,
    },
    {
      id: "target",
      header: "Target",
      enableSorting: false,
      cell: ({ row }) => (
        <span
          className="block max-w-[200px] truncate font-mono text-[11px] text-fg-2"
          title={row.original.target_excerpt}
        >
          {row.original.target_excerpt || "-"}
        </span>
      ),
    },
    {
      id: "reason",
      header: "Reason",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="block max-w-[420px] text-fg-2">
          {row.original.reason}
          {row.original.taint_origin && (
            <span className="ml-1.5 text-[10.5px] text-fg-3">taint: {row.original.taint_origin}</span>
          )}
        </span>
      ),
    },
    {
      id: "session",
      header: "Session",
      enableSorting: false,
      cell: ({ row }) => {
        const ev = row.original;
        if (!ev.session_id) return <span className="text-fg-3">-</span>;
        return (
          // Wraps (id first, then the two row actions) rather than forcing
          // the eight-column table past the card width at desktop sizes.
          <span className="inline-flex flex-wrap items-center gap-1">
            <CopyOnClick
              value={ev.session_id}
              title={
                <>
                  Copy the full session id{" "}
                  <span className="break-all font-mono">{ev.session_id}</span>
                </>
              }
            >
              <Link
                // Deep-links straight to the Messages tab (LOC/guardmsg/APM
                // followups plan Item 2.4): that verdict's session drawer now
                // interleaves this exact rule's block into its timeline, so a
                // reviewer following this link from the global verdict table
                // lands where the block actually happened, not on Overview.
                to={`/sessions?session=${encodeURIComponent(ev.session_id)}&tab=messages`}
                className="font-mono text-[10.5px] text-accent underline decoration-dotted decoration-accent/50 underline-offset-[3px] hover:decoration-accent"
              >
                {fmtShortId(ev.session_id, 8)}
              </Link>
            </CopyOnClick>
            <Tooltip content="Filter the timeline to this session">
              <button
                type="button"
                className={miniBtn}
                onClick={() => setSessionFilter(ev.session_id ?? "")}
              >
                filter
              </button>
            </Tooltip>
            <Tooltip content="Grant a scoped exception for this rule (pre-fills the Approvals form)">
              <button
                type="button"
                className={miniBtn}
                onClick={() => setApproveSeed({ rule: ev.rule_id, session: ev.session_id ?? "" })}
              >
                approve…
              </button>
            </Tooltip>
          </span>
        );
      },
    },
  ];

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("security")}
        title="Security"
        helpId="tab.security"
        sub="The guard layer's verdicts over your agents' actions: what was flagged, what was blocked, which channels can enforce at all, and whether the audit chain is intact. Local, deterministic, observe-first."
      />

      <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <HeroStat
          label="Guard posture"
          helpId="tile.security.posture"
          icon={<MetricIcon metric="guardPosture" />}
          loading={summary.loading}
          value={sum ? (sum.enabled ? sum.mode : "disabled") : "-"}
          sub={
            sum
              ? sum.strict
                ? "strict: internal errors fail closed"
                : "fail-open: internal errors never block"
              : undefined
          }
          variant={sum && sum.enabled && sum.mode === "enforce" ? "danger" : "accent"}
        />
        <HeroStat
          label="Verdicts - last 24h"
          icon={<MetricIcon metric="verdicts" />}
          helpId="tile.security.verdicts"
          loading={summary.loading}
          stale={summary.isStale}
          value={sum ? String(sum.counts_24h.total) : "-"}
          sub={sum ? `${sum.counts_24h.enforced} enforced (blocked or deferred)` : undefined}
          variant={sum && sum.counts_24h.total > 0 ? "warn" : "accent"}
        />
        <HeroStat
          label="Verdicts - last 7d"
          icon={<MetricIcon metric="verdicts" />}
          helpId="tile.security.verdicts"
          loading={summary.loading}
          stale={summary.isStale}
          value={sum ? String(sum.counts_7d.total) : "-"}
          sub={sum ? severitySub(sum.counts_7d) : undefined}
          variant="accent"
        />
        <HeroStat
          label="Audit chain"
          icon={<MetricIcon metric={sum && !sum.chain.ok ? "auditChainBroken" : "auditChain"} />}
          helpId="tile.security.audit_chain"
          loading={summary.loading}
          stale={summary.isStale}
          value={sum ? (sum.chain.ok ? "intact" : "BROKEN") : "-"}
          sub={
            sum
              ? sum.chain.ok
                ? `${sum.chain.checked} rows verified (tamper-evident, SHA-256 chained)`
                : `first divergence at id ${sum.chain.divergence_id} - run observer guard verify-audit`
              : undefined
          }
          variant={sum && !sum.chain.ok ? "danger" : "accent"}
        />
      </Stagger>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <GuardModeCard sum={sum} loading={summary.loading} />
        <ApprovalsCard
          api={approvals}
          ruleDefs={ruleDefs}
          seed={approveSeed}
          onSeedConsumed={() => setApproveSeed(null)}
        />
      </div>

      <EnforceReadinessCard
        sum={sum}
        ruleDefs={ruleDefs}
        onFilterRule={setRuleFilter}
        onApprove={setApproveSeed}
      />

      <GuardBudgetCard />

      {/* Org-granted override (Track B). Renders nothing unless an
          org policy bundle is active on this node. */}
      <GuardOverrideCard />

      <PromptGuardCard />

      <ChartShell
        title={<TitleWithHelp text="Verdict timeline" helpId="chart.security_timeline" />}
        icon={SECURITY_SECTION_ICONS.verdictTimeline}
        right={
          <div className="flex flex-wrap items-center gap-2">
            <SegmentedControl<WindowFilter>
              size="sm"
              options={[
                { value: "24", label: "24h" },
                { value: "168", label: "7d" },
                { value: "720", label: "30d" },
              ]}
              value={hours}
              onChange={setHours}
            />
            <SegmentedControl<SeverityFilter>
              size="sm"
              options={[
                { value: "all", label: "All severities" },
                { value: "warn", label: "Warn" },
                { value: "high", label: "High" },
                { value: "critical", label: "Critical" },
              ]}
              value={severity}
              onChange={setSeverity}
            />
            <SegmentedControl<DecisionFilter>
              size="sm"
              options={[
                { value: "all", label: "All decisions" },
                { value: "flag", label: "Flag" },
                { value: "ask", label: "Ask" },
                { value: "deny", label: "Deny" },
              ]}
              value={decision}
              onChange={setDecision}
            />
          </div>
        }
      >
        {(ruleFilter || sessionFilter) && (
          <div className="mb-3 flex flex-wrap items-center gap-2 text-caption">
            <span className="text-fg-3">Filtered to</span>
            {ruleFilter && (
              <Tooltip content="Clear the rule filter">
                <button
                  type="button"
                  className="inline-flex items-center gap-1 rounded-2 border border-accent/40 bg-bg-3 px-2 py-0.5 font-mono text-accent hover:border-accent"
                  onClick={() => setRuleFilter("")}
                >
                  {ruleFilter} <Icon icon={X} size={10} label="clear" />
                </button>
              </Tooltip>
            )}
            {sessionFilter && (
              <Tooltip content={`Clear the session filter (${sessionFilter})`}>
                <button
                  type="button"
                  className="inline-flex items-center gap-1 rounded-2 border border-accent/40 bg-bg-3 px-2 py-0.5 font-mono text-accent hover:border-accent"
                  onClick={() => setSessionFilter("")}
                >
                  session {fmtShortId(sessionFilter, 8)} <Icon icon={X} size={10} label="clear" />
                </button>
              </Tooltip>
            )}
          </div>
        )}
        {topRules.length > 1 && (
          <div className="mb-3 flex flex-wrap items-center gap-1.5 text-caption">
            <span className="text-fg-3">Top rules in this window:</span>
            {topRules.map(([rule, n]) => (
              <Tooltip key={rule} content={`Filter the timeline to ${rule}`}>
                <button
                  type="button"
                  className="rounded-2 border border-line-2 bg-bg-3 px-2 py-0.5 font-mono text-fg-2 hover:border-line-3 hover:text-fg-0"
                  onClick={() => setRuleFilter(rule)}
                >
                  {rule} <span className="text-fg-3">{n}</span>
                </button>
              </Tooltip>
            ))}
          </div>
        )}
        {events.loading ? (
          <InlineLoading label="Loading guard events" block />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="inline"
            illustration="all-clear"
            title="No guard verdicts in this window"
            body={
              <>
                The rules stayed quiet. Try{" "}
                <code className="rounded-1 bg-bg-3 px-1">observer guard test "git push --force origin main"</code>{" "}
                to see a verdict end to end.
              </>
            }
          />
        ) : (
          <DataTable<GuardEvent>
            data={rows}
            columns={verdictColumns}
            rowKey={(ev) => String(ev.id)}
            minWidth={1000}
            zebra
            rowClassName={() => "align-top"}
          />
        )}
      </ChartShell>

      <ChartShell
        title={<TitleWithHelp text="Enforcement coverage" helpId="chart.security_coverage" />}
        icon={SECURITY_SECTION_ICONS.enforcementCoverage}
        sub={
          <>
            Which channels can actually block before execution vs flag after the fact. Hooks see
            declared tool calls; the watcher sees results - {watcherCount} adapters are covered
            post-hoc, and that asymmetry is structural, not a configuration gap.
          </>
        }
      >
        {conformance.loading ? (
          <InlineLoading label="Loading hook conformance" block />
        ) : (
          // The watcher row spans Client + Channel, so this is the shared
          // Table primitive rather than DataTable.
          <Table
            minWidth={640}
            head={
              <tr>
                <th className="py-1.5 pr-3 font-medium">Client</th>
                <th className="py-1.5 pr-3 font-medium">Channel</th>
                <th className="py-1.5 pr-3 font-medium">Pre-exec</th>
                <th className="py-1.5 pr-3 font-medium">Can block</th>
                <th className="py-1.5 pr-3 font-medium">Can ask</th>
                <th className="py-1.5 font-medium">Notes</th>
              </tr>
            }
          >
            {hookRows.map((e) => (
              <ConformanceRow key={e.client + e.channel} e={e} />
            ))}
            <tr className="border-b border-line-1/60 last:border-0">
              <td className="py-1.5 pr-3 text-fg-2" colSpan={2}>
                every adapter ({watcherCount}) · watcher
              </td>
              <td className="py-1.5 pr-3"><BoolPill v={false} /></td>
              <td className="py-1.5 pr-3"><BoolPill v={false} /></td>
              <td className="py-1.5 pr-3"><BoolPill v={false} /></td>
              <td className="py-1.5 text-fg-3">
                post-hoc flagging; sees results (file changes, outputs) hooks structurally miss
              </td>
            </tr>
          </Table>
        )}
      </ChartShell>

      <RuleManager rulesApi={rulesApi} policyApi={policyApi} projects={projectsApi.data?.rows ?? []} />

      <PolicyLayersCard api={policyApi} />

      <EvidenceCard />

      {/* Agent Access P10: node MCP relay status, approved servers,
          coverage matrix and effective state. */}
      <MCPAccessSection />

      <MCPPinsCard />
    </div>
  );
}

// EvidenceJob mirrors the shared job-registry row the evidence
// buttons poll (/api/backfill/jobs/<id> — same registry as backfill
// Run-Now, mode "guard:<kind>").
type EvidenceJob = {
  id: string;
  mode: string;
  status: string;
  output: string;
  error?: string;
  out_file?: string;
};

const EVIDENCE_PERIODS: { value: string; label: string }[] = [
  { value: "24h", label: "24h" },
  { value: "168h", label: "7d" },
  { value: "720h", label: "30d" },
  { value: "2160h", label: "90d" },
  { value: "8760h", label: "1y" },
];

// EvidenceCard — the G2.3 compliance-evidence buttons: `observer
// guard report` (the §14.4 pack), `guard export` (SIEM jsonl/cef) and
// `guard verify-audit`, each running as an async job (the shared
// registry — the page never blocks) with a download link when done.
// File-based and pull-based like the CLI: nothing leaves the machine.
function EvidenceCard() {
  const [period, setPeriod] = useState("720h");
  const [format, setFormat] = useState<"jsonl" | "cef">("jsonl");
  const [minSeverity, setMinSeverity] = useState("");
  const [job, setJob] = useState<EvidenceJob | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!job || job.status !== "running") return;
    const t = setInterval(() => {
      fetchJSON<EvidenceJob>(`/api/backfill/jobs/${job.id}`)
        .then(setJob)
        .catch(() => {
          // Poll errors are transient (daemon restart mid-job loses
          // the in-memory registry); keep polling until unmount.
        });
    }, 1000);
    return () => clearInterval(t);
  }, [job]);

  const run = async (kind: "report" | "export" | "verify-audit") => {
    setBusy(true);
    setError("");
    try {
      const r = await fetchJSON<{ job_id: string }>("/api/guard/evidence", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind, period, format, min_severity: minSeverity }),
      });
      setJob({ id: r.job_id, mode: `guard:${kind}`, status: "running", output: "" });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const running = job?.status === "running";

  return (
    <ChartShell
      title={<TitleWithHelp text="Compliance evidence" helpId="card.security_evidence" />}
      icon={SECURITY_SECTION_ICONS.complianceEvidence}
      sub={
        <>
          The auditor-shaped outputs: the §14.4 evidence pack (policy state, change log, verdict
          stats, chain verification, exception register), a SIEM export of the audit rows, and the
          full tamper-evidence chain walk. File-based and pull-based - nothing leaves this machine.
        </>
      }
    >
      <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
        <span className="text-fg-3">Window:</span>
        <select
          className={selectCls}
          value={period}
          onChange={(e) => setPeriod(e.target.value)}
        >
          {EVIDENCE_PERIODS.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
        </select>
        <button type="button" className={actionBtn} disabled={busy || running} onClick={() => run("report")}>
          Report
        </button>
        <span className="ml-2 text-fg-3">Export:</span>
        <select
          className={selectCls}
          value={format}
          onChange={(e) => setFormat(e.target.value as "jsonl" | "cef")}
        >
          <option value="jsonl">jsonl</option>
          <option value="cef">cef</option>
        </select>
        <select
          className={selectCls}
          value={minSeverity}
          onChange={(e) => setMinSeverity(e.target.value)}
        >
          <option value="">all severities</option>
          <option value="info">info+</option>
          <option value="warn">warn+</option>
          <option value="high">high+</option>
          <option value="critical">critical</option>
        </select>
        <button type="button" className={actionBtn} disabled={busy || running} onClick={() => run("export")}>
          Export
        </button>
        <Tooltip content="Walk the full guard_events hash chain (observer guard verify-audit)">
          <button
            type="button"
            className={`${actionBtn} ml-2`}
            disabled={busy || running}
            onClick={() => run("verify-audit")}
          >
            Verify audit chain
          </button>
        </Tooltip>
      </div>
      {job && (
        <div className="mt-3 rounded-2 border border-line-2 bg-bg-3 p-3 text-[11.5px]">
          <div className="flex flex-wrap items-center gap-2">
            <code className="font-mono text-[10.5px] text-fg-3">{job.mode}</code>
            <VocabPill vocab="jobStatus" table={JOB_STATUS} value={job.status} />
            {job.status !== "running" && (
              <a
                className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-caption text-accent hover:border-line-3"
                href={`/api/guard/evidence/download?job=${encodeURIComponent(job.id)}`}
                download
              >
                Download {job.out_file ? job.out_file.split(/[\\/]/).pop() : "output"}
              </a>
            )}
            {job.out_file && job.status === "done" && (
              <span className="font-mono text-[10.5px] text-fg-3" title={job.out_file}>
                saved to {job.out_file}
              </span>
            )}
          </div>
          {job.error && (
            <div className="mt-1.5 text-danger">
              {job.error}
              {job.mode === "guard:verify-audit"
                ? " - a non-zero exit from verify-audit means the chain walk found a divergence; the output below is the evidence."
                : ""}
            </div>
          )}
          {job.output && (
            <pre className="mt-1.5 max-h-48 overflow-auto whitespace-pre-wrap font-mono text-[10.5px] leading-relaxed text-fg-2">
              {job.output}
            </pre>
          )}
        </div>
      )}
      {error && <div className="mt-2 text-[11.5px] text-danger">{error}</div>}
    </ChartShell>
  );
}

// MCPPinsCard — the §9 MCP server inventory (G1.6): every configured
// MCP server across supported clients, joined with its pin status.
// Approving re-marks the pin trusted (its results stop carrying
// mcp_unpinned taint); a later definition change still raises R-302.
function MCPPinsCard() {
  const api = useApi<GuardMCPResponse>("/api/guard/mcp");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const servers = api.data?.servers ?? [];
  const issues = api.data?.issues ?? [];

  const approve = async (name: string, client: string) => {
    setBusy(true);
    setError("");
    try {
      await fetchJSON("/api/guard/mcp/approve", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server: name, client }),
      });
      api.reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // Rebuilt per render: the approve button reads busy + approve().
  const mcpColumns: ColumnDef<GuardMCPServer, unknown>[] = [
    {
      id: "client",
      header: "Client",
      accessorKey: "client",
      cell: ({ row }) => <span className="text-fg-2">{row.original.client}</span>,
    },
    {
      id: "server",
      header: "Server",
      accessorKey: "name",
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-fg-1">
          {row.original.name}
          {!row.original.present && (
            <span className="ml-1.5 text-[10px] text-fg-3">(pinned, absent from config)</span>
          )}
        </span>
      ),
    },
    {
      id: "status",
      header: "Status",
      accessorKey: "status",
      cell: ({ row }) => <Pill variant={toneOf(MCP_PIN_TONE, row.original.status)}>{row.original.status}</Pill>,
    },
    {
      id: "command",
      header: "Command",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="block max-w-[340px] truncate font-mono text-[10.5px] text-fg-3" title={row.original.command}>
          {row.original.command || "-"}
        </span>
      ),
    },
    {
      id: "action",
      header: "",
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => {
        const sv = row.original;
        if (sv.status === "approved" || !sv.present) return null;
        return (
          <Tooltip content="Trust this server: its results stop marking mcp_unpinned taint (observer guard mcp approve)">
            <button type="button" className={actionBtn} disabled={busy} onClick={() => approve(sv.name, sv.client)}>
              Approve
            </button>
          </Tooltip>
        );
      },
    },
  ];

  return (
    <ChartShell
      title={<TitleWithHelp text="MCP servers" helpId="card.security_mcp_pins" />}
      icon={SECURITY_SECTION_ICONS.mcpServers}
      sub={
        <>
          Every MCP server found in your AI clients' configs, pinned by definition hash. New or
          changed servers mark their results as untrusted (taint) until approved; rug-pull and
          poisoning checks (R-301…R-305) run against this inventory.
        </>
      }
    >
      {api.loading ? (
        <InlineLoading label="Loading MCP servers" block />
      ) : servers.length === 0 ? (
        <div className="py-4 text-[11.5px] text-fg-3">
          No MCP servers found in any supported client config - nothing to pin.
        </div>
      ) : (
        <DataTable<GuardMCPServer>
          data={servers}
          columns={mcpColumns}
          rowKey={(sv) => `${sv.client}/${sv.name}`}
          minWidth={620}
        />
      )}
      {issues.length > 0 && (
        <div className="mt-2 space-y-0.5 text-[11px] text-fg-3">
          {issues.map((iss, i) => (
            <div key={i}>ISSUE: {iss}</div>
          ))}
        </div>
      )}
      {error && <div className="mt-2 text-[11.5px] text-danger">{error}</div>}
    </ChartShell>
  );
}

// RuleCell renders a verdict's rule as its actual catalog definition
// (doc one-liner primary, mono ID + category secondary) with the full
// per-row breakdown — severity, observe/enforce decisions, remediation
// advice — in a hover tooltip. Falls back to the bare mono ID when the
// catalog has no entry for it. Exported for RuleManager.tsx's structured
// rule list, which reuses it verbatim rather than a second cell renderer.
export function RuleCell({
  id,
  category,
  defs,
  compact,
}: {
  id: string;
  category?: string;
  defs?: GuardRule[];
  // compact narrows the doc line's truncation budget, for the wide
  // eight-column verdict timeline where every column competes for width.
  compact?: boolean;
}) {
  if (!defs || defs.length === 0) {
    return (
      <>
        <span className="font-mono text-fg-1">{id}</span>
        {category && <span className="ml-1.5 text-[10.5px] text-fg-3">{category}</span>}
      </>
    );
  }
  return (
    <Tooltip
      maxWidth={380}
      content={
        <span className="block">
          {defs.map((d, i) => (
            <span key={i} className="mb-1.5 block last:mb-0">
              {d.doc}
              <span className="block text-fg-3">
                {d.severity} · observe → {d.observe} · enforce → {d.enforce}
                {d.enforced ? " · per-rule enforced" : ""}
              </span>
              {d.source && d.source !== "builtin" && (
                <span className="block text-fg-3">defined in the {d.source} policy layer</span>
              )}
              {d.advice && <span className="block text-fg-3">{d.advice}</span>}
            </span>
          ))}
        </span>
      }
    >
      <span className="inline-block cursor-help">
        <span className={clsx("block truncate text-fg-1", compact ? "max-w-[220px]" : "max-w-[280px]")}>{defs[0].doc}</span>
        <span className="block font-mono text-[10.5px] text-fg-3">
          {id}
          {category ? ` · ${category}` : ""}
        </span>
      </span>
    </Tooltip>
  );
}

function ConformanceRow({ e }: { e: ConformanceEntry }) {
  return (
    <tr className="border-b border-line-1/60 last:border-0">
      <td className="py-1.5 pr-3 text-fg-1">{e.client}</td>
      <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">{e.channel}</td>
      <td className="py-1.5 pr-3"><BoolPill v={e.pre_execution} /></td>
      <td className="py-1.5 pr-3"><BoolPill v={e.can_block} /></td>
      <td className="py-1.5 pr-3"><BoolPill v={e.can_ask} /></td>
      <td className="max-w-[480px] py-1.5 text-fg-3">{e.notes}</td>
    </tr>
  );
}

function BoolPill({ v }: { v: boolean }) {
  return <Pill variant={v ? "success" : "neutral"}>{v ? "yes" : "no"}</Pill>;
}

function severitySub(c: GuardCounts): string | undefined {
  const sev = c.by_severity ?? {};
  const parts: string[] = [];
  for (const k of ["critical", "high", "warn", "info"]) {
    if (sev[k]) parts.push(`${sev[k]} ${k}`);
  }
  return parts.length ? parts.join(" · ") : undefined;
}

type GuardMode = "off" | "observe" | "enforce";

// Controls sit inside bg-bg-2 section cards, so they fill with bg-bg-3 (bg-bg-1
// equals bg-bg-2 in the light theme and the control would vanish).
const actionBtn =
  "rounded-2 border border-line-2 bg-bg-3 px-2.5 py-1 text-caption text-fg-1 hover:border-line-3 hover:text-fg-0 disabled:opacity-50";

// The small uppercase row actions in the verdict / readiness tables.
const miniBtn =
  "rounded-1 border border-line-2 bg-bg-3 px-1 text-[9.5px] uppercase tracking-wide text-fg-3 hover:border-line-3 hover:text-fg-1";

// Selects and short inputs inside a section card.
const selectCls = "rounded-2 border border-line-2 bg-bg-3 px-2 py-1 text-caption text-fg-1";

// MCP pin status -> tone (unknown status stays neutral).
const MCP_PIN_TONE: Readonly<Record<string, Tone>> = {
  approved: "success",
  unpinned: "warn",
  changed: "warn",
};

// GuardModeCard — the G1.2 consent-gated mode control. Selecting a
// target mode shows what the change means; selecting ENFORCE first
// fetches the simulate evidence ("what would last week have blocked")
// so the operator promotes with eyes open. The write rides the one
// config seam (PUT /api/config/section/guard) and is restart-honest:
// the RUNNING daemon keeps its mode until restarted, so the card
// reports "saved — restart to apply" and feeds the restart banner.
function GuardModeCard({ sum, loading }: { sum: GuardSummary | null; loading: boolean }) {
  const current: GuardMode = sum ? (sum.enabled ? (sum.mode as GuardMode) : "off") : "observe";
  const [target, setTarget] = useState<GuardMode | null>(null);
  const [evidence, setEvidence] = useState<GuardSimulate | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedAs, setSavedAs] = useState<GuardMode | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setEvidence(null);
    setError("");
    if (target !== "enforce") return;
    let cancelled = false;
    setEvidenceLoading(true);
    fetchJSON<GuardSimulate>("/api/guard/simulate", { hours: 168, enforce: 1 })
      .then((r) => {
        if (!cancelled) setEvidence(r);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!cancelled) setEvidenceLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [target]);

  const confirm = async () => {
    if (!target) return;
    setSaving(true);
    setError("");
    try {
      // Whole-section write through the one config seam: take the
      // on-disk Guard section, flip mode/enabled, PUT it back. Cloud
      // + org-bundle + CEL survive server-side regardless.
      const cfg = await fetchJSON<{ config: { Guard: Record<string, unknown> } }>("/api/config");
      const guardSec = { ...cfg.config.Guard, Mode: target, Enabled: target !== "off" };
      await fetchJSON("/api/config/section/guard", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(guardSec),
      });
      markRestartPending("guard");
      setSavedAs(target);
      setTarget(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const topEvidence = useMemo(() => {
    if (!evidence?.by_rule) return [];
    return Object.entries(evidence.by_rule)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [evidence]);

  return (
    <ChartShell
      title={<TitleWithHelp text="Mode" helpId="card.security_mode" />}
      icon={SECURITY_SECTION_ICONS.mode}
      sub={
        <>
          observe records and alerts but never blocks; enforce lets deny/ask-class rules actually
          block at the hook and proxy seams. Changes bind at daemon start.
        </>
      }
    >
      {loading ? (
        <InlineLoading label="Loading guard mode" block />
      ) : (
        <div className="space-y-3 text-[11.5px]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-fg-3">Running:</span>
            <VocabPill vocab="guardMode" table={POLICY_MODE} value={current} />
            {savedAs && savedAs !== current && (
              <Pill variant="warn">saved: {savedAs} - restart the daemon to apply</Pill>
            )}
            <span className="ml-auto">
              <SegmentedControl<GuardMode>
                size="sm"
                options={[
                  { value: "off", label: "Off" },
                  { value: "observe", label: "Observe" },
                  { value: "enforce", label: "Enforce" },
                ]}
                value={target ?? (savedAs ?? current)}
                onChange={(m) => setTarget(m === current && !savedAs ? null : m)}
              />
            </span>
          </div>
          {target && target !== current && (
            <div className="rounded-2 border border-line-2 bg-bg-3 p-3">
              {target === "enforce" ? (
                evidenceLoading ? (
                  <div className="text-fg-3">Replaying your last 7 days against today's rules…</div>
                ) : evidence ? (
                  <div className="space-y-1.5">
                    <div className="text-fg-1">
                      In the last 7 days, enforce would have{" "}
                      <strong className="font-semibold">
                        blocked or deferred {evidence.would_block}
                      </strong>{" "}
                      of {evidence.scanned.toLocaleString()} captured actions
                      {evidence.capped ? " (50k replay cap hit - partial window)" : ""}.
                    </div>
                    {topEvidence.length > 0 && (
                      <div className="text-fg-3">
                        Top rules:{" "}
                        {topEvidence.map(([r, n], i) => (
                          <span key={r} className="font-mono">
                            {i > 0 ? " · " : ""}
                            {r}×{n}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="text-fg-3">
                      Blocked actions return a machine-readable reason the agent can react to.
                      Scoped exceptions (Approvals) downgrade a block to a flag without a policy
                      edit. You can switch back to observe at any time.
                    </div>
                  </div>
                ) : (
                  <div className="text-fg-3">Evidence unavailable{error ? `: ${error}` : ""} - you can still proceed.</div>
                )
              ) : target === "observe" ? (
                <div className="text-fg-3">
                  Verdicts keep recording and alerting; nothing blocks. The safe default.
                </div>
              ) : (
                <div className="text-fg-3">
                  Guard fully off: no policy engine, no new verdicts, the Security page goes
                  quiet. Existing audit rows are kept.
                </div>
              )}
              <div className="mt-2 flex items-center gap-2">
                <button
                  type="button"
                  className={actionBtn}
                  disabled={saving || (target === "enforce" && evidenceLoading)}
                  onClick={confirm}
                >
                  {saving ? "Saving…" : `Set mode to ${target}`}
                </button>
                <button type="button" className={actionBtn} onClick={() => setTarget(null)}>
                  Cancel
                </button>
              </div>
            </div>
          )}
          {error && !target && <div className="text-danger">{error}</div>}
        </div>
      )}
    </ChartShell>
  );
}

// EnforceReadinessCard - the G2.1 observe→enforce migration evidence,
// the dashboard face of docs/guard-enforce-runbook.md. Click-to-run
// (a 50k-row replay is too heavy to fire on every page view): replays
// the chosen window against today's on-disk policy under the enforce
// projection (GET /api/guard/simulate — dry run, nothing persists)
// and renders what to review before flipping the Mode card. Evidence,
// not a verdict — there is no fake pass/fail gate; the promotion
// stays operator-judged.
function EnforceReadinessCard({
  sum,
  ruleDefs,
  onFilterRule,
  onApprove,
}: {
  sum: GuardSummary | null;
  ruleDefs: Map<string, GuardRule[]>;
  onFilterRule: (rule: string) => void;
  onApprove: (seed: ApproveSeed) => void;
}) {
  const [hours, setHours] = useState<"168" | "720">("168");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<GuardSimulate | null>(null);
  const [error, setError] = useState("");

  const run = async () => {
    setBusy(true);
    setError("");
    try {
      setResult(await fetchJSON<GuardSimulate>("/api/guard/simulate", { hours, enforce: 1 }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const enforceLive = !!sum && sum.enabled && sum.mode === "enforce";
  const days = result ? Math.max(1, Math.round(result.window_hours / 24)) : 1;
  const denies = result?.by_decision?.["deny"] ?? 0;
  const asks = result?.by_decision?.["ask"] ?? 0;

  const topBlocking = useMemo(() => {
    if (!result?.by_rule_blocking) return [];
    return Object.entries(result.by_rule_blocking)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [result]);

  const topShare =
    result && result.would_block > 0 && topBlocking.length > 0
      ? topBlocking[0][1] / result.would_block
      : 0;

  // Top would-block rules, heaviest first; Would block and Share sort by
  // the raw count. Rebuilt per render (the buttons call the page's filter
  // and approve seeds).
  const wouldBlock = result?.would_block ?? 0;
  const blockingColumns: ColumnDef<[string, number], unknown>[] = [
    {
      id: "rule",
      header: "Rule",
      accessorFn: ([rule]) => rule,
      cell: ({ row }) => <RuleCell id={row.original[0]} defs={ruleDefs.get(row.original[0])} />,
    },
    {
      id: "would_block",
      header: "Would block",
      accessorFn: ([, n]) => n,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-1">{row.original[1].toLocaleString()}</span>,
    },
    {
      id: "share",
      header: "Share",
      accessorFn: ([, n]) => n,
      meta: { align: "right" },
      cell: ({ row }) => (
        <span className="text-fg-3">
          {wouldBlock > 0 ? `${Math.round((row.original[1] / wouldBlock) * 100)}%` : "-"}
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => {
        const rule = row.original[0];
        return (
          <span className="inline-flex items-center gap-1">
            <Tooltip content="Filter the verdict timeline to this rule">
              <button type="button" className={miniBtn} onClick={() => onFilterRule(rule)}>
                filter
              </button>
            </Tooltip>
            <Tooltip content="Grant a scoped exception for this rule (pre-fills the Approvals form)">
              <button type="button" className={miniBtn} onClick={() => onApprove({ rule, session: "" })}>
                approve…
              </button>
            </Tooltip>
          </span>
        );
      },
    },
  ];

  return (
    <ChartShell
      title={<TitleWithHelp text="Enforce readiness" helpId="card.security_enforce_readiness" />}
      icon={SECURITY_SECTION_ICONS.enforceReadiness}
      sub={
        <>
          {enforceLive
            ? "Enforce is live - this replay shows what today's on-disk policy blocks; useful after a policy edit, before the restart."
            : "The observe → enforce migration in one place: replay your real history against today's rules, review what would block, tune the noise, then flip the Mode card. Dry run - nothing persists, the live guard is untouched."}{" "}
          CLI parity: <code className="rounded-1 bg-bg-3 px-1">observer guard simulate --since 168h --enforce</code>.
        </>
      }
      right={
        <div className="flex items-center gap-2">
          <SegmentedControl<"168" | "720">
            size="sm"
            options={[
              { value: "168", label: "7d" },
              { value: "720", label: "30d" },
            ]}
            value={hours}
            onChange={setHours}
          />
          <button type="button" className={actionBtn} disabled={busy} onClick={run}>
            {busy ? "Replaying…" : result ? "Replay again" : "Run the readiness check"}
          </button>
        </div>
      }
    >
      {!result && !busy && !error && (
        <div className="py-3 text-[11.5px] text-fg-3">
          Nothing replayed yet. The check answers "what would enforce have blocked over my last{" "}
          {hours === "168" ? "7" : "30"} days?" from history the observer already captured - the question to settle
          before promoting. Full migration path: the guard enforce runbook (
          <code className="rounded-1 bg-bg-3 px-1">docs/guard-enforce-runbook.md</code>).
        </div>
      )}
      {error && <div className="py-2 text-[11.5px] text-danger">{error}</div>}
      {result && (
        <div className="space-y-3 text-[11.5px]">
          <div className="text-fg-1">
            Under enforce, the last {days} days would have{" "}
            <strong className="font-semibold">
              blocked or deferred {result.would_block.toLocaleString()}
            </strong>{" "}
            of {result.scanned.toLocaleString()} captured actions (~{(result.would_block / days).toFixed(1)}/day -{" "}
            {denies.toLocaleString()} deny, {asks.toLocaleString()} ask)
            {result.capped ? " · 50k replay cap hit, the window's oldest actions weren't replayed" : ""}.
          </div>
          <ul className="space-y-1">
            <li className="flex items-baseline gap-2">
              <Icon
                icon={result.scanned > 0 ? Check : X}
                size="xs"
                label={result.scanned > 0 ? "passed" : "failed"}
                className={clsx("shrink-0 self-start mt-[3px]", result.scanned > 0 ? "text-success" : "text-danger")}
              />
              <span className="text-fg-2">
                History to judge - {result.scanned.toLocaleString()} captured actions in the window
                {result.scanned === 0 && (
                  <span className="text-fg-3"> - let the observer run, or widen the window</span>
                )}
              </span>
            </li>
            <li className="flex items-baseline gap-2">
              <Icon
                icon={result.would_block === 0 || topShare < 0.5 ? Check : X}
                size="xs"
                label={result.would_block === 0 || topShare < 0.5 ? "passed" : "failed"}
                className={clsx(
                  "shrink-0 self-start mt-[3px]",
                  result.would_block === 0 || topShare < 0.5 ? "text-success" : "text-danger",
                )}
              />
              <span className="text-fg-2">
                {result.would_block === 0
                  ? "Nothing would block in this window - flipping enforce is low-risk here, and also changes nothing until a rule trips"
                  : `Noise concentration - ${topBlocking[0]?.[0]} alone carries ${Math.round(topShare * 100)}% of the would-blocks`}
                {result.would_block > 0 && topShare >= 0.5 && (
                  <span className="text-fg-3">
                    {" "}
                    - tune it before enforce, strictest first: approve a scope, override its decision, exempt paths,
                    or disable the ID
                  </span>
                )}
              </span>
            </li>
          </ul>
          {topBlocking.length > 0 && (
            <DataTable<[string, number]>
              data={topBlocking}
              columns={blockingColumns}
              rowKey={([rule]) => rule}
              minWidth={520}
            />
          )}
          <div className="space-y-1 text-[11px] leading-snug text-fg-3">
            <div>
              This replay does not consult the Approvals register - active grants downgrade matching blocks in live
              enforce, so the real count is at most what's shown. Ask-class verdicts prompt on clients with a native
              ask and deny-with-reason elsewhere.
            </div>
            <div>
              Not ready to flip everything? Ramp per rule:{" "}
              <code className="rounded-1 bg-bg-3 px-1">[[override]] rule = "R-xxx" / enforce = true</code> in{" "}
              <code className="rounded-1 bg-bg-3 px-1">~/.observer/guard-policy.toml</code> blocks just that rule
              while the mode stays observe. When the list above reads as intended blocks, promote in the Mode card -
              the same evidence is shown at its consent step.
            </div>
          </div>
        </div>
      )}
    </ChartShell>
  );
}

// GuardBudget is GET /api/guard/budget (G2.4): configured thresholds,
// today's spend on the enforcement substrate, and the 30d observed
// distribution the suggestions derive from.
type GuardBudget = {
  session_usd: number;
  daily_usd: number;
  hard: boolean;
  spend_today_usd: number;
  window_days: number;
  sessions: number;
  session_p95_usd: number;
  session_max_usd: number;
  days: number;
  daily_p95_usd: number;
  daily_max_usd: number;
};

// niceCeil rounds a suggestion up to an amount a human would type.
function niceCeil(x: number): number {
  if (x <= 0) return 0;
  if (x < 1) return Math.ceil(x * 10) / 10;
  if (x < 10) return Math.ceil(x * 2) / 2;
  if (x < 100) return Math.ceil(x);
  return Math.ceil(x / 5) * 5;
}

const usd = (v: number) => `$${v.toFixed(2)}`;

// GuardBudgetCard — the G2.4 budget guardrails: suggested thresholds
// from observed spend (p95 + 25% headroom — a tripwire above normal
// use, not a cost target) and a burn-down meter when a daily budget
// is set. Applying a suggestion writes [guard.budget] through the one
// config seam with the usual consent + restart honesty. Distinct from
// the Cost page's BudgetCard (advisory MONTHLY budgets, never a
// gate): these are the guard's per-session/per-day tripwires, and
// `hard` ones actually deny at the proxy.
function GuardBudgetCard() {
  const api = useApi<GuardBudget>("/api/guard/budget");
  const [confirm, setConfirm] = useState<{ which: "session" | "daily"; value: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState("");
  const [error, setError] = useState("");

  const b = api.data;
  // Below 5 samples a p95 is noise — no suggestion rather than a
  // confidently wrong one.
  const suggestSession = b && b.sessions >= 5 ? niceCeil(b.session_p95_usd * 1.25) : 0;
  const suggestDaily = b && b.days >= 5 ? niceCeil(b.daily_p95_usd * 1.25) : 0;

  const apply = async () => {
    if (!confirm) return;
    setBusy(true);
    setError("");
    try {
      const cfg = await fetchJSON<{ config: { Guard: { Budget?: Record<string, unknown> } & Record<string, unknown> } }>(
        "/api/config",
      );
      const guardSec = { ...cfg.config.Guard };
      const budget = { ...(guardSec.Budget ?? {}) };
      if (confirm.which === "session") budget.SessionUSD = confirm.value;
      else budget.DailyUSD = confirm.value;
      guardSec.Budget = budget;
      await fetchJSON("/api/config/section/guard", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(guardSec),
      });
      markRestartPending("guard");
      setSaved(`${confirm.which} budget ${usd(confirm.value)}`);
      setConfirm(null);
      api.reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const pct = b && b.daily_usd > 0 ? Math.min(100, (b.spend_today_usd / b.daily_usd) * 100) : 0;

  return (
    <ChartShell
      title={<TitleWithHelp text="Budget guardrails" helpId="card.security_budget" />}
      icon={SECURITY_SECTION_ICONS.budgetGuardrails}
      right={saved ? <Pill variant="warn">saved: {saved} - restart the daemon to apply</Pill> : undefined}
      sub={
        <>
          Spend tripwires on the guard's own substrate: soft budgets flag (B-601/B-602), hard
          budgets deny at the proxy - clients not routed through the proxy can't be hard-stopped.
          0 = off. (Monthly advisory budgets - never a gate - live on the Cost page.)
        </>
      }
    >
      {api.loading ? (
        <InlineLoading label="Loading budgets" block />
      ) : b ? (
        <div className="space-y-3 text-[11.5px]">
          {b.daily_usd > 0 ? (
            <div>
              <div className="mb-1 flex items-baseline justify-between">
                <span className="text-fg-2">
                  Today: <strong className="font-semibold text-fg-0">{usd(b.spend_today_usd)}</strong> of{" "}
                  {usd(b.daily_usd)} daily budget{b.hard ? " (hard - breach denies at the proxy)" : " (soft - breach flags)"}
                </span>
                <span className={pct >= 100 ? "font-semibold text-danger" : pct >= 75 ? "text-warn" : "text-fg-3"}>
                  {Math.round(pct)}%
                </span>
              </div>
              <div className="h-2 overflow-hidden rounded-2 bg-bg-3">
                <div
                  className={`h-full rounded-2 ${pct >= 100 ? "bg-danger" : pct >= 75 ? "bg-warn" : "bg-accent"}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          ) : (
            <div className="text-fg-3">
              No daily budget set - today's spend is {usd(b.spend_today_usd)} on the substrate a budget would
              meter.
            </div>
          )}
          <Table
            minWidth={560}
            head={
              <tr>
                <th className="py-1 pr-3 font-medium">Budget</th>
                <th className="py-1 pr-3 text-right font-medium">Configured</th>
                <th className="py-1 pr-3 text-right font-medium">Observed p95 ({b.window_days}d)</th>
                <th className="py-1 pr-3 text-right font-medium">Max</th>
                <th className="py-1 pr-3 text-right font-medium">Suggested</th>
                <th className="py-1 font-medium"></th>
              </tr>
            }
          >
            <tr className="border-b border-line-1/60 last:border-0">
              <td className="py-1.5 pr-3 text-fg-2">Per session</td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-1">
                {b.session_usd > 0 ? usd(b.session_usd) : "off"}
              </td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">
                {b.sessions > 0 ? `${usd(b.session_p95_usd)} (n=${b.sessions})` : "-"}
              </td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-3">
                {b.sessions > 0 ? usd(b.session_max_usd) : "-"}
              </td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-1">
                {suggestSession > 0 ? usd(suggestSession) : "-"}
              </td>
              <td className="py-1.5 text-right">
                {suggestSession > 0 && suggestSession !== b.session_usd && (
                  <button
                    type="button"
                    className={actionBtn}
                    disabled={busy}
                    onClick={() => setConfirm({ which: "session", value: suggestSession })}
                  >
                    Apply…
                  </button>
                )}
              </td>
            </tr>
            <tr className="border-b border-line-1/60 last:border-0">
              <td className="py-1.5 pr-3 text-fg-2">Per day</td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-1">
                {b.daily_usd > 0 ? usd(b.daily_usd) : "off"}
              </td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">
                {b.days > 0 ? `${usd(b.daily_p95_usd)} (n=${b.days})` : "-"}
              </td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-3">
                {b.days > 0 ? usd(b.daily_max_usd) : "-"}
              </td>
              <td className="py-1.5 pr-3 text-right tabular-nums text-fg-1">
                {suggestDaily > 0 ? usd(suggestDaily) : "-"}
              </td>
              <td className="py-1.5 text-right">
                {suggestDaily > 0 && suggestDaily !== b.daily_usd && (
                  <button
                    type="button"
                    className={actionBtn}
                    disabled={busy}
                    onClick={() => setConfirm({ which: "daily", value: suggestDaily })}
                  >
                    Apply…
                  </button>
                )}
              </td>
            </tr>
          </Table>
          {b.sessions < 5 && b.days < 5 && (
            <div className="text-[11px] text-fg-3">
              Not enough observed spend to suggest values yet ({b.sessions} session(s) / {b.days} day(s) with
              cost in the last {b.window_days} days) - suggestions appear at 5 samples.
            </div>
          )}
          <div className="text-[11px] leading-snug text-fg-3">
            Suggested = observed p95 + 25% headroom, rounded - a tripwire above your normal use, not a cost
            target. Spend is measured as the larger of proxy ground truth and watcher estimates per session,
            the same substrate the budget rules compare against. Tune precisely in Settings → Guard → budget.
          </div>
          {confirm && (
            <div className="rounded-2 border border-line-2 bg-bg-3 p-3">
              <p className="text-fg-2">
                Set <code className="rounded-1 bg-bg-2 px-1 font-mono text-[10.5px]">[guard.budget] {confirm.which === "session" ? "session_usd" : "daily_usd"} = {confirm.value}</code>
                ? Saved through the config seam; binds at the next daemon restart. Breach behavior stays{" "}
                {b.hard ? "hard (deny at the proxy)" : "soft (flag)"} - the `hard` switch is in Settings → Guard.
              </p>
              <div className="mt-2 flex items-center gap-2">
                <button type="button" className={actionBtn} disabled={busy} onClick={apply}>
                  {busy ? "Saving…" : "Set budget"}
                </button>
                <button type="button" className={actionBtn} onClick={() => setConfirm(null)}>
                  Cancel
                </button>
              </div>
            </div>
          )}
          {error && <div className="text-danger">{error}</div>}
        </div>
      ) : null}
    </ChartShell>
  );
}

// POLICY_PLACEHOLDER seeds an empty editor with the two §4.4 shapes
// (shown as a placeholder only - saving stays an explicit act).
const POLICY_PLACEHOLDER = `# ~/.observer/guard-policy.toml - your user policy layer.
# Reference: docs/guard-policy-authoring.md

# [[rule]]
# id       = "U-001"
# category = "destructive"
# decision = "ask"
# enforce  = true
# match.command_regex = '(?i)\\bterraform\\s+(apply|destroy)\\b'

# [[override]]
# rule    = "R-110"
# enforce = true`;

// The Policy layers card subtitle (kept out of the JSX header for length).
const POLICY_LAYERS_SUB =
  "Effective policy = merge(org bundle, your user file, project files, built-ins) - strictness " +
  "is one-way; a lower layer can escalate but never relax. Only the user layer is editable " +
  "here: project files belong to their repos, the org bundle arrives signed. Most day-to-day " +
  "rule work belongs in the Rule manager above - reach for this raw editor for constructs it " +
  "doesn't support (or when its structured view says a file doesn't round-trip).";

// PolicyLayersCard - the ADVANCED / raw-TOML fallback beneath RuleManager's
// structured editor (docs/plans/guard-rule-management-ui-plan-2026-09-21.md
// §6 Track B). The layers table shows every policy source in effect (org
// bundle, user file, per-project files) with counts + lint findings; the
// editor edits the USER layer only - project files belong to their repos
// (least-trusted; agent edits are R-161) and the org bundle arrives signed.
// This is the escape hatch RuleManager points at when a layer's content
// doesn't round-trip through parseRules (a hand-authored construct the
// structured form can't represent) — it stays a fully working editor on its
// own, independent of RuleManager's parse success. Saves are lint-gated (the
// same strict parse `observer guard lint` runs; the server refuses a
// malformed file 422), keep a .bak, and are restart-honest. `api` is shared
// with RuleManager (lifted to SecurityPage) so a save in either place
// reloads the same view.
function PolicyLayersCard({ api }: { api: ApiState<GuardPolicyView> }) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");
  const [lint, setLint] = useState<GuardPolicyLint | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const [confirmRestore, setConfirmRestore] = useState(false);

  const view = api.data;
  const layers = view?.layers ?? [];
  const loadIssues = view?.load_issues ?? [];

  const startEdit = () => {
    setText(view?.user.content ?? "");
    setLint(null);
    setProblems([]);
    setError("");
    setSaved(false);
    setEditing(true);
  };

  const runLint = async (content: string): Promise<GuardPolicyLint> =>
    fetchJSON<GuardPolicyLint>("/api/guard/policy/lint", undefined, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, layer: "user" }),
    });

  const validate = async () => {
    setBusy(true);
    setError("");
    try {
      setLint(await runLint(text));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    setBusy(true);
    setError("");
    setProblems([]);
    try {
      // Lint first so problems render in full (the PUT still gates
      // server-side - a malformed body is refused 422 regardless).
      const l = await runLint(text);
      setLint(l);
      if (!l.ok) {
        setProblems(l.problems ?? []);
        return;
      }
      await fetchJSON("/api/guard/policy", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: text }),
      });
      markRestartPending("guard-policy");
      setSaved(true);
      setEditing(false);
      api.reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    setBusy(true);
    setError("");
    try {
      await fetchJSON("/api/guard/policy/backup", undefined, { method: "POST" });
      markRestartPending("guard-policy");
      setConfirmRestore(false);
      setEditing(false);
      setSaved(true);
      api.reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <ChartShell
      title={
        <TitleWithHelp text="Advanced: policy layers (raw TOML)" helpId="card.security_policy_editor" />
      }
      icon={SECURITY_SECTION_ICONS.policyLayers}
      sub={POLICY_LAYERS_SUB}
      right={
        <div className="flex flex-wrap items-center gap-2">
          {saved && <Pill variant="warn">saved - restart the daemon to apply</Pill>}
          {view?.user.writable && !editing && (
            <button type="button" className={actionBtn} onClick={startEdit}>
              {view.user.exists ? "Edit user policy…" : "Create user policy…"}
            </button>
          )}
          {view?.user.backup_exists && !editing && (
            <Tooltip content="Swap the policy file with its .bak (a second restore undoes the first)">
              <button
                type="button"
                className={actionBtn}
                disabled={busy}
                onClick={() => setConfirmRestore((v) => !v)}
              >
                Restore backup…
              </button>
            </Tooltip>
          )}
        </div>
      }
    >
      {confirmRestore && (
        <div className="mb-3 rounded-2 border border-line-2 bg-bg-3 p-3 text-[11.5px]">
          <p className="text-fg-2">
            Swap <code className="rounded-1 bg-bg-2 px-1 font-mono text-[10.5px]">{view?.user.path}</code> with its{" "}
            .bak? The backup is lint-checked before it lands; because it's a swap, restoring again
            undoes this.
          </p>
          <div className="mt-2 flex items-center gap-2">
            <button type="button" className={actionBtn} disabled={busy} onClick={restore}>
              {busy ? "Restoring…" : "Restore"}
            </button>
            <button type="button" className={actionBtn} onClick={() => setConfirmRestore(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {api.loading ? (
        <InlineLoading label="Loading policy layers" block />
      ) : (
        <>
          <Table
            minWidth={860}
            head={
              <tr>
                <th className="py-1 pr-3 font-medium">Layer</th>
                <th className="py-1 pr-3 font-medium">File</th>
                <th className="py-1 pr-3 text-right font-medium">Rules</th>
                <th className="py-1 pr-3 text-right font-medium">Overrides</th>
                <th className="py-1 font-medium">Status</th>
              </tr>
            }
          >
            {layers.map((l) => (
              // project_root joins the key: two trusted_project layers can
              // share one policy file path while naming different projects.
              <tr
                key={`${l.layer}/${l.path}/${l.project_root ?? ""}`}
                className="border-b border-line-1/60 align-top last:border-0"
              >
                <td className="py-1.5 pr-3">
                  <Pill variant={l.editable ? "accent" : "neutral"}>{l.layer}</Pill>
                </td>
                {/* The width cap sits on inner blocks: a max-width on the
                    cell itself is ignored by auto table layout, which let a
                    long path squeeze the Status column into a tall wrap. */}
                <td className="py-1.5 pr-3 font-mono text-[10.5px] text-fg-2">
                  <span className="block max-w-[380px] truncate" title={l.path}>
                    {l.path}
                  </span>
                  {l.project_root && (
                    <span className="block max-w-[380px] truncate text-fg-3" title={l.project_root}>
                      in {l.project_root}
                    </span>
                  )}
                </td>
                <td className="py-1.5 pr-3 text-right tabular-nums text-fg-1">
                  {l.counts_known ? l.rules : "-"}
                </td>
                <td className="py-1.5 pr-3 text-right tabular-nums text-fg-1">
                  {l.counts_known ? l.overrides : "-"}
                </td>
                <td className="py-1.5">
                  {!l.exists ? (
                    <span className="text-fg-3">not present{l.editable ? " - create it with the editor" : ""}</span>
                  ) : (l.problems ?? []).length > 0 ? (
                    <Pill variant="danger">{(l.problems ?? []).length} lint problem(s)</Pill>
                  ) : (
                    <Pill variant="success">ok</Pill>
                  )}
                  {l.version && <span className="ml-1.5 text-[10.5px] text-fg-3">bundle v{l.version}</span>}
                </td>
              </tr>
            ))}
          </Table>
          {layers.flatMap((l) => (l.problems ?? []).map((p) => `${l.layer}: ${p}`)).map((p, i) => (
            <div key={i} className="mt-1.5 text-[11px] text-danger">
              {p}
            </div>
          ))}
          {loadIssues.length > 0 && (
            <div className="mt-2 space-y-0.5 text-[11px] text-fg-3">
              {loadIssues.map((iss, i) => (
                <div key={i}>LOAD ISSUE: {iss}</div>
              ))}
            </div>
          )}
        </>
      )}
      {editing && (
        <div className="mt-3 space-y-2 rounded-2 border border-line-2 bg-bg-3 p-3">
          <div className="text-caption text-fg-3">
            Editing <code className="rounded-1 bg-bg-2 px-1 font-mono text-[10.5px]">{view?.user.path}</code> - saves
            are lint-gated (a malformed file is refused) and keep the prior version at .bak. Syntax:{" "}
            <code className="rounded-1 bg-bg-2 px-1 font-mono text-[10.5px]">docs/guard-policy-authoring.md</code>.
          </div>
          <textarea
            className="h-64 w-full resize-y rounded-2 border border-line-2 bg-bg-2 p-2 font-mono text-[11.5px] leading-relaxed text-fg-1"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setLint(null);
              setProblems([]);
            }}
            placeholder={POLICY_PLACEHOLDER}
            spellCheck={false}
          />
          {lint && lint.ok && (
            <div className="text-[11.5px] text-success">
              Lints clean - {lint.rules} rule(s), {lint.overrides} override(s).
            </div>
          )}
          {(problems.length > 0 || (lint && !lint.ok)) && (
            <div className="space-y-0.5 text-[11.5px] text-danger">
              {(problems.length > 0 ? problems : (lint?.problems ?? [])).map((p, i) => (
                <div key={i}>{p}</div>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <button type="button" className={actionBtn} disabled={busy} onClick={validate}>
              {busy ? "Working…" : "Validate"}
            </button>
            <button type="button" className={actionBtn} disabled={busy} onClick={save}>
              {busy ? "Working…" : "Lint + save"}
            </button>
            <button type="button" className={actionBtn} onClick={() => setEditing(false)}>
              Cancel
            </button>
            <span className="text-[11px] text-fg-3">
              Changes bind at daemon restart; hook processes follow immediately.
            </span>
          </div>
        </div>
      )}
      {error && <div className="mt-2 text-[11.5px] text-danger">{error}</div>}
    </ChartShell>
  );
}

const TTL_OPTIONS: { value: number; label: string }[] = [
  { value: 24, label: "24 hours" },
  { value: 168, label: "7 days" },
  { value: 720, label: "30 days" },
  { value: 0, label: "never expires" },
];

// ApprovalsCard — the §6.3 exception register (G1.3): active grants
// with revoke, plus the grant form. "approve…" on a timeline row
// pre-fills rule + session here. Grants are DB writes through the
// same store seam the CLI uses — live immediately, no restart.
// CUSTOM_RULE_OPTION is the combobox sentinel that reveals the free-text
// rule-id input — the escape hatch for granting an exception against a
// user/project/org custom rule that isn't in the effective catalog.
const CUSTOM_RULE_OPTION = "__custom__";

function ApprovalsCard({
  api,
  ruleDefs,
  seed,
  onSeedConsumed,
}: {
  api: ApiState<GuardApprovalsResponse>;
  // The effective /api/guard/rules catalog, keyed by id (same Map the
  // timeline's RuleCell reads) — so the grant form can offer a picker of
  // real rules with their descriptions instead of a bare code field.
  ruleDefs: Map<string, GuardRule[]>;
  seed: ApproveSeed | null;
  onSeedConsumed: () => void;
}) {
  const [ruleId, setRuleId] = useState("");
  // custom = the free-text escape hatch is active (rule id typed by hand,
  // not chosen from the catalog). Kept distinct from ruleId so an empty
  // custom field and an empty catalog selection read differently.
  const [custom, setCustom] = useState(false);
  const [scope, setScope] = useState<"session" | "project" | "global">("session");
  const [sessionId, setSessionId] = useState("");
  const [ttl, setTtl] = useState(24);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [formOpen, setFormOpen] = useState(false);

  useEffect(() => {
    if (!seed) return;
    setRuleId(seed.rule);
    // A seeded rule that isn't in the effective catalog (older daemon, or a
    // user/project/org custom rule) drops into the free-text escape hatch.
    setCustom(seed.rule ? !ruleDefs.has(seed.rule) : false);
    setSessionId(seed.session);
    setScope(seed.session ? "session" : "global");
    setFormOpen(true);
    onSeedConsumed();
  }, [seed, onSeedConsumed, ruleDefs]);

  // One combobox option per unique catalog rule id, grouped by category and
  // sorted (category, then id). Label is "<id> — <doc>"; searchable folds in
  // id + doc + category so type-ahead matches any of them. A trailing
  // sentinel reveals the custom free-text field.
  const ruleOptions = useMemo<ComboOption[]>(() => {
    const entries = Array.from(ruleDefs.entries()).map(([id, defs]) => {
      const primary = defs[0];
      const category = primary?.category ?? "";
      const doc = primary?.doc ?? "";
      return { id, category, doc };
    });
    entries.sort(
      (a, b) => a.category.localeCompare(b.category) || a.id.localeCompare(b.id),
    );
    const opts: ComboOption[] = entries.map((e) => ({
      value: e.id,
      label: (
        <span className="min-w-0">
          <span className="font-mono text-fg-1">{e.id}</span>
          {e.doc && <span className="text-fg-3"> - {e.doc}</span>}
        </span>
      ),
      searchable: `${e.id} ${e.doc} ${e.category}`.toLowerCase(),
      groupLabel: e.category || "other",
    }));
    opts.push({
      value: CUSTOM_RULE_OPTION,
      label: <span className="text-fg-2">Other / custom rule id…</span>,
      searchable: "other custom rule id",
      groupLabel: " ", // sorts last; blank heading keeps it visually apart
    });
    return opts;
  }, [ruleDefs]);

  // The rule currently chosen from the catalog (if any) — drives the
  // explanation panel beneath the picker.
  const selectedDefs = !custom && ruleId ? ruleDefs.get(ruleId) : undefined;

  const rows = api.data?.approvals ?? [];

  const grant = async () => {
    setBusy(true);
    setError("");
    try {
      await fetchJSON("/api/guard/approvals", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: ruleId.trim(),
          scope,
          session_id: sessionId.trim(),
          ttl_hours: ttl,
        }),
      });
      setRuleId("");
      setCustom(false);
      setSessionId("");
      setFormOpen(false);
      api.reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (id: number) => {
    setBusy(true);
    setError("");
    try {
      await fetchJSON(`/api/guard/approvals/${id}`, undefined, { method: "DELETE" });
      api.reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };


  // Exception register rows. Expires sorts by the raw timestamp, and a
  // grant that never expires sorts last. Rebuilt per render (the revoke
  // button reads busy).
  const approvalColumns: ColumnDef<GuardApproval, unknown>[] = [
    {
      id: "rule",
      header: "Rule",
      accessorKey: "rule_id",
      cell: ({ row }) => <span className="font-mono text-fg-1">{row.original.rule_id}</span>,
    },
    {
      id: "scope",
      header: "Scope",
      accessorKey: "scope",
      cell: ({ row }) => <span className="text-fg-2">{row.original.scope}</span>,
    },
    {
      id: "anchor",
      header: "Anchor",
      enableSorting: false,
      cell: ({ row }) => {
        const a = row.original;
        return (
          <span
            className="block max-w-[180px] truncate font-mono text-[10.5px] text-fg-3"
            title={a.scope === "project" ? a.project_root_hash : undefined}
          >
            {a.scope === "session"
              ? a.session_id
              : a.scope === "project"
                ? fmtShortId(a.project_root_hash, 12)
                : "everywhere"}
          </span>
        );
      },
    },
    {
      id: "expires",
      header: "Expires",
      accessorFn: (a) => (a.expires_at ? new Date(a.expires_at).getTime() : Number.MAX_SAFE_INTEGER),
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-fg-3">
          {row.original.expires_at ? fmtDateTime(row.original.expires_at) : "never"}
        </span>
      ),
    },
    {
      id: "action",
      header: "",
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => (
        <Tooltip content="Withdraw this exception (observer guard revoke)">
          <button type="button" className={actionBtn} disabled={busy} onClick={() => revoke(row.original.id)}>
            Revoke
          </button>
        </Tooltip>
      ),
    },
  ];
  return (
    <ChartShell
      title={<TitleWithHelp text="Approvals" helpId="card.security_approvals" />}
      icon={SECURITY_SECTION_ICONS.approvals}
      sub={
        <>
          Scoped exceptions: a matching blocking verdict downgrades to a flag. Auditable, expiring,
          revocable - prefer these over disabling a rule outright.
        </>
      }
      right={
        <button type="button" className={actionBtn} onClick={() => setFormOpen((v) => !v)}>
          {formOpen ? "Close" : "Grant…"}
        </button>
      }
    >
      {formOpen && (
        <div className="mb-3 space-y-2 rounded-2 border border-line-2 bg-bg-3 p-3 text-[11.5px]">
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-fg-3">Rule</label>
            <ComboChip
              label="Rule"
              value={custom ? CUSTOM_RULE_OPTION : ruleId}
              options={ruleOptions}
              placeholder="Search rules…"
              popoverWidth={420}
              emptyHint="No matching rules."
              buttonValueRender={(sel) =>
                custom ? (
                  <b className="font-semibold text-fg-0">Custom id</b>
                ) : sel ? (
                  <b className="font-mono font-semibold text-fg-0">{sel.value}</b>
                ) : (
                  <b className="font-semibold text-fg-3">Pick a rule…</b>
                )
              }
              onChange={(next) => {
                if (next === CUSTOM_RULE_OPTION) {
                  setCustom(true);
                  setRuleId("");
                } else {
                  setCustom(false);
                  setRuleId(next);
                }
              }}
            />
            {custom && (
              <input
                className="w-28 rounded-2 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-caption text-fg-1"
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value)}
                placeholder="R-151"
                aria-label="Custom rule id"
                // eslint-disable-next-line jsx-a11y/no-autofocus
                autoFocus
              />
            )}
            <SegmentedControl<"session" | "project" | "global">
              size="sm"
              options={[
                { value: "session", label: "Session" },
                { value: "project", label: "Project" },
                { value: "global", label: "Global" },
              ]}
              value={scope}
              onChange={setScope}
            />
            <select
              className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-caption text-fg-1"
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value))}
            >
              {TTL_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          {selectedDefs && selectedDefs.length > 0 && (
            // The chosen rule's definition, reusing RuleCell's tooltip idiom
            // (doc + severity + observe/enforce + advice) so the operator
            // sees exactly what they're granting an exception for.
            <div className="rounded-2 border border-line-2 bg-bg-2 p-2 text-caption leading-snug">
              {selectedDefs.map((d, i) => (
                <div key={i} className="mb-1.5 last:mb-0">
                  <span className="text-fg-1">{d.doc}</span>
                  <span className="block text-fg-3">
                    {d.severity} · observe → {d.observe} · enforce → {d.enforce}
                    {d.enforced ? " · per-rule enforced" : ""}
                  </span>
                  {d.source && d.source !== "builtin" && (
                    <span className="block text-fg-3">
                      defined in the {d.source} policy layer
                    </span>
                  )}
                  {d.advice && <span className="block text-fg-3">{d.advice}</span>}
                </div>
              ))}
            </div>
          )}
          {custom && (
            <div className="text-[10.5px] text-fg-3">
              Granting for a rule id not in the effective catalog (a user, project, or org
              custom rule). The exception applies to whatever verdict carries this exact id.
            </div>
          )}
          {scope !== "global" && (
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-fg-3">Session id</label>
              <input
                className="w-72 rounded-2 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-caption text-fg-1"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                placeholder={
                  scope === "project" ? "any session in the target project" : "the session to except"
                }
              />
            </div>
          )}
          {scope === "project" && (
            <div className="text-[10.5px] text-fg-3">
              Project scope anchors to this session's project root as a hash - other checkouts of
              the same repo at different paths won't match.
            </div>
          )}
          <div className="flex items-center gap-2">
            <button
              type="button"
              className={actionBtn}
              disabled={busy || !ruleId.trim() || (scope !== "global" && !sessionId.trim())}
              onClick={grant}
            >
              {busy ? "Granting…" : "Grant exception"}
            </button>
            {error && <span className="text-danger">{error}</span>}
          </div>
        </div>
      )}
      {api.loading ? (
        <InlineLoading label="Loading approvals" block />
      ) : rows.length === 0 ? (
        <div className="py-3 text-[11.5px] text-fg-3">
          No active exceptions. Use “approve…” on a verdict row to grant one scoped to that
          rule + session.
        </div>
      ) : (
        <DataTable<GuardApproval>
          data={rows}
          columns={approvalColumns}
          rowKey={(a) => String(a.id)}
          minWidth={440}
        />
      )}
    </ChartShell>
  );
}

// ---- Prompt guard card (PHASE-3b-DASHBOARD) ----
//
// Prompt-submit intervention (docs/guard-prompt.md): warn/ask-once/
// block/redact when the DEVELOPER'S OWN prompt carries an API token or
// deterministic PII, before it reaches the model. Distinct from the
// verdict timeline above (which covers every guard rule) — this card
// scopes to R-172/R-190 hits on KindUserPrompt events specifically, via
// the feature's own /api/guard/prompt/* endpoints (never reusing
// /api/guard/events' generic rule_id filter, since matching R-172 alone
// would ALSO catch this rule's other surfaces — shell args, proxy
// egress on a non-prompt request).
//
// PRIVACY: nothing rendered here is ever a matched value or prompt
// span — see internal/intelligence/dashboard/guard_prompt.go's package
// doc comment for the upstream invariant this card's data depends on.
// "Fingerprint" below is an opaque sha256 hex digest, safe to show and
// copy (it's the audit anchor `clear` looks up by), never the secret.

type PromptStatusConfig = {
  enabled: boolean;
  mode: string;
  hook_lane: boolean;
  proxy_lane: boolean;
  reconsider_ttl: string;
  reconsider_min_delay?: string;
  suppress_in_code: boolean;
  max_findings: number;
  enforce_independent: boolean;
  allow_pattern_count: number;
  effective_hook_lane_state: "off" | "observe_only" | "active" | string;
};

type PromptClient = {
  tool: string;
  prompt_lane: string;
  mechanism?: string;
  auto_wired: boolean;
  wire_state: "auto_wired" | "documented_only" | string;
};

type PromptReconsiderRow = {
  fingerprint: string;
  session_id?: string;
  tool?: string;
  detectors?: string;
  warned_at: string;
  confirmed_at?: string;
  expires_at: string;
  expired: boolean;
};

type PromptStatus = {
  guard_enabled: boolean;
  guard_mode: string;
  config: PromptStatusConfig;
  effective_modes: Record<string, string>;
  clients: PromptClient[] | null;
  reconsider_total: number;
  reconsider_expired: number;
  pending: PromptReconsiderRow[] | null;
  approvals: GuardApproval[] | null;
};

type PromptEvent = {
  id: number;
  ts: string;
  session_id?: string;
  tool?: string;
  lane: "hook" | "proxy" | string;
  rule_id: string;
  category?: string;
  severity?: string;
  decision?: string;
  outcome?: string;
  enforced: boolean;
  detectors?: string[] | null;
  fingerprint?: string;
};

type PromptEventsResponse = { events: PromptEvent[] | null; count: number };

type PromptProbeCheck = { name: string; status: string; message: string; details?: string[] | null };

// HOOK_LANE_TILE - the prompt guard's effective hook-lane state as a status
// tile tone: an active (blocking) lane is danger, off is neutral, and
// observe_only (or any other state) reads warn.
const HOOK_LANE_TILE: Readonly<Record<string, Tone>> = {
  active: "danger",
  off: "neutral",
  observe_only: "warn",
};

// OutcomePill renders a prompt-guard outcome from the ONE
// PROMPT_GUARD_OUTCOME table (web/src/lib/vocabTones.ts); a
// "degraded:<why>" outcome keeps its full text on the degraded row.
function OutcomePill({ outcome, children }: { outcome: string; children?: ReactNode }) {
  return (
    <VocabPill vocab="promptGuardOutcome" table={PROMPT_GUARD_OUTCOME} value={promptGuardOutcomeKey(outcome)}>
      {children ?? outcome}
    </VocabPill>
  );
}

function PromptGuardCard() {
  const status = useApi<PromptStatus>("/api/guard/prompt/status");
  const events = useApi<PromptEventsResponse>("/api/guard/prompt/events", { since: "168h", limit: 300 });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [probeChecks, setProbeChecks] = useState<PromptProbeCheck[] | null>(null);
  const [probing, setProbing] = useState(false);

  const reload = () => {
    status.reload();
    events.reload();
  };

  const clearFingerprint = async (fingerprint: string) => {
    setBusy(true);
    setErr("");
    try {
      await fetchJSON("/api/guard/prompt/clear", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fingerprint }),
      });
      reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const revokeApproval = async (id: number) => {
    setBusy(true);
    setErr("");
    try {
      await fetchJSON(`/api/guard/prompt/allow/${id}`, undefined, { method: "DELETE" });
      reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const probeHooks = async (tool?: string) => {
    setProbing(true);
    setErr("");
    setProbeChecks(null);
    try {
      const res = await fetchJSON<{ checks: PromptProbeCheck[] | null }>(
        "/api/guard/prompt/probe",
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(tool ? { tool } : {}),
        },
      );
      setProbeChecks(res.checks ?? []);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setProbing(false);
    }
  };

  const rows = events.data?.events ?? [];
  const now = Date.now();
  const counts = useMemo(() => {
    const byOutcome24 = new Map<string, number>();
    const byOutcome7d = new Map<string, number>();
    const byDetector7d = new Map<string, number>();
    for (const ev of rows) {
      const outcome = ev.outcome || "unknown";
      byOutcome7d.set(outcome, (byOutcome7d.get(outcome) ?? 0) + 1);
      if (now - new Date(ev.ts).getTime() <= 24 * 3600 * 1000) {
        byOutcome24.set(outcome, (byOutcome24.get(outcome) ?? 0) + 1);
      }
      for (const d of ev.detectors ?? []) {
        byDetector7d.set(d, (byDetector7d.get(d) ?? 0) + 1);
      }
    }
    return { byOutcome24, byOutcome7d, byDetector7d };
  }, [rows, now]);

  const cfg = status.data?.config;
  const pending = status.data?.pending ?? [];
  const approvals = status.data?.approvals ?? [];
  const clients = status.data?.clients ?? [];
  const wiredCount = clients.filter((c) => c.wire_state === "auto_wired").length;

  // Pending reconsider-once grants and active R-172/R-190 grants. Rebuilt
  // per render (the Clear / Revoke buttons read busy). Time columns sort
  // by the raw timestamp.
  const pendingColumns: ColumnDef<PromptReconsiderRow, unknown>[] = [
    {
      id: "detectors",
      header: "Detectors",
      accessorFn: (p) => p.detectors ?? "",
      cell: ({ row }) => <span className="font-mono text-fg-1">{row.original.detectors || "-"}</span>,
    },
    {
      id: "session",
      header: "Session",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="block max-w-[160px] truncate font-mono text-[10.5px] text-fg-3" title={row.original.session_id}>
          {row.original.session_id ? fmtShortId(row.original.session_id, 8) : "-"}
        </span>
      ),
    },
    {
      id: "warned",
      header: "Warned",
      accessorFn: (p) => new Date(p.warned_at).getTime(),
      cell: ({ row }) => <span className="whitespace-nowrap text-fg-3">{fmtDateTime(row.original.warned_at)}</span>,
    },
    {
      id: "expires",
      header: "Expires",
      accessorFn: (p) => new Date(p.expires_at).getTime(),
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-fg-3">
          {row.original.expired ? <Pill variant="warn">expired</Pill> : fmtDateTime(row.original.expires_at)}
        </span>
      ),
    },
    {
      id: "action",
      header: "",
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => (
        <Tooltip content="Force a fresh ask-once interrupt on the next identical resend (observer guard prompt clear)">
          <button
            type="button"
            className={actionBtn}
            disabled={busy}
            onClick={() => clearFingerprint(row.original.fingerprint)}
          >
            Clear
          </button>
        </Tooltip>
      ),
    },
  ];

  const grantColumns: ColumnDef<GuardApproval, unknown>[] = [
    {
      id: "rule",
      header: "Rule",
      accessorKey: "rule_id",
      cell: ({ row }) => <span className="font-mono text-fg-1">{row.original.rule_id}</span>,
    },
    {
      id: "scope",
      header: "Scope",
      accessorKey: "scope",
      cell: ({ row }) => {
        const a = row.original;
        return (
          <span className="text-fg-2">
            {a.scope}
            {a.scope === "global" && !a.expires_at && (
              <Pill
                variant="danger"
                className="ml-1.5"
                title="Exempts every detector in this rule class, everywhere on this node, forever"
              >
                global · never expires
              </Pill>
            )}
          </span>
        );
      },
    },
    {
      id: "expires",
      header: "Expires",
      accessorFn: (a) => (a.expires_at ? new Date(a.expires_at).getTime() : Number.MAX_SAFE_INTEGER),
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-fg-3">
          {row.original.expires_at ? fmtDateTime(row.original.expires_at) : "never"}
        </span>
      ),
    },
    {
      id: "action",
      header: "",
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => (
        <Tooltip content="Withdraw this exception">
          <button type="button" className={actionBtn} disabled={busy} onClick={() => revokeApproval(row.original.id)}>
            Revoke
          </button>
        </Tooltip>
      ),
    },
  ];

  return (
    <ChartShell
      title={<TitleWithHelp text="Prompt guard" helpId="card.security_prompt_guard" />}
      icon={SECURITY_SECTION_ICONS.promptGuard}
      sub={
        <>
          Warn/ask-once/block/redact when a prompt you type into a coding agent carries an API token
          or deterministic PII (R-172/R-190) - before it reaches the model. Hook lane (native
          per-client) and/or proxy lane (the latest turn on outbound requests). Never shows a matched
          value or prompt text - only detector types, counts, and an opaque fingerprint.
        </>
      }
      right={
        <div className="flex items-center gap-2">
          <Link
            to="/settings?section=guard"
            className="text-caption text-fg-3 underline decoration-dotted underline-offset-[3px] hover:text-fg-1"
          >
            Configure…
          </Link>
          <Tooltip content="Fire a synthetic, obviously-fake secret through every registered prompt-submit hook and report whether it actually blocked (observer doctor --probe-hook)">
            <button
              type="button"
              className={actionBtn}
              disabled={probing}
              onClick={() => probeHooks()}
            >
              {probing ? "Probing…" : "Probe hooks"}
            </button>
          </Tooltip>
        </div>
      }
    >

      {status.loading ? (
        <InlineLoading label="Loading prompt guard" className="py-3" />
      ) : cfg ? (
        <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <StatusTile
            label="Effective state"
            value={cfg.effective_hook_lane_state.replace("_", " ")}
            tone={HOOK_LANE_TILE[cfg.effective_hook_lane_state] ?? "warn"}
          />
          <StatusTile label="Global mode" value={cfg.enabled ? cfg.mode : "disabled"} tone="accent" />
          <StatusTile
            label="Lanes"
            value={[cfg.hook_lane ? "hook" : null, cfg.proxy_lane ? "proxy" : null].filter(Boolean).join(" + ") || "none"}
            tone="neutral"
          />
          <StatusTile
            label="Clients wired"
            value={`${wiredCount} / ${clients.length}`}
            sub="init/auto-register can write this tool's hook config; the rest are documented-only or need a probe"
            tone="neutral"
          />
        </div>
      ) : null}

      {err && <div className="mb-3 text-[11.5px] text-danger">{err}</div>}

      {probeChecks && (
        <div className="mb-4 rounded-2 border border-line-2 bg-bg-3 p-3">
          <div className="mb-2 text-caption font-semibold uppercase tracking-[0.06em] text-fg-2">
            Probe results
          </div>
          {probeChecks.length === 0 ? (
            <div className="text-[11.5px] text-fg-3">No probe-capable clients registered.</div>
          ) : (
            <ul className="space-y-1 text-[11.5px]">
              {probeChecks.map((c) => (
                <li key={c.name} className="flex items-start gap-2">
                  <VocabPill vocab="healthCheck" table={CHECK_STATUS} value={c.status} />
                  <span className="text-fg-2">{c.message}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {pending.length > 0 && (
        <div className="mb-4">
          <div className="mb-1.5 flex items-center justify-between">
            <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
              Pending reconsider-once grants ({status.data?.reconsider_total ?? 0} total,{" "}
              {status.data?.reconsider_expired ?? 0} expired)
            </div>
          </div>
          <DataTable<PromptReconsiderRow>
            data={pending}
            columns={pendingColumns}
            rowKey={(p) => p.fingerprint}
            minWidth={560}
          />
        </div>
      )}

      {approvals.length > 0 && (
        <div className="mb-4">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
            Active R-172/R-190 grants
          </div>
          <DataTable<GuardApproval>
            data={approvals}
            columns={grantColumns}
            rowKey={(a) => String(a.id)}
            minWidth={480}
          />
        </div>
      )}

      <div className="mb-2 flex flex-wrap items-center gap-3 text-[11px] text-fg-3">
        <span className="font-semibold uppercase tracking-[0.06em] text-fg-2">Last 7d by outcome:</span>
        {[...counts.byOutcome7d.entries()].map(([o, n]) => (
          <OutcomePill key={o} outcome={o}>
            {o} × {n}
          </OutcomePill>
        ))}
        {counts.byOutcome7d.size === 0 && <span>none</span>}
      </div>
      <div className="mb-3 flex flex-wrap items-center gap-3 text-[11px] text-fg-3">
        <span className="font-semibold uppercase tracking-[0.06em] text-fg-2">Last 24h by outcome:</span>
        {[...counts.byOutcome24.entries()].map(([o, n]) => (
          <OutcomePill key={o} outcome={o}>
            {o} × {n}
          </OutcomePill>
        ))}
        {counts.byOutcome24.size === 0 && <span>none</span>}
      </div>

      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
        Events (last 7d)
      </div>
      {events.loading ? (
        <InlineLoading label="Loading events" className="py-3" />
      ) : rows.length === 0 ? (
        <div className="py-3 text-[11.5px] text-fg-3">No prompt-submit guard events in this window.</div>
      ) : (
        <Table
          maxHeight={320}
          stickyHead
          minWidth={640}
          head={
            <tr>
              <th className="py-1 pr-3 font-medium">Time</th>
              <th className="py-1 pr-3 font-medium">Tool</th>
              <th className="py-1 pr-3 font-medium">Lane</th>
              <th className="py-1 pr-3 font-medium">Rule</th>
              <th className="py-1 pr-3 font-medium">Detectors</th>
              <th className="py-1 pr-3 font-medium">Outcome</th>
              <th className="py-1 font-medium">Session</th>
            </tr>
          }
        >
          {rows.slice(0, 100).map((ev) => (
            <tr key={ev.id} className="border-b border-line-1/60 last:border-0">
              <td className="whitespace-nowrap py-1.5 pr-3 text-fg-3">{fmtClock(ev.ts)}</td>
              <td className="whitespace-nowrap py-1.5 pr-3 text-fg-2">{ev.tool || "-"}</td>
              <td className="py-1.5 pr-3 text-fg-2">{ev.lane}</td>
              <td className="whitespace-nowrap py-1.5 pr-3 font-mono text-fg-1">{ev.rule_id}</td>
              <td className="py-1.5 pr-3 font-mono text-[10.5px] text-fg-2">
                {(ev.detectors ?? []).join(", ") || "-"}
              </td>
              <td className="py-1.5 pr-3">
                {ev.outcome ? <OutcomePill outcome={ev.outcome} /> : <span className="text-fg-3">-</span>}
              </td>
              <td className="whitespace-nowrap py-1.5">
                {ev.session_id ? (
                  <Tooltip content={<span className="break-all font-mono">{ev.session_id}</span>}>
                    <Link
                      to={`/sessions?session=${encodeURIComponent(ev.session_id)}`}
                      className="font-mono text-[10.5px] text-accent underline decoration-dotted decoration-accent/50 underline-offset-[3px] hover:decoration-accent"
                    >
                      {fmtShortId(ev.session_id, 8)}
                    </Link>
                  </Tooltip>
                ) : (
                  "-"
                )}
              </td>
            </tr>
          ))}
        </Table>
      )}
    </ChartShell>
  );
}
