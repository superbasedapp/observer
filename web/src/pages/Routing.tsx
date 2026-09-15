import { Fragment, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { HeroStat, PageHeader, Pill, SegmentedControl } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import { CompassIcon } from "@/components/icons";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { markRestartPending } from "@/lib/restartPending";
import { useFilters, windowDaysApprox, windowLabel } from "@/lib/filters";
import { fmtClock, fmtDateTime, fmtInt, fmtUSD } from "@/lib/format";

// Routing page (model-routing spec §R17.1–17.2): live policy with the
// EXPANDED rule table (never a black box), decisions feed with
// reason-code filters, savings-to-date (realized vs counterfactual,
// with the structural honesty note), tier map with calibration
// overlays, and the observed-health board. Windowed queries honor the
// global TopBar window like every sibling page; tool/project filters
// don't apply — routing decisions are a node-global stream.

type RoutingRule = { name: string; when: string; action: string; reason: string };
type RoutingLint = { check: string; rule?: string; severity: string; message: string };
type RoutingStatus = {
  enabled: boolean;
  mode: string;
  policy: string;
  policy_hash: string;
  min_turns: number;
  respect_cache: boolean;
  bases: string[];
  rules: RoutingRule[];
  lint: RoutingLint[];
  decisions: number;
  calibration_rows: number;
  demoted_rules: Record<string, string>;
  demotions_live: boolean;
  last_decision_at?: string;
};

type RoutingDecision = {
  ID: number;
  APITurnID: number | null;
  SessionID: string;
  Timestamp: string;
  Mode: string;
  OriginalModel: string;
  SelectedModel: string;
  TurnKind: string;
  PolicyName: string;
  PolicyHash: string;
  ReasonCodes: string[] | null;
  EstSavingsUSD: number;
  CacheForfeitUSD: number;
  EstimateVersion: string;
  Applied: boolean;
  ProjectRoot: string;
  Tool: string;
};

type DecisionsResponse = { decisions: RoutingDecision[] | null; total: number; reasons: string[] };

type SavingsGroup = {
  key: string;
  decisions: number;
  reroutes: number;
  realized_usd: number;
  would_have_usd: number;
  mean_per_decision_usd: number;
  ci95_per_decision_usd: number;
};
type SavingsResponse = {
  window_days: number;
  decisions: number;
  realized_usd: number;
  would_have_usd: number;
  by_project: SavingsGroup[] | null;
  by_tool: SavingsGroup[] | null;
  by_tier: SavingsGroup[] | null;
  note: string;
};

type CalibrationCell = {
  model: string;
  turn_kind: string;
  project_id: number;
  n: number;
  error_rate: number;
  error_graded: number;
  tool_failure_rate: number;
  latency_p50_ms: number;
};
type TiersResponse = { tiers: Record<string, string[]>; calibration: CalibrationCell[] | null };

type HealthRow = {
  model: string;
  turns_1h: number;
  errors_1h: number;
  turns_24h: number;
  errors_24h: number;
  error_rate_24h: number;
};
type HealthResponse = { models: HealthRow[] | null };

type ShadowReport = {
  window_days: number;
  advise_decisions: number;
  would_reroute: number;
  would_save_usd: number;
  cache_forfeit_usd: number;
  quality_flags: number;
  quality_flags_by_turn_kind: Record<string, number>;
  evidence_backed_moves: number;
  holds_by_reason: Record<string, number>;
  ready_to_promote: boolean;
  min_decisions: number;
  note: string;
};

type SimMove = { from: string; to: string; count: number; est_savings_usd: number };
type SimulateResponse = {
  window_days: number;
  note: string;
  report: {
    policy_name: string;
    policy_hash: string;
    estimate_version: string;
    turns_evaluated: number;
    would_reroute: number;
    reroutes_by_turn_kind: Record<string, number> | null;
    decisions_by_reason: Record<string, number> | null;
    moves: SimMove[] | null;
    est_savings_usd: number;
    cache_forfeit_usd: number;
    quality_risk_flags: number;
    quality_risk_by_turn_kind: Record<string, number> | null;
  };
};

const SIM_TEMPLATES = ["value", "frugal", "fast", "plan-exec", "strict-privacy", "enterprise-default"];

// Channel A apply (R2.1, §R10): the closed §R10.2 tool vocabulary and
// the preview/write wire shapes of /api/routing/apply.
const APPLY_TOOLS = ["claude-code", "codex", "aider", "zed", "kilo-code", "cline", "opencode", "cursor", "copilot"];

type ApplyDelta = {
  turn_kind: string;
  baseline_model: string;
  candidate_model: string;
  n_baseline: number;
  n_candidate: number;
  delta_error_rate_pp: number;
  error_ci95_pp: number;
  verdict: string;
  verdict_basis?: string;
};
type ApplyEvidence = {
  name: string;
  model: string;
  sessions: number;
  actions: number;
  reads: number;
  mutations: number;
  commands: number;
  failures: number;
};
type ApplyChange = {
  path: string;
  agent: string;
  from_model: string;
  to_model: string;
  rationale: string;
  reason: string;
  evidence: ApplyEvidence;
  deltas: ApplyDelta[] | null;
};
type ApplyBackup = { path: string; backup: string; stamp: string };
type ApplyLedgerEvent = {
  time: string;
  kind: string;
  source: string;
  path: string;
  agent?: string;
  from_model?: string;
  to_model?: string;
  backup?: string;
};
type ApplyLedgerResponse = { events: ApplyLedgerEvent[]; skipped: number; path: string };
type ApplyPreview = {
  tool: string;
  mode: "writable" | "snippet" | "advisory";
  window_days: number;
  note: string;
  agent_dirs?: string[];
  changes?: ApplyChange[] | null;
  skipped?: string[] | null;
  backups?: ApplyBackup[] | null;
  weak_model?: string;
  snippet?: string;
  deltas?: ApplyDelta[] | null;
};

// REASON_DOCS spells out the closed reason-code enum (§R9.1,
// internal/routing/types.go) for the decision drawer — one line per
// code, mirroring the Go doc comments. An unknown code (a newer
// daemon) degrades to the bare code, never a guess.
const REASON_DOCS: Record<string, string> = {
  overpowered_read: "a read-only exploration turn ran on a tier above the policy's floor for that work",
  overpowered_housekeeping: "commits / summaries / titles on a flagship tier - weak-model work",
  overpowered_subagent: "a sidechain turn on a tier the sub-agent's observed profile doesn't need",
  overpowered_test_run: "build / test / lint command turns on a flagship tier",
  phase_pin: "a phase rule pinned the tier (opusplan-style)",
  cache_hold: "switching would forfeit a warm prompt cache worth more than the switch saves - the decision is stay",
  stickiness_hold: "the proposed switch landed inside the min-turns-between-switches coherence floor - held",
  budget_band_50: "the budget modifier demoted the max allowed tier at the 50% burn band",
  budget_band_80: "the budget modifier demoted the max allowed tier at the 80% burn band",
  budget_band_95: "the budget modifier demoted the max allowed tier at the 95% burn band",
  availability_fallback: "the target model is health-degraded - the fallback chain engaged",
  rate_limit_window: "subscription-window headroom preservation demoted a soft turn-kind",
  entitlement_hold: "subscription traffic outside the plan's native model set - advise-only",
  escalation: "a downshifted turn failed; the session escalated back to the pre-downshift tier",
  fail_open: "an engine error or timeout - the original model passed through untouched",
  unknown_turn_kind: "the classifier degraded to unknown, so no routing applies",
  unclassified_model: "the original model isn't in the tier table; the engine refuses to reason about it",
  no_candidate: "a rule matched but no same-provider-shape candidate exists in the target tier",
  no_route: "an explicit exemption rule matched - this turn is exempt from routing",
  insufficient_evidence: "the move lacks calibration parity evidence - surfaced as a quality-risk flag",
  custom_rule: "a user-defined [[routing.rules]] row fired without declaring its own reason code",
  privacy_hold: "a privacy rule constrained the candidate set",
  quality_floor_hold: "the quality floor denied the proposed target - the turn stays on its model",
  capability_hold: "the capability basis denied the switch (provider shape, context window, tool support)",
  effort_downshift: "effort / thinking lowered instead of switching model - zero cache loss",
  budget_exhausted: "a budget scope hit 100% and its configured exhaustion behavior fired",
  calibration_demoted: "calibration graded this rule's downshift as regressing - logged, never applied until evidence clears",
};

const TIER_ORDER = ["opus-class", "sonnet-class", "haiku-class", "free", "local", "unclassified"];

type AppliedFilter = "" | "true" | "false";

const SELECT_CLASS =
  "rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-[11.5px] text-fg-1 outline-none focus:border-accent/60";

export function RoutingPage() {
  // Global window (TopBar) drives every windowed query; "all" maps to
  // the same far horizon as sibling pages. Reason/applied stay local —
  // they're feed filters, not data scopes.
  const { win, customRange } = useFilters();
  // Routing surfaces are day-centric: the savings / shadow / apply
  // endpoints replay over a whole-day count and echo `window_days`,
  // so sub-day / custom windows round up to a day count here rather
  // than emitting hours / since-until.
  const days = windowDaysApprox(win, customRange);
  const winLabel =
    win === "all" ? "all time" : `last ${windowLabel(win, customRange)}`;
  // Feed filters live in the URL (R1.4) so a filtered view is
  // shareable and back/forward works — the /sessions?session= idiom.
  const [searchParams, setSearchParams] = useSearchParams();
  const reason = searchParams.get("reason") ?? "";
  const appliedFilter = (searchParams.get("applied") ?? "") as AppliedFilter;
  const setParam = (key: string, value: string) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value) {
          next.set(key, value);
        } else {
          next.delete(key);
        }
        return next;
      },
      { replace: true },
    );
  };
  const [expanded, setExpanded] = useState<number | null>(null);

  const status = useApi<RoutingStatus>("/api/routing/status");
  const savings = useApi<SavingsResponse>("/api/routing/savings", { days }, [days]);
  const decisions = useApi<DecisionsResponse>(
    "/api/routing/decisions",
    { days, limit: 50, reason: reason || undefined, applied: appliedFilter || undefined },
    [days, reason, appliedFilter],
  );
  const tiers = useApi<TiersResponse>("/api/routing/tiers");
  const health = useApi<HealthResponse>("/api/routing/health");
  const shadow = useApi<ShadowReport>("/api/routing/shadow", { days }, [days]);

  const st = status.data;
  const sv = savings.data;
  const sh = shadow.data;
  const decisionRows = decisions.data?.decisions ?? [];

  return (
    <div className="space-y-4 p-5">
      <PageHeader
        title="Routing"
        helpId="tab.routing"
        sub={
          st ? (
            <span className="inline-flex flex-wrap items-center gap-1.5">
              {st.enabled ? (
                <Pill variant={st.mode === "enforce" ? "warn" : "info"}>{st.mode}</Pill>
              ) : (
                <Pill variant="neutral">disabled</Pill>
              )}
              <span>
                policy <span className="font-semibold text-fg-1">{st.policy}</span> @{" "}
                <code className="rounded-1 bg-bg-2 px-1 font-mono text-[11px]">{st.policy_hash}</code> · stickiness{" "}
                {st.min_turns} turns · cache-priced switching {st.respect_cache ? "on" : "off"}
              </span>
            </span>
          ) : (
            "Model-routing decisions, savings, and policy transparency"
          )
        }
      />

      {st && !st.enabled && <RoutingPreviewCard />}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <HeroStat
          label="Decisions - all time"
          helpId="tile.routing.decisions"
          icon={<CompassIcon />}
          loading={status.loading}
          value={st ? fmtInt(st.decisions) : "-"}
          sub={
            st?.last_decision_at
              ? `last ${fmtDateTime(st.last_decision_at)}`
              : "none yet - routing is opt-in (Settings → Routing, or the preview above)"
          }
        />
        <HeroStat
          label={`Realized - ${winLabel}`}
          helpId="tile.routing.realized"
          loading={savings.loading}
          value={sv ? fmtUSD(sv.realized_usd) : "-"}
          sub="decision-time estimates on applied rewrites (enforce mode)"
        />
        <HeroStat
          label={`Would-have - ${winLabel}`}
          helpId="tile.routing.would_have"
          loading={savings.loading}
          value={sv ? fmtUSD(sv.would_have_usd) : "-"}
          sub="the same estimates on unapplied advise decisions"
        />
        <HeroStat
          label="Calibration cells"
          helpId="tile.routing.calibration"
          loading={status.loading}
          value={st ? fmtInt(st.calibration_rows) : "-"}
          sub={
            <>
              <code className="rounded-1 bg-bg-2 px-1 font-mono text-[10.5px]">
                observer model-value --save-calibration
              </code>{" "}
              feeds the §R7.2 evidence gate
            </>
          }
        />
      </div>

      <Section
        title={`Advise shadow - ${winLabel}`}
        helpId="chart.routing_shadow"
        right={
          sh ? (
            sh.ready_to_promote ? (
              <Pill variant="success">promotion evidence present</Pill>
            ) : (
              <Pill variant="neutral">gate not met</Pill>
            )
          ) : null
        }
      >
        {shadow.loading ? (
          <Loading />
        ) : st && !st.enabled ? (
          <p className="py-2 text-[12px] text-fg-3">
            Routing is off - the shadow accrues once advise mode runs (every advise decision is a recorded
            counterfactual; requests stay untouched). Preview savings above answers "is it worth enabling?" without
            turning anything on.
          </p>
        ) : sh ? (
          <>
            <p className="text-[12px] leading-relaxed text-fg-2">
              {fmtInt(sh.advise_decisions)} advise decisions; {fmtInt(sh.would_reroute)} would have rerouted, saving{" "}
              <span className="font-semibold text-fg-1">{fmtUSD(sh.would_save_usd)}</span> (net of{" "}
              {fmtUSD(sh.cache_forfeit_usd)} cache forfeits) with{" "}
              <span className="font-semibold text-fg-1">{fmtInt(sh.quality_flags)}</span> quality-flag events (
              {fmtInt(sh.evidence_backed_moves)} moves evidence-backed).
            </p>
            <ReadinessLadder sh={sh} />
            {Object.keys(sh.holds_by_reason ?? {}).length > 0 && (
              <p className="mt-2 text-[11.5px] text-fg-3">
                Why the router stayed put:{" "}
                {Object.entries(sh.holds_by_reason)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 4)
                  .map(([rc, n], i) => (
                    <span key={rc} className="font-mono text-[11px]">
                      {i > 0 ? " · " : ""}
                      {rc}×{n}
                    </span>
                  ))}
              </p>
            )}
            {st?.enabled && st.mode === "advise" && <PromoteControl sh={sh} />}
            {st?.enabled && st.mode === "enforce" && (
              <p className="mt-2 text-[11.5px] text-fg-3">
                Enforce is live - applied rewrites land in the decisions feed below; realized savings on the tile
                above.
              </p>
            )}
            <p className="mt-2 text-[11px] leading-snug text-fg-3">{sh.note}</p>
          </>
        ) : null}
      </Section>

      <RoutingApplyCard days={days} />

      {st && Object.keys(st.demoted_rules ?? {}).length > 0 && (
        <Section
          title="Calibration demotions"
          helpId="chart.routing_demotions"
          sub="Rules the calibration job graded as regressing - their decisions log but never apply until the evidence clears (§R18.3)."
        >
          <div className="space-y-1.5">
            {Object.entries(st.demoted_rules).map(([rule, why]) => (
              <div key={rule} className="flex flex-wrap items-center gap-1.5 text-[12px] text-fg-2">
                <Pill variant="warn">demoted</Pill>
                <code className="font-mono text-[11px] text-fg-1">{rule}</code>
                <span>- {why}</span>
              </div>
            ))}
          </div>
          <p className="mt-2 text-[11px] leading-snug text-fg-3">
            Demotions are in-memory: a daemon restart clears them and the next calibration pass (hourly) re-detects
            anything still regressing. Affected decisions carry the{" "}
            <code className="font-mono">calibration_demoted</code> reason code in the feed below.
          </p>
        </Section>
      )}

      {st && st.lint.length > 0 && (
        <Section title="Policy lint findings">
          <div className="space-y-1.5">
            {st.lint.map((l, i) => (
              <div key={i} className="flex flex-wrap items-center gap-1.5 text-[12px] text-fg-2">
                <Pill variant={l.severity === "error" ? "danger" : "warn"}>{l.severity}</Pill>
                <code className="font-mono text-[11px] text-fg-1">{l.check}</code>
                {l.rule ? <code className="font-mono text-[11px] text-fg-3">({l.rule})</code> : null}
                <span>- {l.message}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section
        title="Policy rule table"
        helpId="chart.routing_rules"
        sub={`Walked top-down, first match wins. Bases: ${st ? st.bases.join(" → ") : "…"}`}
      >
        {status.loading ? (
          <Loading />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-1.5 pr-3 font-semibold">#</th>
                  <th className="py-1.5 pr-3 font-semibold">Rule</th>
                  <th className="py-1.5 pr-3 font-semibold">When</th>
                  <th className="py-1.5 pr-3 font-semibold">Action</th>
                  <th className="py-1.5 font-semibold">Reason</th>
                </tr>
              </thead>
              <tbody>
                {(st?.rules ?? []).map((r, i) => (
                  <tr key={r.name} className="border-b border-line-1/60 align-top">
                    <td className="py-1.5 pr-3 tabular-nums text-fg-3">{i + 1}</td>
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-1">
                      {r.name}
                      {st?.demoted_rules?.[r.name] !== undefined && (
                        <>
                          {" "}
                          <Pill variant="warn" title={st.demoted_rules[r.name]}>
                            demoted
                          </Pill>
                        </>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">{r.when}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{r.action}</td>
                    <td className="py-1.5">
                      <Pill variant="neutral">{r.reason}</Pill>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section
        title="Decisions feed"
        helpId="chart.routing_decisions"
        right={
          <>
            <select value={reason} onChange={(e) => setParam("reason", e.target.value)} className={SELECT_CLASS}>
              <option value="">all reasons</option>
              {(decisions.data?.reasons ?? []).map((rc) => (
                <option key={rc} value={rc} title={REASON_DOCS[rc]}>
                  {rc}
                </option>
              ))}
            </select>
            <SegmentedControl<AppliedFilter>
              size="sm"
              options={[
                { value: "", label: "All" },
                { value: "true", label: "Applied" },
                { value: "false", label: "Advised" },
              ]}
              value={appliedFilter}
              onChange={(v) => setParam("applied", v)}
            />
            <span className="text-[11px] text-fg-3">
              {decisions.data ? `${fmtInt(decisions.data.total)} decisions ${winLabel}` : ""}
            </span>
          </>
        }
      >
        {decisions.loading ? (
          <Loading />
        ) : decisionRows.length === 0 ? (
          <div className="py-8 text-center text-[12px] text-fg-3">
            No routing decisions in this window. Routing is opt-in and advise-first - preview the value first (the
            card above, while routing is off), enable advise via Settings → Routing, route traffic through the proxy,
            then watch decisions land here (<code className="rounded-1 bg-bg-2 px-1">observer routing advise</code>{" "}
            for the CLI view).
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-1.5 pr-3 font-semibold">When</th>
                  <th className="py-1.5 pr-3 font-semibold">Kind</th>
                  <th className="py-1.5 pr-3 font-semibold">Route</th>
                  <th className="py-1.5 pr-3 font-semibold">Mode</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Est. savings</th>
                  <th className="py-1.5 font-semibold">Reasons</th>
                </tr>
              </thead>
              <tbody>
                {decisionRows.map((d) => (
                  <Fragment key={d.ID}>
                    <tr
                      onClick={() => setExpanded(expanded === d.ID ? null : d.ID)}
                      className="cursor-pointer border-b border-line-1/60 transition-colors hover:bg-bg-2/60"
                    >
                      <td className="whitespace-nowrap py-1.5 pr-3 text-fg-3">
                        {fmtClock(d.Timestamp)}
                      </td>
                      <td className="py-1.5 pr-3">
                        <Pill variant="neutral">{d.TurnKind}</Pill>
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">
                        {d.OriginalModel}
                        {d.SelectedModel !== d.OriginalModel ? (
                          <>
                            {" "}
                            <span className="text-fg-3">→</span>{" "}
                            <span className="text-fg-1">{d.SelectedModel}</span>
                          </>
                        ) : null}
                      </td>
                      <td className="py-1.5 pr-3">
                        {d.Applied ? <Pill variant="warn">applied</Pill> : <Pill variant="info">{d.Mode}</Pill>}
                      </td>
                      <td className="whitespace-nowrap py-1.5 pr-3 text-right tabular-nums text-fg-2">
                        {fmtUSD(d.EstSavingsUSD)}
                      </td>
                      <td className="py-1.5 text-[11px] text-fg-3">{(d.ReasonCodes ?? []).join(", ")}</td>
                    </tr>
                    {expanded === d.ID && (
                      <tr className="border-b border-line-1/60">
                        <td colSpan={6} className="rounded-1 bg-bg-2 px-3 py-2 text-[11px] leading-relaxed text-fg-2">
                          <div className="space-y-1.5">
                            <div>
                              decision <code className="font-mono">{d.ID}</code> · session{" "}
                              {d.SessionID ? (
                                <Link
                                  to={`/sessions?session=${encodeURIComponent(d.SessionID)}`}
                                  className="font-mono text-accent hover:underline"
                                >
                                  {d.SessionID}
                                </Link>
                              ) : (
                                <code className="font-mono">(none)</code>
                              )}
                              {d.APITurnID != null ? (
                                <>
                                  {" "}
                                  · api turn <code className="font-mono">{d.APITurnID}</code>
                                </>
                              ) : (
                                " · turn never landed"
                              )}
                              {d.Tool ? ` · ${d.Tool}` : ""}
                              {d.ProjectRoot ? (
                                <>
                                  {" "}
                                  · <code className="font-mono">{d.ProjectRoot}</code>
                                </>
                              ) : null}
                            </div>
                            {(d.ReasonCodes ?? []).length > 0 && (
                              <ul className="space-y-0.5">
                                {(d.ReasonCodes ?? []).map((rc) => (
                                  <li key={rc}>
                                    <code className="font-mono text-fg-1">{rc}</code>
                                    {REASON_DOCS[rc] ? <span className="text-fg-3"> - {REASON_DOCS[rc]}</span> : null}
                                  </li>
                                ))}
                              </ul>
                            )}
                            <div>
                              policy <code className="font-mono">{d.PolicyName}</code> @{" "}
                              <code className="font-mono">{d.PolicyHash}</code> · economics: est. savings{" "}
                              <span className="font-semibold text-fg-1">{fmtUSD(d.EstSavingsUSD)}</span> net of cache
                              forfeit {fmtUSD(d.CacheForfeitUSD)}{" "}
                              <span className="text-fg-3">
                                (what abandoning the warm prompt-cache prefix would cost - already deducted;{" "}
                                {d.EstimateVersion})
                              </span>
                            </div>
                            <div className="text-fg-3">
                              CLI: <code className="font-mono">observer routing explain {d.ID}</code>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title={`Savings by tier - ${winLabel}`} helpId="chart.routing_savings" sub={sv?.note}>
        {savings.loading ? (
          <Loading />
        ) : (sv?.by_tier ?? []).length === 0 ? (
          <div className="py-6 text-center text-[12px] text-fg-3">
            No graded savings yet - rows appear once decisions land in this window.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-1.5 pr-3 font-semibold">Group</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">n</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Reroutes</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Realized (est.)</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Would-have</th>
                  <th className="py-1.5 text-right font-semibold">$/decision ± CI95</th>
                </tr>
              </thead>
              <tbody>
                {(sv?.by_tier ?? []).map((g) => (
                  <tr key={g.key} className="border-b border-line-1/60">
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-1">{g.key}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtInt(g.decisions)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtInt(g.reroutes)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtUSD(g.realized_usd)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtUSD(g.would_have_usd)}</td>
                    <td className="py-1.5 text-right tabular-nums text-fg-2">
                      {g.mean_per_decision_usd.toFixed(4)} ± {g.ci95_per_decision_usd.toFixed(4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section
        title="Tier map"
        helpId="chart.routing_tiers"
        sub="Pills with counts carry observed calibration evidence (hover for per-kind error rates). Evidence is correlational - deltas act only past the §R7.2 thresholds."
      >
        {tiers.loading ? (
          <Loading />
        ) : (
          <div className="space-y-2">
            {TIER_ORDER.map((tier) => {
              const models = tiers.data?.tiers?.[tier] ?? [];
              if (models.length === 0) return null;
              return (
                <div key={tier} className="flex items-baseline gap-2">
                  <span className="w-28 shrink-0 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                    {tier}
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {models.map((m) => {
                      const cal = (tiers.data?.calibration ?? []).filter(
                        (c) => c.model === m && c.project_id === 0,
                      );
                      return (
                        <Pill
                          key={m}
                          variant={cal.length > 0 ? "info" : "neutral"}
                          title={
                            cal.length > 0
                              ? cal
                                  .map((c) => `${c.turn_kind}: n=${c.n} err=${(c.error_rate * 100).toFixed(1)}%`)
                                  .join("; ")
                              : "no calibration evidence yet"
                          }
                        >
                          {m}
                          {cal.length > 0 ? ` (${cal.reduce((a, c) => a + c.n, 0)})` : ""}
                        </Pill>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Section>

      <Section
        title="Health board (observed)"
        helpId="chart.routing_health"
        sub="429/5xx rates from the node's own api_turns stream - the observations the §R12.3 circuit breakers act on."
      >
        {health.loading ? (
          <Loading />
        ) : (health.data?.models ?? []).length === 0 ? (
          <div className="py-6 text-center text-[12px] text-fg-3">no proxied turns observed yet</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-1.5 pr-3 font-semibold">Model</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Turns 1h</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Errors 1h</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Turns 24h</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Errors 24h</th>
                  <th className="py-1.5 text-right font-semibold">Error rate 24h</th>
                </tr>
              </thead>
              <tbody>
                {(health.data?.models ?? []).map((h) => (
                  <tr key={h.model} className="border-b border-line-1/60">
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-1">{h.model || "(unknown)"}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtInt(h.turns_1h)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtInt(h.errors_1h)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtInt(h.turns_24h)}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">{fmtInt(h.errors_24h)}</td>
                    <td className="py-1.5 text-right tabular-nums">
                      {h.error_rate_24h >= 0.25 ? (
                        <Pill variant="danger">{(h.error_rate_24h * 100).toFixed(1)}%</Pill>
                      ) : (
                        <span className="text-fg-2">{(h.error_rate_24h * 100).toFixed(1)}%</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}

const actionBtn =
  "rounded-2 border border-line-1 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-1 hover:border-line-2 hover:text-fg-0 disabled:opacity-50";

// ReadinessLadder — the R1.3 explanation of ready_to_promote: the four
// mechanical criteria the §R22 gate checks (the backend computes the
// boolean; this renders WHY), each failing rung carrying its concrete
// next step. The gate is evidence, not the decision — promotion stays
// operator-judged.
function ReadinessLadder({ sh }: { sh: ShadowReport }) {
  const flaggedKinds = Object.entries(sh.quality_flags_by_turn_kind ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([k, n]) => `${k}×${n}`)
    .join(", ");
  const rungs: { ok: boolean; label: string; next?: string }[] = [
    {
      ok: sh.advise_decisions >= sh.min_decisions,
      label: `Evidence volume - ${fmtInt(sh.advise_decisions)} of ${fmtInt(sh.min_decisions)} advise decisions`,
      next: `keep advise mode running: ${fmtInt(Math.max(0, sh.min_decisions - sh.advise_decisions))} more decisions needed`,
    },
    {
      ok: sh.would_reroute > 0,
      label: `Reroutes proposed - ${fmtInt(sh.would_reroute)} in the window`,
      next: "the policy never proposed a reroute here - there is nothing enforce would change; try a different template via Preview or widen the window",
    },
    {
      ok: sh.would_save_usd > 0,
      label: `Net savings positive - ${fmtUSD(sh.would_save_usd)} after cache forfeits`,
      next: "proposed moves don't pay for their cache forfeits in this window - enforce would not help",
    },
    {
      ok: sh.quality_flags === 0,
      label:
        sh.quality_flags === 0
          ? "Zero quality flags - every proposed move is evidence-backed"
          : `Quality flags - ${fmtInt(sh.quality_flags)} proposed moves lack parity evidence${flaggedKinds ? ` (${flaggedKinds})` : ""}`,
      next: "investigate the flagged kinds and grow calibration evidence: observer model-value --save-calibration",
    },
  ];
  return (
    <ul className="mt-3 space-y-1">
      {rungs.map((r) => (
        <li key={r.label} className="flex items-baseline gap-2 text-[11.5px]">
          <span className={r.ok ? "text-success" : "text-danger"}>{r.ok ? "✓" : "✗"}</span>
          <span className="text-fg-2">
            {r.label}
            {!r.ok && r.next && <span className="text-fg-3"> - {r.next}</span>}
          </span>
        </li>
      ))}
    </ul>
  );
}

// PromoteControl — the R1.3 consent-gated advise → enforce promotion.
// Rendered only while routing runs in advise mode. The confirm dialog
// restates the shadow evidence (and is LOUD when the §R22 gate is not
// met — shown, never hidden, never pre-selected); the write rides the
// one config seam and is restart-honest.
function PromoteControl({ sh }: { sh: ShadowReport }) {
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  const promote = async () => {
    setSaving(true);
    setError("");
    try {
      const cfg = await fetchJSON<{ config: { Routing: Record<string, unknown> } }>("/api/config");
      const sec = { ...cfg.config.Routing, Enabled: true, Mode: "enforce" };
      await fetchJSON("/api/config/section/routing", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(sec),
      });
      markRestartPending("routing");
      setSaved(true);
      setConfirming(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  if (saved) {
    return (
      <div className="mt-3">
        <Pill variant="warn">saved: enforce mode - restart the daemon to apply</Pill>
      </div>
    );
  }
  return (
    <div className="mt-3">
      {confirming ? (
        <div className="rounded-2 border border-line-1 bg-bg-2 p-3 text-[11.5px]">
          {!sh.ready_to_promote && (
            <p className="mb-2 font-semibold text-danger">
              The §R22 gate is NOT met - the rungs above show what's missing. Promoting now goes against the
              evidence; the decision is yours.
            </p>
          )}
          <p className="text-fg-2">
            Enforce rewrites the model on proxied requests (same provider shape, fail-open on any internal error).
            The shadow says: {fmtInt(sh.would_reroute)} reroutes would have applied over {sh.window_days} days,
            saving {fmtUSD(sh.would_save_usd)} net, {fmtInt(sh.quality_flags)} quality flags. You can demote back
            to advise at any time in Settings → Routing.
          </p>
          <div className="mt-2 flex items-center gap-2">
            <button type="button" className={actionBtn} disabled={saving} onClick={promote}>
              {saving ? "Saving…" : "Promote to enforce"}
            </button>
            <button type="button" className={actionBtn} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
          {error && <p className="mt-2 text-danger">{error}</p>}
        </div>
      ) : (
        <button type="button" className={actionBtn} onClick={() => setConfirming(true)}>
          Promote to enforce…
          <HelpInd id="card.routing_promote" />
        </button>
      )}
    </div>
  );
}

// DeltaLines renders the §R7.2 parity rows for a target model - honest
// about absence: no graded rows means the observed profile is the
// whole basis, stated rather than invented.
function DeltaLines({ deltas }: { deltas: ApplyDelta[] | null | undefined }) {
  if (!deltas || deltas.length === 0) {
    return (
      <p className="text-[11px] text-fg-3">
        No graded parity deltas for the target model in this window - the observed profile above is the whole basis.
      </p>
    );
  }
  return (
    <ul className="space-y-0.5 text-[11px] text-fg-3">
      {deltas.map((d) => (
        <li key={`${d.turn_kind}|${d.baseline_model}`} className="font-mono">
          {d.turn_kind}: Δerr {d.delta_error_rate_pp >= 0 ? "+" : ""}
          {d.delta_error_rate_pp.toFixed(1)}pp ± {d.error_ci95_pp.toFixed(1)}pp vs {d.baseline_model} (n{" "}
          {fmtInt(d.n_candidate)} vs {fmtInt(d.n_baseline)}; {d.verdict}
          {d.verdict_basis ? `, ${d.verdict_basis}` : ""})
        </li>
      ))}
    </ul>
  );
}

// ApplyChangeRow - one planned claude-code edit with its evidence and
// the per-write consent flow (wizard semantics: this row's Apply
// confirms exactly ONE file write; the server re-validates against a
// fresh plan before touching disk).
function ApplyChangeRow({ tool, days, change }: { tool: string; days: number; change: ApplyChange }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [backup, setBackup] = useState("");
  const [error, setError] = useState("");

  const apply = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await fetchJSON<{ written: boolean; backup: string }>("/api/routing/apply", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool, path: change.path, to_model: change.to_model, days }),
      });
      setBackup(r.backup);
      setConfirming(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const ev = change.evidence;
  const failurePct = ev.actions > 0 ? ((ev.failures / ev.actions) * 100).toFixed(0) : "0";
  return (
    <div className="rounded-2 border border-line-1 bg-bg-2/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <code className="font-mono text-[11px] text-fg-1">{change.path}</code>
        {backup ? (
          <Pill variant="success">written</Pill>
        ) : (
          <button type="button" className={actionBtn} onClick={() => setConfirming(true)} disabled={confirming}>
            Apply…
          </button>
        )}
      </div>
      <p className="mt-1 font-mono text-[11px] text-fg-2">
        model: {change.from_model || "(inherited)"} <span className="text-fg-3">→</span>{" "}
        <span className="text-fg-1">{change.to_model}</span>
      </p>
      <p className="mt-1 text-[11.5px] text-fg-2">{change.rationale}</p>
      <p className="mt-1.5 text-[11px] text-fg-3">
        evidence: {fmtInt(ev.actions)} sidechain actions / {fmtInt(ev.sessions)} session(s) - {fmtInt(ev.reads)}{" "}
        reads, {fmtInt(ev.mutations)} mutations, {fmtInt(ev.commands)} commands, {failurePct}% failures
      </p>
      <div className="mt-1">
        <DeltaLines deltas={change.deltas} />
      </div>
      {confirming && !backup && (
        <div className="mt-2 rounded-2 border border-line-1 bg-bg-2 p-3 text-[11.5px]">
          <p className="text-fg-2">
            Writes <code className="font-mono">model: {change.to_model}</code> into this file's frontmatter - every
            other byte preserved. A <code className="font-mono">.bak-observer-&lt;stamp&gt;</code> backup lands next
            to the file; Revert restores it. claude-code picks the change up at the next session spawn - no observer
            restart.
          </p>
          <div className="mt-2 flex items-center gap-2">
            <button type="button" className={actionBtn} disabled={busy} onClick={apply}>
              {busy ? "Writing…" : "Write this file"}
            </button>
            <button type="button" className={actionBtn} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {backup && (
        <p className="mt-1.5 text-[11px] text-fg-3">
          backup: <code className="font-mono">{backup}</code>
        </p>
      )}
      {error && <p className="mt-1.5 text-[11.5px] text-danger">{error}</p>}
    </div>
  );
}

// ApplyBackupRow - one restorable observer backup with the per-file
// revert consent flow.
function ApplyBackupRow({ backup }: { backup: ApplyBackup }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [restored, setRestored] = useState(false);
  const [error, setError] = useState("");

  const revert = async () => {
    setBusy(true);
    setError("");
    try {
      await fetchJSON("/api/routing/apply/revert", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: backup.path }),
      });
      setRestored(true);
      setConfirming(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 text-[11.5px]">
      <code className="font-mono text-[11px] text-fg-2">{backup.path}</code>
      <div className="flex items-center gap-2">
        <span className="text-fg-3">stamp {backup.stamp}</span>
        {restored ? (
          <Pill variant="success">restored</Pill>
        ) : confirming ? (
          <>
            <button type="button" className={actionBtn} disabled={busy} onClick={revert}>
              {busy ? "Restoring…" : "Restore newest backup"}
            </button>
            <button type="button" className={actionBtn} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button type="button" className={actionBtn} onClick={() => setConfirming(true)}>
            Revert…
          </button>
        )}
      </div>
      {error && <p className="w-full text-danger">{error}</p>}
    </div>
  );
}

// RoutingApplyCard - the R2.1 Channel A surface (§R10): per-tool
// dry-run preview from /api/routing/apply, one consent per file write
// for claude-code, copyable native-config snippets for paste-emission
// tools, and the honest advisory-only answer for cursor/copilot.
// Channel A is independent of the proxy router, so the card shows
// regardless of whether routing is enabled.
function RoutingApplyCard({ days }: { days: number }) {
  const [tool, setTool] = useState("claude-code");
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<ApplyPreview | null>(null);
  const [ledger, setLedger] = useState<ApplyLedgerResponse | null>(null);
  const [error, setError] = useState("");

  const run = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await fetchJSON<ApplyPreview>("/api/routing/apply", { tool, days });
      setPreview(r);
      // The audit trail rides along with writable previews - "what
      // did observer change?" (R2.5). Best-effort: a ledger fetch
      // failure never blocks the preview.
      if (r.mode === "writable") {
        try {
          setLedger(await fetchJSON<ApplyLedgerResponse>("/api/routing/apply/ledger", { limit: 20 }));
        } catch {
          setLedger(null);
        }
      }
    } catch (e: unknown) {
      setPreview(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const changes = preview?.changes ?? [];
  const skipped = preview?.skipped ?? [];
  const backups = preview?.backups ?? [];

  return (
    <Section
      title="Apply to tools (Channel A)"
      helpId="card.routing_apply"
      sub="Turn the observed sub-agent evidence into each tool's native config - dry-run preview first; claude-code writes are per-file, consented, backed up, and revertable. CLI: observer routing apply --tool <tool>."
      right={
        <>
          <select
            value={tool}
            onChange={(e) => {
              setTool(e.target.value);
              setPreview(null);
            }}
            className={SELECT_CLASS}
          >
            {APPLY_TOOLS.map((tl) => (
              <option key={tl} value={tl}>
                {tl}
              </option>
            ))}
          </select>
          <button type="button" className={actionBtn} disabled={busy} onClick={run}>
            {busy ? "Planning…" : preview ? "Re-run preview" : "Preview"}
          </button>
        </>
      }
    >
      {!preview && !busy && !error && (
        <p className="text-[12px] text-fg-3">
          Pick a tool and run the preview - a dry run over the §R10.3 evidence (which sub-agent personas ran
          read-shaped work on bigger models than their observed profile needs). Nothing is written without a per-file
          confirmation.
        </p>
      )}
      {error && <p className="text-[12px] text-danger">{error}</p>}
      {preview?.mode === "advisory" && <p className="text-[12px] leading-relaxed text-fg-2">{preview.note}</p>}
      {preview?.mode === "snippet" && (
        <div className="space-y-2">
          <p className="text-[12px] text-fg-2">
            Evidence-backed weak model: <code className="font-mono text-fg-1">{preview.weak_model}</code> - paste the
            block into the tool's own config (observer does not write this tool's files):
          </p>
          <CopyOnClick value={preview.snippet ?? ""} title="Copy the snippet">
            <pre className="overflow-x-auto rounded-2 border border-line-1 bg-bg-2 p-3 text-left font-mono text-[11px] leading-relaxed text-fg-2">
              {preview.snippet}
            </pre>
          </CopyOnClick>
          <DeltaLines deltas={preview.deltas} />
          <p className="text-[11px] leading-snug text-fg-3">{preview.note}</p>
        </div>
      )}
      {preview?.mode === "writable" && (
        <div className="space-y-3">
          {changes.length === 0 ? (
            <p className="text-[12px] text-fg-3">
              No actionable per-subagent changes - every evidence-backed persona is already at its target (or no
              sidechain evidence has cleared the §R7.2 floor yet).
            </p>
          ) : (
            <div className="space-y-2">
              {changes.map((c) => (
                <ApplyChangeRow key={c.path} tool={tool} days={days} change={c} />
              ))}
            </div>
          )}
          {skipped.length > 0 && (
            <ul className="space-y-0.5 text-[11px] text-fg-3">
              {skipped.map((sk) => (
                <li key={sk}>note: {sk}</li>
              ))}
            </ul>
          )}
          {backups.length > 0 && (
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                  SuperBased backups (revertable)
                </h3>
                <RevertAllControl count={backups.length} />
              </div>
              {backups.map((b) => (
                <ApplyBackupRow key={b.path} backup={b} />
              ))}
            </div>
          )}
          {ledger && ledger.events.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                Change history - what observer changed
              </h3>
              {ledger.events.map((ev, i) => (
                <div key={`${ev.time}-${i}`} className="flex flex-wrap items-center gap-1.5 text-[11px] text-fg-3">
                  <span className="whitespace-nowrap">{fmtDateTime(ev.time)}</span>
                  <Pill variant={ev.kind === "revert" ? "neutral" : "info"}>{ev.kind}</Pill>
                  <code className="font-mono text-fg-2">{ev.path}</code>
                  {ev.kind === "write" && (
                    <span className="font-mono">
                      {ev.from_model || "(inherited)"} → {ev.to_model}
                    </span>
                  )}
                  <span>({ev.source})</span>
                </div>
              ))}
              <p className="text-[10.5px] text-fg-3">
                Append-only node-local ledger ({ledger.path}) - records both CLI and dashboard writes/reverts. CLI
                view: <code className="font-mono">observer routing apply --history</code>.
              </p>
            </div>
          )}
          <p className="text-[11px] leading-snug text-fg-3">{preview.note}</p>
        </div>
      )}
    </Section>
  );
}

// RevertAllControl - the R2.5 unified revert: one consented operation
// restoring EVERY agent file that has an observer backup (the CLI
// --revert contract).
function RevertAllControl({ count }: { count: number }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<number | null>(null);
  const [error, setError] = useState("");

  const revertAll = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await fetchJSON<{ restored: boolean; count: number }>("/api/routing/apply/revert", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ all: true }),
      });
      setDone(r.count);
      setConfirming(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (done !== null) {
    return <Pill variant="success">restored {done} file(s)</Pill>;
  }
  return (
    <span className="flex items-center gap-2">
      {confirming ? (
        <>
          <span className="text-[11px] text-fg-3">Restore every file from its newest observer backup?</span>
          <button type="button" className={actionBtn} disabled={busy} onClick={revertAll}>
            {busy ? "Restoring…" : `Restore all (${count})`}
          </button>
          <button type="button" className={actionBtn} onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </>
      ) : (
        <button type="button" className={actionBtn} onClick={() => setConfirming(true)}>
          Revert all…
        </button>
      )}
      {error && <span className="text-[11px] text-danger">{error}</span>}
    </span>
  );
}

// RoutingPreviewCard - the R1.2 adoption-funnel CTA, shown only while
// routing is OFF. One click POSTs /api/routing/simulate (a read-only
// counterfactual replay of recorded turns - no restart, no traffic
// touched) and renders the breakdown; from the result, an explicit
// consent flow can enable advise mode through the one config seam
// (restart-honest, mirroring the Security page's mode control).
function RoutingPreviewCard() {
  const [template, setTemplate] = useState("value");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SimulateResponse | null>(null);
  const [error, setError] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [enabling, setEnabling] = useState(false);
  const [enabled, setEnabled] = useState(false);

  const preview = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await fetchJSON<SimulateResponse>("/api/routing/simulate", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policy: template, days: 30 }),
      });
      setResult(r);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const enableAdvise = async () => {
    setEnabling(true);
    setError("");
    try {
      // Whole-section write through the one config seam: take the
      // on-disk Routing section, flip enabled + mode + the chosen
      // template, PUT it back. key_pool / rules / tiers and every
      // other file-only shape survive server-side regardless.
      const cfg = await fetchJSON<{ config: { Routing: Record<string, unknown> } }>("/api/config");
      const sec = { ...cfg.config.Routing, Enabled: true, Mode: "advise", Policy: template };
      await fetchJSON("/api/config/section/routing", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(sec),
      });
      markRestartPending("routing");
      setEnabled(true);
      setConfirming(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setEnabling(false);
    }
  };

  const rep = result?.report;
  const topMoves = (rep?.moves ?? []).slice(0, 6);

  return (
    <Section
      title="Preview savings"
      helpId="card.routing_preview"
      sub="Routing is off. Preview what a policy would have saved over your last 30 days - a read-only replay of recorded turns. No restart, no traffic touched, nothing persisted."
      right={
        <>
          <select value={template} onChange={(e) => setTemplate(e.target.value)} className={SELECT_CLASS}>
            {SIM_TEMPLATES.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <button type="button" className={actionBtn} disabled={busy} onClick={preview}>
            {busy ? "Replaying…" : rep ? "Re-run preview" : "Preview savings"}
          </button>
        </>
      }
    >
      {!rep && !busy && !error && (
        <p className="text-[12px] text-fg-3">
          Pick a policy template and run the preview - the answer comes from your own recorded traffic, not a
          brochure.
        </p>
      )}
      {error && <p className="text-[12px] text-danger">{error}</p>}
      {rep && (
        <div className="space-y-3">
          <p className="text-[12px] leading-relaxed text-fg-2">
            Over the last {result!.window_days} days, the <span className="font-semibold text-fg-1">{rep.policy_name}</span>{" "}
            policy would have rerouted <span className="font-semibold text-fg-1">{fmtInt(rep.would_reroute)}</span> of{" "}
            {fmtInt(rep.turns_evaluated)} turns, saving an estimated{" "}
            <span className="font-semibold text-fg-1">{fmtUSD(rep.est_savings_usd)}</span> net (cache forfeits of{" "}
            {fmtUSD(rep.cache_forfeit_usd)} already deducted), with{" "}
            <span className="font-semibold text-fg-1">{fmtInt(rep.quality_risk_flags)}</span> quality-risk flags
            (reroutes lacking parity evidence).
          </p>
          {topMoves.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-auto text-left text-[12px]">
                <thead>
                  <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                    <th className="py-1 pr-4 font-semibold">From</th>
                    <th className="py-1 pr-4 font-semibold">To</th>
                    <th className="py-1 pr-4 text-right font-semibold">Turns</th>
                    <th className="py-1 text-right font-semibold">Est. $</th>
                  </tr>
                </thead>
                <tbody>
                  {topMoves.map((m) => (
                    <tr key={`${m.from}→${m.to}`} className="border-b border-line-1/60">
                      <td className="py-1 pr-4 font-mono text-[11px] text-fg-2">{m.from}</td>
                      <td className="py-1 pr-4 font-mono text-[11px] text-fg-1">{m.to}</td>
                      <td className="py-1 pr-4 text-right tabular-nums text-fg-2">{fmtInt(m.count)}</td>
                      <td className="py-1 text-right tabular-nums text-fg-2">{fmtUSD(m.est_savings_usd)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="text-[11px] leading-snug text-fg-3">{result!.note}</p>
          {enabled ? (
            <Pill variant="warn">saved: advise mode ({template}) - restart the daemon to apply</Pill>
          ) : confirming ? (
            <div className="rounded-2 border border-line-1 bg-bg-2 p-3 text-[11.5px]">
              <p className="text-fg-2">
                Advise mode only <strong className="font-semibold">records</strong> what routing would have done -
                decision rows accrue on this page, requests are untouched. Promotion to enforce stays a separate,
                evidence-gated step on the Shadow card. Saves <code className="font-mono">[routing]</code> in this
                node's config.toml; the daemon binds it at next restart.
              </p>
              <div className="mt-2 flex items-center gap-2">
                <button type="button" className={actionBtn} disabled={enabling} onClick={enableAdvise}>
                  {enabling ? "Saving…" : `Enable advise mode (${template})`}
                </button>
                <button type="button" className={actionBtn} onClick={() => setConfirming(false)}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button type="button" className={actionBtn} onClick={() => setConfirming(true)}>
              Enable advise mode…
            </button>
          )}
        </div>
      )}
    </Section>
  );
}

// Section mirrors the Security page's card shape (the house pattern
// for non-chart sections: bg-bg-1 cards with a 13px semibold title
// row and optional right-side controls). helpId renders the inline
// help indicator next to the title, drawer-linked like every other
// page's section titles.
function Section({
  title,
  helpId,
  sub,
  right,
  children,
}: {
  title: ReactNode;
  helpId?: string;
  sub?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-3 border border-line-1 bg-bg-1 p-4">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-[13px] font-semibold text-fg-0">
            {title}
            {helpId && <HelpInd id={helpId} />}
          </h2>
          {sub && <p className="mt-0.5 max-w-3xl text-[11.5px] leading-snug text-fg-3">{sub}</p>}
        </div>
        {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
      </div>
      {children}
    </section>
  );
}

function Loading() {
  return <div className="py-8 text-center text-[12px] text-fg-3">Loading…</div>;
}
