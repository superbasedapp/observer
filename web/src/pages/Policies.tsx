import { useState } from "react";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  InlineLoading,
  PageHeader,
  SegmentedControl,
  StatCard,
  StatStrip,
  TabStrip,
  VocabDefPill,
  type TabDef,
} from "@/components/primitives";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { useApi } from "@/lib/useApi";
import { useUrlTab } from "@/lib/useUrlTab";
import { useHrefGate, usePageTabs } from "@/lib/governance";
import { POLICIES_TABS, defaultTab, type PoliciesTab } from "@/lib/nodePageTabs";
import { ApiError, fetchJSON } from "@/lib/api";
import { fmtInt, fmtShortId, fmtUSD } from "@/lib/format";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import { vocabView } from "@shared/lib/vocabEntry";
import { VocabPill } from "@shared/lib/vocabPill";
import { ADMISSION_DECISION, judgeHostingLabel } from "@shared/lib/obsVocab";
import { AUDIT_CHAIN } from "@/lib/vocabTones";
import { ActivityTab } from "./policies/Activity";
import { GuardrailsTab } from "./policies/Guardrails";
import { RoutingTab } from "./policies/Routing";
import { TemplatesTab } from "./policies/Templates";
import { TestTab } from "./policies/Test";
import { POLICY_MODE_LABEL, wordsFor } from "./policies/vocab";
import {
  type AdmissionMode,
  type AdmissionPolicyGet,
  type EgressMode,
  type EgressPolicyGet,
  applyAdmissionPolicy,
  policyErrorText,
  policyStatusText,
  postPolicy,
} from "./policies/types";
import { AdmissionOff, AdmissionOffNote, AdmissionStartsNext, LiveUnsaved } from "./policies/AdmissionOff";
import { admissionCard } from "./policies/applyRule";
import { navIcon } from "@/lib/nav";
import { ObsDisabled } from "@/components/ObsDisabled";
import { OrgAppBudgetCard, type OrgAppCap } from "@/components/OrgAppBudgetCard";
import {
  FlaskConical,
  History,
  LayoutDashboard,
  LayoutTemplate,
  Route,
  ShieldHalf,
  type LucideIcon,
} from "lucide-react";
import { MetricIcon } from "@/components/MetricIcon";
import { PLACES } from "@/lib/settingsPlaces";

// Policies page (Plane-A admission + egress policy AUTHORING) - the write
// counterpart to the read-only Egress page. It lets the app operator author
// the input-admission guardrails ([observability.admission]) and the egress
// routing policy ([observability.egress]) from the dashboard instead of
// hand-editing config.toml. Node-local: admission/egress policy has no remote
// apply (an org admin can VIEW admission on web2 but never push policy to a
// node), so the authoring surface belongs here on the node dashboard.
//
// HONESTY NOTE that shapes the UI: under `observer start` the dashboard and
// the proxy share ONE admission service (gap P0-7, cmd/observer obs_wire.go),
// so applying an admission policy changes the SDK front door and the proxy
// check at once, and the page always saves it too (UI review U-27: a live-only
// apply was silently lost on the next restart; /admission/status reports
// live_unsaved when a save failed). Egress routing, the judge binding and the
// per-user budget are read at daemon start and still need a restart. The UI
// must never imply those are instant.

// The page's `?tab=` ids (platform tabs plan 2.2: the tab moved from local
// state to the URL, so every tab is a cold deep link and Back walks tabs).
// The ids and labels live in lib/nodePageTabs.ts (POLICIES_TABS), the table
// the command palette and the breadcrumb read too.
type PolicyTab = PoliciesTab;

// One glyph per Policies tab.
const POLICY_TAB_ICONS: Record<PolicyTab, LucideIcon> = {
  overview: LayoutDashboard,
  templates: LayoutTemplate,
  guardrails: ShieldHalf,
  routing: Route,
  test: FlaskConical,
  activity: History,
};

type AdmissionStatus = {
  // available: admission checks run on this machine at all
  // ([observability.admission] enabled). Absent on an older daemon.
  available?: boolean;
  // pending_next_start: admission is turned on but starts at the next daemon
  // start (FR-M01); available is false until then.
  pending_next_start?: boolean;
  enabled: boolean;
  mode: string;
  judge_hosting: string;
  criteria_count: number;
  policy_hash?: string;
  // A sparse map: a decision key is absent when its 24h count is zero.
  decisions_24h: Partial<Record<"allow" | "flag" | "ask" | "deny", number>>;
  // The live policy applied but did not reach config (U-27).
  live_unsaved?: boolean;
  // state: off | intact | broken | unknown (U-11). Absent on an older daemon.
  chain: { rows: number; ok: boolean; state?: string };
};
type AdmissionBudget = {
  enabled: boolean;
  five_hour_usd: number;
  weekly_usd: number;
  monthly_usd: number;
  breaches_24h: number;
  top_spenders: { user: string; usd: number }[] | null;
  // The organization's app budgets in force here (Plane A W4-1).
  org_applied?: boolean;
  org_authoritative?: boolean;
  org_app_caps?: OrgAppCap[];
};
type EgressStatus = {
  enabled: boolean;
  mode: string;
  policy_hash?: string;
  rules: { name: string; action: string; target?: string }[] | null;
  targets: { id: string; url: string; shape: string }[] | null;
  decisions_by_action: Record<string, number>;
  decisions_24h: number;
  chain: { rows: number; ok: boolean };
};

export function PoliciesPage() {
  // The tabs the organization left visible on this machine (T-132).
  const pageTabs = usePageTabs("policies", POLICIES_TABS);
  const [tab, setTab] = useUrlTab(pageTabs.ids, defaultTab(pageTabs));

  const admission = useApi<AdmissionStatus>("/api/obs/admission/status");
  const budget = useApi<AdmissionBudget>("/api/obs/admission/budget");
  const egress = useApi<EgressStatus>("/api/obs/egress/status");

  // The /api/obs/* routes exist only when [observability] is enabled. When
  // absent the SPA catch-all serves index.html (200) -> a JSON parse error
  // (non-ApiError), or a 404 from a stricter mux. Either means "obs off". A
  // real 5xx is a genuine handler error and renders as an error state.
  const obsOff = [admission.error, budget.error, egress.error].some(
    (e) => e != null && (!(e instanceof ApiError) || e.status === 404),
  );

  const allTabs: TabDef<PolicyTab>[] = [
    { id: "overview", label: POLICIES_TABS.labels.overview, icon: POLICY_TAB_ICONS.overview },
    { id: "templates", label: POLICIES_TABS.labels.templates, icon: POLICY_TAB_ICONS.templates },
    {
      id: "guardrails",
      label: POLICIES_TABS.labels.guardrails,
      icon: POLICY_TAB_ICONS.guardrails,
      count: admission.data?.criteria_count ?? null,
    },
    {
      id: "routing",
      label: POLICIES_TABS.labels.routing,
      icon: POLICY_TAB_ICONS.routing,
      count: egress.data?.rules?.length ?? null,
    },
    { id: "test", label: POLICIES_TABS.labels.test, icon: POLICY_TAB_ICONS.test },
    { id: "activity", label: POLICIES_TABS.labels.activity, icon: POLICY_TAB_ICONS.activity },
  ];
  const tabs = allTabs.filter((t) => pageTabs.ids.includes(t.id));
  const reloadAll = () => {
    admission.reload();
    budget.reload();
    egress.reload();
  };
  // Admission checks are not running here (U-13): the page offers to turn
  // them on instead of controls that would only answer "not enabled".
  const card = admissionCard(admission.data ?? undefined);
  const admissionOff = card !== "none";

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("policies")}
        title="Policies"
        sub="Admission checks and routing rules for your AI apps' end-user traffic. Kept on this machine."
      />

      {obsOff ? (
        <ObsDisabled needs={["observability", "admission"]}>
          Admission and routing policies need AI Apps with admission checks on.
        </ObsDisabled>
      ) : (
        <>
          {card === "starts_next" ? <AdmissionStartsNext /> : card === "off" ? <AdmissionOff /> : <ApplyModeNote />}
          {!admissionOff && admission.data?.live_unsaved && <LiveUnsaved onSaved={admission.reload} />}
          <TabStrip tabs={tabs} value={tab} onChange={setTab} idPrefix="policies" />
          {tab === "overview" && (
            <OverviewTab
              admission={admission}
              budget={budget.data}
              egress={egress}
              reload={reloadAll}
              onReviewActivity={pageTabs.ids.includes("activity") ? () => setTab("activity") : undefined}
            />
          )}
          {tab === "templates" && <TemplatesTab onApplied={reloadAll} />}
          {tab === "guardrails" && (
            <GuardrailsTab
              admissionOff={admissionOff}
              onApplied={() => {
                admission.reload();
                budget.reload();
              }}
            />
          )}
          {tab === "routing" && <RoutingTab onApplied={() => egress.reload()} />}
          {tab === "test" && (admissionOff ? <AdmissionOffNote what="test requests against the policy" /> : <TestTab />)}
          {tab === "activity" && <ActivityTab />}
        </>
      )}
    </div>
  );
}

// ApplyModeNote is the standing honesty note (handover section 1): it names
// the two distinct apply semantics so the operator is never misled into
// thinking an egress or proxy-backstop edit took effect the instant they
// clicked Apply. Stated once per page (Copy rules: "Where explanation
// belongs").
function ApplyModeNote() {
  return (
    <Callout title="When a change applies">
      An admission policy applies at once, on your app's front door and the proxy check, and is saved. Routing, the
      judge and the per-user budget apply after a daemon restart.
    </Callout>
  );
}

type Read<T> = { data?: T | null; error?: Error | null; loading: boolean; reload: () => void };

function OverviewTab({
  admission: admissionRead,
  budget,
  egress: egressRead,
  reload,
  onReviewActivity,
}: {
  admission: Read<AdmissionStatus>;
  budget?: AdmissionBudget | null;
  egress: Read<EgressStatus>;
  reload: () => void;
  onReviewActivity?: () => void;
}) {
  const admission = admissionRead.data;
  const egress = egressRead.data;
  const loading = admissionRead.loading || egressRead.loading;
  // busy guards the mode toggles against double-submits while a POST is in
  // flight; an empty string means idle.
  const [busy, setBusy] = useState<"" | "admission" | "egress">("");
  // The per-user budget is edited in Settings > AI Apps (review E-73): the
  // tile links there when that section is shown on this machine.
  const budgetEditShown = useHrefGate()(PLACES.observability_settings.href) === "shown";

  // setAdmissionMode fetches the CURRENT full policy, swaps only the mode, and
  // applies it live and saved (applyAdmissionPolicy, U-27) so no other field
  // is lost and a restart keeps it.
  async function setAdmissionMode(mode: AdmissionMode) {
    if (busy) return;
    setBusy("admission");
    try {
      const cur = await fetchJSON<AdmissionPolicyGet>("/api/obs/admission/policy");
      const { status, data } = await applyAdmissionPolicy({ ...cur.policy, mode });
      if (status === 409) {
        pushToast(policyStatusText(409), "danger");
        return;
      }
      if (status === 422 || !data.applied) {
        pushToast(data.error || "The mode change was rejected.", "danger");
        return;
      }
      if (!data.persisted) {
        pushToast(`Admission set to ${wordsFor(POLICY_MODE_LABEL, mode)}, but not saved: a daemon restart drops it.`, "warn");
      } else {
        pushToast(`Admission set to ${wordsFor(POLICY_MODE_LABEL, mode)} and saved.`, "success");
      }
      reload();
    } catch (e) {
      pushToast(policyErrorText(e), "danger");
    } finally {
      setBusy("");
    }
  }

  // setEgressMode is Save-oriented: egress only takes real effect on the proxy
  // path, so a live apply just updates the dashboard's preview; the routing
  // change lands on the daemon restart the banner prompts.
  async function setEgressMode(mode: EgressMode) {
    if (busy) return;
    setBusy("egress");
    try {
      const cur = await fetchJSON<EgressPolicyGet>("/api/obs/egress/policy");
      const { status, data } = await postPolicy("/api/obs/egress/policy", { ...cur.policy, mode }, true);
      if (status === 422 || !data.applied) {
        pushToast(data.error || "Mode change rejected", "danger");
        return;
      }
      markRestartPending("egress policy");
      pushToast(`Routing set to ${wordsFor(POLICY_MODE_LABEL, mode)} and saved. Restart the daemon to apply it.`, "success");
      reload();
    } catch (e) {
      pushToast(policyErrorText(e), "danger");
    } finally {
      setBusy("");
    }
  }

  const admDecisions = admission
    ? Object.values(admission.decisions_24h).reduce((a, n) => a + (n ?? 0), 0)
    : 0;
  const egDecisions = egress
    ? Object.values(egress.decisions_by_action).reduce((a, n) => a + n, 0)
    : 0;
  const ruleCount = egress?.rules?.length ?? 0;
  const judge = admission?.judge_hosting ?? "";

  return (
    <div className="space-y-4">
      <StatStrip cols={4} ariaLabel="Policy posture" className="">
        <StatCard
          label="Admission"
          icon={<MetricIcon metric="admission" />}
          loading={loading}
          value={admission ? wordsFor(POLICY_MODE_LABEL, admission.mode) : "-"}
          sub={
            admission?.enabled
              ? `${fmtInt(admission.criteria_count)} criteria, ${fmtInt(admDecisions)} decisions in 24h`
              : admission
                ? "Requests are not checked"
                : undefined
          }
          linkTo={admission && !admission.enabled ? "/policies?tab=guardrails" : undefined}
        />
        <StatCard
          label="Egress routing"
          icon={<MetricIcon metric="egressRouting" />}
          loading={loading}
          value={egress ? wordsFor(POLICY_MODE_LABEL, egress.mode) : "-"}
          sub={
            egress?.enabled
              ? `${fmtInt(ruleCount)} ${ruleCount === 1 ? "rule" : "rules"}, ${fmtInt(egDecisions)} decisions`
              : egress
                ? "Nothing is rerouted"
                : undefined
          }
          linkTo={egress && !egress.enabled ? "/policies?tab=routing" : undefined}
        />
        <StatCard
          label="Judge"
          icon={<MetricIcon metric="judge" />}
          loading={loading}
          value={admission ? (judge ? judgeHostingLabel(judge) : "None") : "-"}
          sub={admission ? judgeHostingNote(judge) : undefined}
          linkTo={admission && (judge === "" || judge === "off") ? "/policies?tab=guardrails" : undefined}
        />
        <StatCard
          label="Per-user budget"
          icon={<MetricIcon metric="budget" />}
          loading={loading}
          warn={!!budget && budget.breaches_24h > 0}
          value={budget ? (budget.enabled ? fmtUSD(budget.five_hour_usd) : "Off") : "-"}
          sub={
            budget
              ? budget.enabled
                ? `per 5 hours, ${fmtInt(budget.breaches_24h)} ${budget.breaches_24h === 1 ? "breach" : "breaches"} in 24h`
                : `No per-user cap${budgetEditShown ? ", set one" : ""}`
              : undefined
          }
          linkTo={budgetEditShown ? PLACES.observability_settings.href : undefined}
        />
      </StatStrip>

      {budget && (budget.org_app_caps?.length ?? 0) > 0 && (
        <OrgAppBudgetCard applied={Boolean(budget.org_applied)} authoritative={Boolean(budget.org_authoritative)} caps={budget.org_app_caps ?? []} />
      )}

      <ShadowNudge admission={admission} egress={egress} onReview={onReviewActivity} />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card title="Admission posture">
          {admission ? (
            <DefinitionList>
              <DefinitionRow
                label="Mode"
                value={
                  admission.available === false ? (
                    <span className="font-normal text-fg-3">Checks are off on this machine</span>
                  ) : (
                    <SegmentedControl<AdmissionMode>
                      size="sm"
                      options={[
                        { value: "off", label: "Off" },
                        { value: "observe", label: "Observe" },
                        { value: "enforce", label: "Enforce" },
                      ]}
                      value={(admission.mode as AdmissionMode) || "off"}
                      onChange={setAdmissionMode}
                    />
                  )
                }
              />
              <DefinitionRow label="Criteria" value={fmtInt(admission.criteria_count)} />
              <DefinitionRow label="Judge" value={judge ? judgeHostingLabel(judge) : "None"} />
              <DefinitionRow label="Decisions in 24h" value={<DecisionBreakdown d={admission.decisions_24h} />} />
              <DefinitionRow
                label="Audit log"
                value={<ChainPill ok={admission.chain.ok} rows={admission.chain.rows} state={admission.chain.state} />}
              />
              {admission.policy_hash && (
                <DefinitionRow
                  label="Policy version"
                  value={<span className="font-mono text-[11px] font-normal text-fg-3" title={admission.policy_hash}>{fmtShortId(admission.policy_hash, 16)}</span>}
                />
              )}
            </DefinitionList>
          ) : admissionRead.error ? (
            <ErrorState title="Couldn't load the admission status" error={admissionRead.error} onRetry={admissionRead.reload} />
          ) : (
            <InlineLoading label="Loading policy status" />
          )}
        </Card>

        <Card title="Egress posture">
          {egress ? (
            <DefinitionList>
              <DefinitionRow
                label="Mode"
                value={
                  <SegmentedControl<EgressMode>
                    size="sm"
                    options={[
                      { value: "off", label: "Off" },
                      { value: "advise", label: "Advise" },
                      { value: "enforce", label: "Enforce" },
                    ]}
                    value={(egress.mode as EgressMode) || "off"}
                    onChange={setEgressMode}
                  />
                }
              />
              <DefinitionRow label="Rules" value={fmtInt(ruleCount)} />
              <DefinitionRow label="Targets" value={fmtInt(egress.targets?.length ?? 0)} />
              <DefinitionRow label="Decisions" value={fmtInt(egDecisions)} />
              <DefinitionRow label="Audit log" value={<ChainPill ok={egress.chain.ok} rows={egress.chain.rows} />} />
              {egress.policy_hash && (
                <DefinitionRow
                  label="Policy version"
                  value={<span className="font-mono text-[11px] font-normal text-fg-3" title={egress.policy_hash}>{fmtShortId(egress.policy_hash, 16)}</span>}
                />
              )}
            </DefinitionList>
          ) : egressRead.error ? (
            <ErrorState title="Couldn't load the routing status" error={egressRead.error} onRetry={egressRead.reload} />
          ) : (
            <InlineLoading label="Loading policy status" />
          )}
        </Card>
      </div>
    </div>
  );
}

// ShadowNudge encourages observe/advise-first rollout, the reference
// deployment's guidance. It only appears when something is already in
// enforce, and links to the verdicts to check (every reason links to its fix).
function ShadowNudge({
  admission,
  egress,
  onReview,
}: {
  admission?: AdmissionStatus | null;
  egress?: EgressStatus | null;
  onReview?: () => void;
}) {
  const enforcing = admission?.mode === "enforce" || egress?.mode === "enforce";
  if (!enforcing) return null;
  return (
    <Callout
      tone="warn"
      title="A policy is enforcing"
      action={
        onReview && (
          <Button size="sm" onClick={onReview}>
            Review verdicts
          </Button>
        )
      }
    >
      It blocks or reroutes end-user traffic. Check that the observe-only verdicts looked right.
    </Callout>
  );
}

// ChainPill renders an audit chain's verification state from AUDIT_CHAIN
// (@/lib/vocabTones) with its row count. A chain that is off (admission not
// running and nothing recorded, U-11) or could not be checked is plain text,
// never "broken".
function ChainPill({ ok, rows, state }: { ok: boolean; rows: number; state?: string }) {
  if (state === "off") return <span className="font-normal text-fg-3">Off, nothing recorded</span>;
  if (state === "unknown") return <span className="font-normal text-fg-3">Not checked</span>;
  const value = (state ?? (ok ? "intact" : "broken")) === "intact" ? "intact" : "broken";
  const v = vocabView("auditChain", AUDIT_CHAIN, value);
  return (
    <VocabPill vocab="auditChain" table={AUDIT_CHAIN} value={value}>
      {v.label}, {fmtInt(rows)} rows
    </VocabPill>
  );
}

function DecisionBreakdown({ d }: { d: AdmissionStatus["decisions_24h"] }) {
  const entries = (["allow", "flag", "ask", "deny"] as const).filter((k) => (d[k] ?? 0) > 0);
  if (entries.length === 0) return <span className="font-normal text-fg-3">None</span>;
  return (
    <span className="inline-flex flex-wrap justify-end gap-1">
      {entries.map((k) => (
        <VocabDefPill key={k} of={ADMISSION_DECISION} value={k}>
          {vocabLabel(k)} {fmtInt(d[k] ?? 0)}
        </VocabDefPill>
      ))}
    </span>
  );
}

function vocabLabel(k: keyof typeof ADMISSION_DECISION.entries): string {
  return ADMISSION_DECISION.entries[k].label ?? k;
}

// JUDGE_HOSTING_NOTE - where the admission judge runs (the Judge tile's
// sub-line). Glyphs: VOCAB_ICONS.judgeHosting.
const JUDGE_HOSTING_NOTE: Readonly<Record<string, string>> = {
  local: "Runs on this machine, no key leaves it",
  aggregator: "Through a model aggregator",
  provider: "Hosted by a model provider",
  private: "Your private endpoint",
  org_relay: "Through your organization",
};

function judgeHostingNote(h?: string): string {
  return (h && JUDGE_HOSTING_NOTE[h]) || "No judge set up yet";
}
