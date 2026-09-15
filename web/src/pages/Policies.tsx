import { useState, type ReactNode } from "react";
import { HeroStat, PageHeader, Pill, SegmentedControl, TabStrip, type TabDef } from "@/components/primitives";
import { ShieldIcon, CompassIcon, CoinsIcon, SparklesIcon } from "@/components/icons";
import { useApi } from "@/lib/useApi";
import { ApiError, fetchJSON } from "@/lib/api";
import { fmtShortId, fmtUSD } from "@/lib/format";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import { ActivityTab } from "./policies/Activity";
import { GuardrailsTab } from "./policies/Guardrails";
import { RoutingTab } from "./policies/Routing";
import { TemplatesTab } from "./policies/Templates";
import { TestTab } from "./policies/Test";
import {
  type AdmissionMode,
  type AdmissionPolicyGet,
  type EgressMode,
  type EgressPolicyGet,
  postPolicy,
} from "./policies/types";

// Policies page (Plane-A admission + egress policy AUTHORING) — the write
// counterpart to the read-only Egress page. It lets the app operator author
// the input-admission guardrails ([observability.admission]) and the egress
// routing policy ([observability.egress]) from the dashboard instead of
// hand-editing config.toml. Node-local: admission/egress policy has no remote
// apply (an org admin can VIEW admission on web2 but never push policy to a
// node), so the authoring surface belongs here on the node dashboard.
//
// HONESTY NOTE that shapes the UI (handover §1): the dashboard and the proxy
// each build their OWN admission-service instance. "Apply live" hot-swaps the
// dashboard's instance — the SDK/harness front-door — immediately. The proxy's
// pre-forward backstop AND all egress routing run on the SEPARATE proxy
// instance, which a live apply does NOT reach: those need Save (persist) + a
// daemon restart. The UI must never imply every edit is instant.

type PolicyTab = "overview" | "templates" | "guardrails" | "routing" | "test" | "activity";

type AdmissionStatus = {
  enabled: boolean;
  mode: string;
  judge_hosting: string;
  criteria_count: number;
  policy_hash?: string;
  // A sparse map — a decision key is absent when its 24h count is zero.
  decisions_24h: Partial<Record<"allow" | "flag" | "ask" | "deny", number>>;
  chain: { rows: number; ok: boolean };
};
type AdmissionBudget = {
  enabled: boolean;
  five_hour_usd: number;
  weekly_usd: number;
  monthly_usd: number;
  breaches_24h: number;
  top_spenders: { user: string; usd: number }[] | null;
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
  const [tab, setTab] = useState<PolicyTab>("overview");

  const admission = useApi<AdmissionStatus>("/api/obs/admission/status");
  const budget = useApi<AdmissionBudget>("/api/obs/admission/budget");
  const egress = useApi<EgressStatus>("/api/obs/egress/status");

  // The /api/obs/* routes exist only when [observability] is enabled. When
  // absent the SPA catch-all serves index.html (200) → a JSON parse error
  // (non-ApiError), or a 404 from a stricter mux. Either means "obs off". A
  // real 5xx is a genuine handler error and renders as an error note.
  const obsOff = [admission.error, budget.error, egress.error].some(
    (e) => e != null && (!(e instanceof ApiError) || e.status === 404),
  );

  const tabs: TabDef<PolicyTab>[] = [
    { id: "overview", label: "Overview" },
    { id: "templates", label: "Templates" },
    { id: "guardrails", label: "Guardrails", count: admission.data?.criteria_count ?? null },
    { id: "routing", label: "Routing", count: egress.data?.rules?.length ?? null },
    { id: "test", label: "Test" },
    { id: "activity", label: "Activity" },
  ];

  return (
    <div className="space-y-4 p-5">
      <PageHeader
        title="Policies"
        sub="Author the Plane-A input-admission guardrails and egress routing policy for a hosted app's end-user traffic - the write counterpart to the read-only Egress and admission views. Node-local: policy is never pushed from an org server."
      />

      {obsOff ? (
        <ObsDisabled />
      ) : (
        <>
          <ApplyModeNote />
          <TabStrip tabs={tabs} value={tab} onChange={setTab} idPrefix="policies" />
          {tab === "overview" && (
            <OverviewTab
              admission={admission.data}
              budget={budget.data}
              egress={egress.data}
              loading={admission.loading || egress.loading}
              reload={() => {
                admission.reload();
                budget.reload();
                egress.reload();
              }}
            />
          )}
          {tab === "templates" && (
            <TemplatesTab
              onApplied={() => {
                admission.reload();
                budget.reload();
                egress.reload();
              }}
            />
          )}
          {tab === "guardrails" && (
            <GuardrailsTab
              onApplied={() => {
                admission.reload();
                budget.reload();
              }}
            />
          )}
          {tab === "routing" && <RoutingTab onApplied={() => egress.reload()} />}
          {tab === "test" && <TestTab />}
          {tab === "activity" && <ActivityTab />}
        </>
      )}
    </div>
  );
}

// ApplyModeNote is the standing honesty banner (handover §1): it names the
// two distinct apply semantics so the operator is never misled into thinking
// an egress or proxy-backstop edit took effect the instant they clicked Apply.
function ApplyModeNote() {
  return (
    <div className="rounded-3 border border-line-1 bg-bg-1 p-3 text-[11.5px] leading-relaxed text-fg-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span className="inline-flex items-center gap-1.5">
          <Pill variant="success">Apply live</Pill>
          hot-swaps the admission front-door (the SDK path) immediately.
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Pill variant="warn">Save &amp; restart</Pill>
          is required for the proxy backstop and all egress routing to change.
        </span>
      </div>
    </div>
  );
}

function OverviewTab({
  admission,
  budget,
  egress,
  loading,
  reload,
}: {
  admission?: AdmissionStatus | null;
  budget?: AdmissionBudget | null;
  egress?: EgressStatus | null;
  loading: boolean;
  reload: () => void;
}) {
  // busy guards the mode toggles against double-submits while a POST is in
  // flight; an empty string means idle.
  const [busy, setBusy] = useState<"" | "admission" | "egress">("");

  // setAdmissionMode fetches the CURRENT full policy, swaps only the mode, and
  // re-POSTs it (persist=1) so no other field is lost. The apply is live on the
  // dashboard front-door immediately; the proxy backstop picks it up on the
  // restart the banner then prompts.
  async function setAdmissionMode(mode: AdmissionMode) {
    if (busy) return;
    setBusy("admission");
    try {
      const cur = await fetchJSON<AdmissionPolicyGet>("/api/obs/admission/policy");
      const { status, data } = await postPolicy("/api/obs/admission/policy", { ...cur.policy, mode }, true);
      if (status === 422 || !data.applied) {
        pushToast(data.error || "Mode change rejected", "danger");
        return;
      }
      markRestartPending("admission policy");
      pushToast(`Admission → ${mode}. Live on the front-door now; restart to update the proxy.`, "success");
      reload();
    } catch (e) {
      pushToast(e instanceof Error ? e.message : String(e), "danger");
    } finally {
      setBusy("");
    }
  }

  // setEgressMode is Save-oriented: egress only takes real effect on the proxy
  // path, so a live apply just updates the dashboard's preview — the routing
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
      pushToast(`Egress → ${mode} saved. Restart the daemon to apply routing.`, "success");
      reload();
    } catch (e) {
      pushToast(e instanceof Error ? e.message : String(e), "danger");
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

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <HeroStat
          label="Admission"
          icon={<ShieldIcon />}
          loading={loading}
          variant={admission?.mode === "enforce" ? "warn" : "accent"}
          value={admission ? admission.mode : "-"}
          sub={
            admission?.enabled
              ? `${admission.criteria_count} criteria · ${admDecisions} decisions/24h`
              : "disabled"
          }
        />
        <HeroStat
          label="Egress routing"
          icon={<CompassIcon />}
          loading={loading}
          variant={egress?.mode === "enforce" ? "warn" : "accent"}
          value={egress ? egress.mode : "-"}
          sub={
            egress?.enabled
              ? `${egress.rules?.length ?? 0} rules · ${egDecisions} decisions/24h`
              : "disabled"
          }
        />
        <HeroStat
          label="Judge"
          icon={<SparklesIcon />}
          loading={loading}
          variant="accent"
          value={admission ? admission.judge_hosting : "-"}
          sub={judgeHostingNote(admission?.judge_hosting)}
        />
        <HeroStat
          label="Per-user budget"
          icon={<CoinsIcon />}
          loading={loading}
          variant={budget && budget.breaches_24h > 0 ? "warn" : "accent"}
          value={budget?.enabled ? fmtUSD(budget.five_hour_usd) : "off"}
          sub={
            budget?.enabled
              ? `5h cap · ${budget.breaches_24h} breaches/24h`
              : "no per-user cap"
          }
        />
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card title="Admission posture">
          {admission ? (
            <dl className="space-y-1.5 text-[12px]">
              <Row
                k="Mode"
                v={
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
                }
              />
              <Row k="Criteria" v={String(admission.criteria_count)} />
              <Row k="Judge hosting" v={<Pill variant="info">{admission.judge_hosting}</Pill>} />
              <Row k="24h decisions" v={<DecisionBreakdown d={admission.decisions_24h} />} />
              <Row k="Audit chain" v={<Pill variant={admission.chain.ok ? "success" : "danger"}>{admission.chain.ok ? "ok" : "broken"} · {admission.chain.rows} rows</Pill>} />
              {admission.policy_hash && (
                <Row k="Policy" v={<span className="font-mono text-[11px] text-fg-3" title={admission.policy_hash}>{fmtShortId(admission.policy_hash, 16)}</span>} />
              )}
            </dl>
          ) : (
            <Muted>Loading…</Muted>
          )}
        </Card>

        <Card title="Egress posture">
          {egress ? (
            <dl className="space-y-1.5 text-[12px]">
              <Row
                k="Mode"
                v={
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
              <Row k="Rules" v={String(egress.rules?.length ?? 0)} />
              <Row k="Targets" v={String(egress.targets?.length ?? 0)} />
              <Row k="24h decisions" v={String(egDecisions)} />
              <Row k="Audit chain" v={<Pill variant={egress.chain.ok ? "success" : "danger"}>{egress.chain.ok ? "ok" : "broken"} · {egress.chain.rows} rows</Pill>} />
              {egress.policy_hash && (
                <Row k="Policy" v={<span className="font-mono text-[11px] text-fg-3" title={egress.policy_hash}>{fmtShortId(egress.policy_hash, 16)}</span>} />
              )}
            </dl>
          ) : (
            <Muted>Loading…</Muted>
          )}
        </Card>
      </div>

      <ShadowNudge admission={admission} egress={egress} />
    </div>
  );
}

// ShadowNudge encourages observe/advise-first rollout — the reference
// deployment's guidance. It only appears when something is already in enforce.
function ShadowNudge({ admission, egress }: { admission?: AdmissionStatus | null; egress?: EgressStatus | null }) {
  const enforcing = admission?.mode === "enforce" || egress?.mode === "enforce";
  if (!enforcing) return null;
  return (
    <div className="rounded-3 border border-warn/30 bg-warn-soft p-3 text-[11.5px] leading-relaxed text-warn">
      A policy is in <b>enforce</b> mode - it actively blocks or reroutes end-user
      traffic. Confirm the shadow (observe/advise) verdicts looked right before
      enforcing, and keep an eye on the audit timeline.
    </div>
  );
}

function DecisionBreakdown({ d }: { d: AdmissionStatus["decisions_24h"] }) {
  const entries = (["allow", "flag", "ask", "deny"] as const).filter((k) => (d[k] ?? 0) > 0);
  if (entries.length === 0) return <span className="text-fg-3">none</span>;
  const tone: Record<string, "success" | "warn" | "info" | "danger"> = {
    allow: "success",
    flag: "warn",
    ask: "info",
    deny: "danger",
  };
  return (
    <span className="inline-flex flex-wrap gap-1">
      {entries.map((k) => (
        <Pill key={k} variant={tone[k]}>
          {k} {d[k]}
        </Pill>
      ))}
    </span>
  );
}

function judgeHostingNote(h?: string): string {
  switch (h) {
    case "local":
      return "loopback · no key egress";
    case "aggregator":
      return "via aggregator (OpenRouter)";
    case "provider":
      return "hosted provider";
    case "private":
      return "private endpoint";
    default:
      return "no judge configured";
  }
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-3 border border-line-1 bg-bg-1 p-4">
      <h3 className="mb-2.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">{title}</h3>
      {children}
    </div>
  );
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-fg-3">{k}</dt>
      <dd className="text-right text-fg-1">{v}</dd>
    </div>
  );
}

function Muted({ children }: { children: ReactNode }) {
  return <p className="text-[12px] text-fg-3">{children}</p>;
}

// ObsDisabled names the exact gate: [observability] must be enabled for the
// admission/egress policy routes to be served.
function ObsDisabled() {
  return (
    <div className="rounded-3 border border-line-1 bg-bg-1 p-8 text-center text-[12px] leading-relaxed text-fg-3">
      <p className="mb-2 text-[13px] font-semibold text-fg-2">Observability is disabled</p>
      <div className="mx-auto max-w-xl">
        <p>
          Admission + egress policy authoring needs the observability subsystem.
          Enable it in{" "}
          <code className="rounded-1 bg-bg-2 px-1 font-mono">~/.observer/config.toml</code>:
        </p>
        <pre className="mt-2 inline-block rounded-2 bg-bg-2 px-3 py-2 text-left font-mono text-[11px] text-fg-2">
          {"[observability]\nenabled = true\n\n[observability.admission]\nenabled = true"}
        </pre>
        <p className="mt-2">then restart the daemon.</p>
      </div>
    </div>
  );
}
