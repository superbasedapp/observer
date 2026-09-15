import { useState } from "react";
import { Pill, SlideOver } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import {
  type AdmissionPolicyGet,
  type EgressPolicyGet,
  type EgressRule,
  decisionVariant,
  postPolicy,
} from "./types";
import {
  type PolicyTemplate,
  TEMPLATE_CATALOG,
  TEMPLATE_GROUPS,
  mergeAdmission,
  mergeEgress,
  templateTouches,
} from "./templates-catalog";
import { Card, btnPrimary, btnSecondary } from "./ui";

// Templates tab — the card gallery (handover §5 headline). Each card opens a
// preview drawer showing the exact criteria/rules/budget it contributes; Apply
// MERGES that contribution into the current live policy and POSTs it through the
// same editors' endpoints. Templates default the policy to a shadow mode
// (admission→observe, egress→advise) when it's currently off, so applying one
// never silently starts enforcing.

const touchLabel: Record<string, string> = { guardrail: "guardrail", routing: "routing", budget: "budget" };
const touchVariant: Record<string, "info" | "warn" | "success"> = { guardrail: "info", routing: "warn", budget: "success" };

export function TemplatesTab({ onApplied }: { onApplied?: () => void }) {
  const [preview, setPreview] = useState<PolicyTemplate | null>(null);

  return (
    <div className="space-y-5">
      {TEMPLATE_GROUPS.map((group) => {
        const items = TEMPLATE_CATALOG.filter((t) => t.group === group);
        if (items.length === 0) return null;
        return (
          <div key={group}>
            <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">{group}</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {items.map((t) => (
                <TemplateCard key={t.id} t={t} onOpen={() => setPreview(t)} />
              ))}
            </div>
          </div>
        );
      })}

      <SlideOver
        open={preview != null}
        onClose={() => setPreview(null)}
        title={preview?.title ?? ""}
        subtitle={preview?.group}
        width={720}
      >
        {preview && <TemplatePreview t={preview} onDone={() => { setPreview(null); onApplied?.(); }} />}
      </SlideOver>
    </div>
  );
}

function TemplateCard({ t, onOpen }: { t: PolicyTemplate; onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex h-full flex-col rounded-3 border border-line-1 bg-bg-1 p-4 text-left transition-colors hover:border-line-3"
    >
      <div className="mb-1.5 flex items-center gap-1.5">
        {templateTouches(t).map((k) => (
          <Pill key={k} variant={touchVariant[k]}>{touchLabel[k]}</Pill>
        ))}
      </div>
      <div className="text-[13px] font-semibold text-fg-0">{t.title}</div>
      <p className="mt-1 flex-1 text-[11.5px] leading-relaxed text-fg-3">{t.blurb}</p>
      <span className="mt-2 text-[11px] font-medium text-accent">Preview →</span>
    </button>
  );
}

function TemplatePreview({ t, onDone }: { t: PolicyTemplate; onDone: () => void }) {
  const [busy, setBusy] = useState<"" | "apply" | "save">("");
  const touches = templateTouches(t);

  async function apply(persist: boolean) {
    setBusy(persist ? "save" : "apply");
    try {
      let needsRestart = persist;

      // 1. Guardrail contribution → merge into the live admission policy.
      if (t.criteria || t.prefilterDeny || t.secretRemoteJudge) {
        const cur = await fetchJSON<AdmissionPolicyGet>("/api/obs/admission/policy");
        const merged = mergeAdmission(cur.policy, t);
        if (merged.mode === "off") merged.mode = "observe";
        const { status, data } = await postPolicy("/api/obs/admission/policy", merged, persist);
        if (status === 422 || !data.applied) {
          pushToast(data.issues?.[0]?.message || data.error || "Guardrail merge rejected", "danger");
          return;
        }
      }

      // 2. Routing contribution → merge into the live egress policy.
      if (t.egressTargets || t.egressRules) {
        const cur = await fetchJSON<EgressPolicyGet>("/api/obs/egress/policy");
        const merged = mergeEgress(cur.policy, t);
        if (merged.mode === "off") merged.mode = "advise";
        const { status, data } = await postPolicy("/api/obs/egress/policy", merged, persist);
        if (status === 422 || !data.applied) {
          pushToast(data.issues?.[0]?.message || data.error || "Routing merge rejected", "danger");
          return;
        }
      }

      // 3. Budget → config-section (always restart-oriented; no live path).
      if (t.budget) {
        const res = await fetchJSON<{ saved: boolean; restart_required: boolean }>("/api/config/section/observability", undefined, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ Admission: { Budget: t.budget } }),
        });
        if (!res.saved) {
          pushToast("Budget save was not confirmed", "danger");
          return;
        }
        needsRestart = true;
      }

      if (needsRestart) markRestartPending("policy templates");
      pushToast(
        persist
          ? "Template saved. Restart the daemon to apply everywhere."
          : t.budget
            ? "Applied live; the budget cap needs a restart."
            : "Template applied live to the admission front-door.",
        "success",
      );
      onDone();
    } catch (e) {
      pushToast(e instanceof Error ? e.message : String(e), "danger");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="space-y-4 p-5">
      <p className="text-[12px] leading-relaxed text-fg-2">{t.blurb}</p>
      <div className="flex flex-wrap gap-1.5">
        {touches.map((k) => (
          <Pill key={k} variant={touchVariant[k]}>{touchLabel[k]}</Pill>
        ))}
      </div>

      {t.criteria && t.criteria.length > 0 && (
        <Card title="Adds guardrail criteria">
          <ul className="space-y-2">
            {t.criteria.map((c) => (
              <li key={c.id} className="flex items-start gap-2 text-[12px]">
                <Pill variant={decisionVariant(c.decision)}>{c.decision}</Pill>
                <div>
                  <span className="font-mono text-[11px] text-fg-1">{c.id}</span>
                  <span className="text-fg-3"> · {c.type}</span>
                  {c.definition && <p className="mt-0.5 text-fg-3">{c.definition}</p>}
                  {c.topics.length > 0 && <p className="mt-0.5 text-fg-3">topics: {c.topics.join(", ")}</p>}
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {t.prefilterDeny && t.prefilterDeny.length > 0 && (
        <Card title="Adds deny-list patterns">
          <ul className="space-y-1 font-mono text-[11px] text-fg-2">
            {t.prefilterDeny.map((p, i) => <li key={i}>{p}</li>)}
          </ul>
          {t.secretRemoteJudge && <p className="mt-2 text-[11.5px] text-fg-3">Secret + remote judge → <Pill variant={decisionVariant(t.secretRemoteJudge)}>{t.secretRemoteJudge}</Pill> (a secret-bearing request is decided locally, never sent to a remote judge).</p>}
        </Card>
      )}

      {(t.egressTargets?.length || t.egressRules?.length) && (
        <Card title="Adds routing">
          {t.egressTargets && t.egressTargets.length > 0 && (
            <div className="mb-2">
              <div className="mb-1 text-[10.5px] uppercase tracking-[0.05em] text-fg-3">Targets</div>
              <ul className="space-y-0.5 text-[11.5px] text-fg-2">
                {t.egressTargets.map((tg) => (
                  <li key={tg.id}><span className="font-mono text-fg-1">{tg.id}</span> → {tg.url} <span className="text-fg-3">({tg.shape})</span></li>
                ))}
              </ul>
            </div>
          )}
          {t.egressRules && t.egressRules.length > 0 && (
            <div>
              <div className="mb-1 text-[10.5px] uppercase tracking-[0.05em] text-fg-3">Rules</div>
              <ul className="space-y-0.5 text-[11.5px] text-fg-2">
                {t.egressRules.map((r) => (
                  <li key={r.name}><span className="font-mono text-fg-1">{r.name}</span>: {ruleSummary(r)}</li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      )}

      {t.budget && (
        <Card title="Sets per-user budget">
          <p className="text-[12px] text-fg-2">
            ${t.budget.PerUser5hUSD} / 5h · ${t.budget.PerUserWeeklyUSD} / week · ${t.budget.PerUserMonthlyUSD} / month.
            <span className="text-fg-3"> Read at daemon start - needs a restart.</span>
          </p>
        </Card>
      )}

      <div className="rounded-2 border border-line-1 bg-bg-2/40 px-3 py-2 text-[11px] leading-relaxed text-fg-3">
        Applying merges this into your current policy (criteria by id, rules by name - nothing is removed).
        If the target policy is off it moves to a shadow mode ({touches.includes("routing") ? "advise" : "observe"}), never straight to enforce.
      </div>

      <div className="flex items-center gap-2 pb-2">
        <button type="button" disabled={busy !== ""} onClick={() => apply(false)} className={btnSecondary}>
          {busy === "apply" ? "Applying…" : "Apply live"}
        </button>
        <button type="button" disabled={busy !== ""} onClick={() => apply(true)} className={btnPrimary}>
          {busy === "save" ? "Saving…" : "Save & restart"}
        </button>
      </div>
    </div>
  );
}

function ruleSummary(r: EgressRule): string {
  const conds: string[] = [];
  if (r.when.verdict_at_least) conds.push(`verdict ≥ ${r.when.verdict_at_least}`);
  if (r.when.budget_band_at_least != null) conds.push(`budget ≥ ${Math.round(r.when.budget_band_at_least * 100)}%`);
  if (r.when.user_cohort) conds.push(`cohort "${r.when.user_cohort}"`);
  const when = conds.length ? conds.join(", ") : "any";
  let then = "log only";
  if (r.action.deny) then = "deny";
  else if (r.action.route_to_upstream) then = `→ ${r.action.route_to_upstream}`;
  else if (r.action.route_to_model) then = `→ model ${r.action.route_to_model}`;
  else if (r.action.set_effort) then = `effort ${r.action.set_effort}`;
  return `when ${when}, ${then}`;
}
