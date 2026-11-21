import { useState } from "react";
import { ArrowRight } from "lucide-react";
import { Button, Callout, Card, CardHeader, Pill, SlideOver } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { dollarsShown, fmtUSD } from "@/lib/format";
import { ConfigSaveCancelled, saveConfigSection } from "@/lib/configSectionSave";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import { useDaemonRestart } from "@/lib/useDaemonRestart";
import { RestartOverlay } from "@/components/RestartOverlay";
import { restartErrorText } from "./AdmissionOff";
import {
  type AdmissionPolicyGet,
  type EgressPolicyGet,
  type EgressRule,
  applyAdmissionPolicy,
  policyErrorText,
  policyStatusText,
  postPolicy,
} from "./types";
import { decisionTone } from "@shared/lib/guardCatalog";
import { VocabPill } from "@shared/lib/vocabPill";
import type { Tone } from "@shared/lib/tone";
import {
  type PolicyTemplate,
  TEMPLATE_CATALOG,
  TEMPLATE_GROUPS,
  mergeAdmission,
  mergeEgress,
  templateTouches,
} from "./templates-catalog";
import { CRITERION_TYPE_LABEL, EGRESS_ACTION_LABEL, TARGET_SHAPE_LABEL, wordsFor } from "./vocab";

// Templates tab: the card gallery (handover section 5 headline). Each card
// opens a preview drawer showing the exact criteria/rules/budget it
// contributes; Apply MERGES that contribution into the current live policy
// and POSTs it through the same editors' endpoints, always saved (UI review
// U-27: a live-only apply was lost on the next restart). The guardrail part
// is live at once; a routing or budget part is read at daemon start, so such
// a template also offers "Apply and restart" (U-29: the old "Save and
// restart" only saved). Templates default the policy to a shadow mode
// (admission->observe, egress->advise) when it's currently off, so applying
// one never silently starts enforcing.

// What a template touches, as a category pill. Categories are not a
// condition to act on, so none is warn or danger (Emphasis).
const touchLabel: Record<string, string> = { guardrail: "guardrail", routing: "routing", budget: "budget" };
const touchTone: Record<string, Tone> = { guardrail: "info", routing: "accent", budget: "neutral" };

export function TemplatesTab({ onApplied }: { onApplied?: () => void }) {
  const [preview, setPreview] = useState<PolicyTemplate | null>(null);

  return (
    <div className="space-y-5">
      {TEMPLATE_GROUPS.map((group) => {
        const items = TEMPLATE_CATALOG.filter((t) => t.group === group);
        if (items.length === 0) return null;
        return (
          <section key={group} aria-label={group}>
            <h3 className="mb-2 text-[13px] font-semibold text-fg-1">{group}</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {items.map((t) => (
                <TemplateCard key={t.id} t={t} onOpen={() => setPreview(t)} />
              ))}
            </div>
          </section>
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

function TouchPills({ t }: { t: PolicyTemplate }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {templateTouches(t).map((k) => (
        <Pill key={k} variant={touchTone[k] ?? "neutral"}>{touchLabel[k] ?? k}</Pill>
      ))}
    </div>
  );
}

// TemplateCard: the shared Card with one real action. The Preview button is
// its own control (keyboard reachable, its own click), not a text arrow
// inside a card-sized button.
function TemplateCard({ t, onOpen }: { t: PolicyTemplate; onOpen: () => void }) {
  return (
    <Card className="flex h-full flex-col" bodyClassName="flex flex-1 flex-col">
      <CardHeader title={t.title} className="mb-1.5" />
      <TouchPills t={t} />
      <p className="mt-2 flex-1 text-[11.5px] leading-relaxed text-fg-3">{t.blurb}</p>
      <div className="mt-3">
        <Button size="sm" iconRight={ArrowRight} onClick={onOpen} aria-label={`Preview ${t.title}`}>
          Preview
        </Button>
      </div>
    </Card>
  );
}

function TemplatePreview({ t, onDone }: { t: PolicyTemplate; onDone: () => void }) {
  const [busy, setBusy] = useState<"" | "apply" | "restart">("");
  const touches = templateTouches(t);
  const { restarting, error: restartError, restart } = useDaemonRestart();
  // A routing or budget contribution is read at daemon start.
  const needsRestart = Boolean(t.egressTargets?.length || t.egressRules?.length || t.budget);

  // apply merges and saves every part; withRestart then asks to restart.
  async function apply(withRestart: boolean) {
    setBusy(withRestart ? "restart" : "apply");
    try {
      // 1. Guardrail contribution -> merge into the live admission policy,
      // applied live and saved.
      if (t.criteria || t.prefilterDeny || t.secretRemoteJudge) {
        const cur = await fetchJSON<AdmissionPolicyGet>("/api/obs/admission/policy");
        const merged = mergeAdmission(cur.policy, t);
        if (merged.mode === "off") merged.mode = "observe";
        const { status, data } = await applyAdmissionPolicy(merged);
        if (status === 409) {
          pushToast(policyStatusText(409), "danger");
          return;
        }
        if (status === 422 || !data.applied) {
          pushToast(data.issues?.[0]?.message || data.error || "The guardrail part was rejected.", "danger");
          return;
        }
        if (!data.persisted) pushToast("The guardrail part applies now but was not saved: a daemon restart drops it.", "warn");
      }

      // 2. Routing contribution -> merge into the live egress policy, saved.
      if (t.egressTargets || t.egressRules) {
        const cur = await fetchJSON<EgressPolicyGet>("/api/obs/egress/policy");
        const merged = mergeEgress(cur.policy, t);
        if (merged.mode === "off") merged.mode = "advise";
        const { status, data } = await postPolicy("/api/obs/egress/policy", merged, true);
        if (status === 422 || !data.applied) {
          pushToast(data.issues?.[0]?.message || data.error || "The routing part was rejected.", "danger");
          return;
        }
      }

      // 3. Budget -> config-section (always restart-oriented; no live path).
      if (t.budget) {
        let res;
        try {
          res = await saveConfigSection("observability", { Admission: { Budget: t.budget } });
        } catch (e) {
          // The guardrail and routing parts above already applied; say so
          // rather than "nothing was written" for the whole template.
          if (e instanceof ConfigSaveCancelled) {
            pushToast("Guardrail and routing parts applied; the budget cap was not saved.", "warn");
            onDone();
            return;
          }
          throw e;
        }
        if (!res.saved) {
          pushToast("The budget cap was not saved. Try again.", "danger");
          return;
        }
      }

      if (!needsRestart) {
        pushToast("Template applied and saved.", "success");
        onDone();
        return;
      }
      markRestartPending("policy templates");
      if (withRestart) {
        await restart({
          title: "Restart the daemon to apply the template?",
          lead: "The template is saved. Its routing and budget parts apply when the daemon starts again.",
        });
        return;
      }
      pushToast("Template saved. Its routing and budget parts apply after a daemon restart.", "success");
      onDone();
    } catch (e) {
      pushToast(policyErrorText(e), "danger");
    } finally {
      setBusy("");
    }
  }

  if (restarting) {
    return (
      <RestartOverlay
        title="Restarting the daemon…"
        body="Applying the template and reconnecting. This page reloads automatically when the new process is up."
      />
    );
  }

  return (
    <div className="space-y-4 p-5">
      <p className="text-[12px] leading-relaxed text-fg-2">{t.blurb}</p>
      <TouchPills t={t} />

      {t.criteria && t.criteria.length > 0 && (
        <Card title="Adds guardrail criteria">
          <ul className="space-y-2">
            {t.criteria.map((c) => (
              <li key={c.id} className="flex items-start gap-2 text-[12px]">
                <VocabPill vocab="guardDecision" value={c.decision} tone={decisionTone(c.decision)} />
                <div>
                  <span className="font-mono text-[11px] text-fg-1">{c.id}</span>
                  <span className="text-fg-3">, {wordsFor(CRITERION_TYPE_LABEL, c.type)}</span>
                  {c.definition && <p className="mt-0.5 text-fg-3">{c.definition}</p>}
                  {c.topics.length > 0 && <p className="mt-0.5 text-fg-3">Topics: {c.topics.join(", ")}</p>}
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
          {t.secretRemoteJudge && (
            <p className="mt-2 text-[11.5px] text-fg-3">
              A request carrying a secret is decided on this machine, never sent to a remote judge:{" "}
              <VocabPill vocab="guardDecision" value={t.secretRemoteJudge} tone={decisionTone(t.secretRemoteJudge)} />
            </p>
          )}
        </Card>
      )}

      {(t.egressTargets?.length || t.egressRules?.length) && (
        <Card title="Adds routing">
          {t.egressTargets && t.egressTargets.length > 0 && (
            <div className="mb-2">
              <div className="mb-1 text-[11px] font-medium text-fg-2">Targets</div>
              <ul className="space-y-0.5 text-[11.5px] text-fg-2">
                {t.egressTargets.map((tg) => (
                  <li key={tg.id}>
                    <span className="font-mono text-fg-1">{tg.id}</span> at <span className="font-mono">{tg.url}</span>{" "}
                    <span className="text-fg-3">({wordsFor(TARGET_SHAPE_LABEL, tg.shape)})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {t.egressRules && t.egressRules.length > 0 && (
            <div>
              <div className="mb-1 text-[11px] font-medium text-fg-2">Rules</div>
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
            {/* The caps are dollar amounts; under the token-usage view the
                amounts are not shown (T-204), the windows still are. */}
            {dollarsShown()
              ? `${fmtUSD(t.budget.PerUser5hUSD)} per 5 hours, ${fmtUSD(t.budget.PerUserWeeklyUSD)} per week, ${fmtUSD(t.budget.PerUserMonthlyUSD)} per month.`
              : "Dollar caps per 5 hours, week and month (amounts hidden: your organization shows token usage)."}
            <span className="text-fg-3"> Read when the daemon starts, so it needs a restart.</span>
          </p>
        </Card>
      )}

      <Callout>
        Applying merges this into your current policy and saves it; nothing is removed. A policy that is off moves to{" "}
        {touches.includes("routing") ? "advise only" : "observe only"}, never straight to enforce.
        {needsRestart ? " Routing and budget parts apply after a daemon restart." : " It applies at once."}
      </Callout>

      {restartError && (
        <Callout tone="warn" title="The daemon did not restart">
          {restartErrorText(restartError)}
        </Callout>
      )}

      <div className="flex flex-wrap items-center gap-2 pb-2">
        <Button variant={needsRestart ? "secondary" : "primary"} disabled={busy !== ""} loading={busy === "apply"} onClick={() => void apply(false)}>
          {busy === "apply" ? "Applying" : "Apply"}
        </Button>
        {needsRestart && (
          <Button variant="primary" disabled={busy !== ""} loading={busy === "restart"} onClick={() => void apply(true)}>
            {busy === "restart" ? "Applying" : "Apply and restart"}
          </Button>
        )}
      </div>
    </div>
  );
}

function ruleSummary(r: EgressRule): string {
  const conds: string[] = [];
  if (r.when.verdict_at_least) conds.push(`verdict at least ${r.when.verdict_at_least}`);
  if (r.when.budget_band_at_least != null) conds.push(`budget at least ${Math.round(r.when.budget_band_at_least * 100)}%`);
  if (r.when.user_cohort) conds.push(`cohort "${r.when.user_cohort}"`);
  const when = conds.length ? conds.join(", ") : "any request";
  let then = wordsFor(EGRESS_ACTION_LABEL, "no_route").toLowerCase();
  if (r.action.deny) then = "deny";
  else if (r.action.route_to_upstream) then = `route to ${r.action.route_to_upstream}`;
  else if (r.action.route_to_model) then = `swap to model ${r.action.route_to_model}`;
  else if (r.action.set_effort) then = `set effort to ${r.action.set_effort}`;
  return `when ${when}, ${then}`;
}
