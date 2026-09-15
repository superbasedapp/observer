import { useEffect, useMemo, useState } from "react";
import { Pill, SegmentedControl, Toggle } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import {
  type AdmissionCriterion,
  type AdmissionPolicy,
  type AdmissionPolicyGet,
  type BudgetConfig,
  type ConfigResponse,
  type CriterionType,
  type Decision,
  type JudgeConfig,
  type LintIssue,
  type Severity,
  isJudged,
  judgeHosting,
  newCriterionId,
  postPolicy,
} from "./types";
import {
  Card,
  IssueList,
  Labeled,
  Muted,
  NumberInput,
  Select,
  TextArea,
  btnGhost,
  btnGhostDanger,
  btnPrimary,
  btnSecondary,
  inputClass,
  splitLines,
} from "./ui";

// Guardrails tab — the admission (input-guardrail) authoring surface. It edits
// three things with TWO distinct apply semantics, kept visually separate
// because the backend applies them by different paths:
//
//   • The POLICY (mode/strict/scope/secret-remote-judge, the deterministic
//     pre-filter, and the criterion table) is hot-swappable — "Apply live"
//     POSTs it and the dashboard's admission front-door reflects it at once;
//     "Save & restart" also persists it to config.toml.
//   • The JUDGE binding and the per-user BUDGET are read at daemon start and
//     are NOT hot-swappable, so they only have "Save & restart" (a
//     config-section PUT + a restart-pending banner) — the honest truth.

const CRITERION_TYPES: { value: CriterionType; label: string; hint: string }[] = [
  { value: "valid_use_case", label: "Valid use case", hint: "LLM-judged - allow only requests that fit the app's purpose (needs a definition)." },
  { value: "denied_topics", label: "Denied topics", hint: "Deterministic - match against a topic list." },
  { value: "jailbreak", label: "Jailbreak", hint: "Deterministic - detect prompt-injection / jailbreak attempts." },
  { value: "custom", label: "Custom (judged)", hint: "LLM-judged against a free-form definition you write." },
];
const DECISIONS: Decision[] = ["allow", "flag", "ask", "deny"];
const SEVERITIES: Severity[] = ["info", "warn", "high", "critical"];

export function GuardrailsTab({ onApplied }: { onApplied?: () => void }) {
  const policyApi = useApi<AdmissionPolicyGet>("/api/obs/admission/policy");
  const configApi = useApi<ConfigResponse>("/api/config");

  return (
    <div className="space-y-4">
      <PolicyEditor policyApi={policyApi} onApplied={onApplied} />
      <JudgeEditor configApi={configApi} />
      <BudgetEditor configApi={configApi} />
    </div>
  );
}

// ---------------- Policy (criteria + prefilter + mode) ----------------

function PolicyEditor({
  policyApi,
  onApplied,
}: {
  policyApi: ReturnType<typeof useApi<AdmissionPolicyGet>>;
  onApplied?: () => void;
}) {
  const [draft, setDraft] = useState<AdmissionPolicy | null>(null);
  const [busy, setBusy] = useState<"" | "apply" | "save">("");
  const [issues, setIssues] = useState<LintIssue[]>([]);
  const [err, setErr] = useState("");

  // Hydrate the draft once the live policy loads. A structuredClone keeps the
  // edits local until the operator applies — a reload won't clobber in-progress
  // work unless it changes the loaded reference. The backend marshals empty
  // string slices as JSON null (regexpSources returns nil, criterion.Topics is
  // nil for non-topic types), so coerce every list to [] here — the form binds
  // to `.join`/`.map` and a null would crash the render.
  useEffect(() => {
    if (!policyApi.data) return;
    const p = structuredClone(policyApi.data.policy);
    p.prefilter = p.prefilter ?? { allow: [], deny: [], max_message_bytes: 0 };
    p.prefilter.allow = p.prefilter.allow ?? [];
    p.prefilter.deny = p.prefilter.deny ?? [];
    p.criteria = (p.criteria ?? []).map((c) => ({ ...c, topics: c.topics ?? [] }));
    setDraft(p);
  }, [policyApi.data]);

  const globalIssues = useMemo(() => issues.filter((i) => !i.criterion_id), [issues]);

  if (policyApi.loading && !draft) return <Card title="Admission policy"><Muted>Loading…</Muted></Card>;
  if (!draft) return <Card title="Admission policy"><Muted>No policy loaded.</Muted></Card>;

  const patch = (p: Partial<AdmissionPolicy>) => setDraft({ ...draft, ...p });
  const patchCriterion = (idx: number, c: Partial<AdmissionCriterion>) => {
    const criteria = draft.criteria.map((x, i) => (i === idx ? { ...x, ...c } : x));
    setDraft({ ...draft, criteria });
  };
  const addCriterion = () =>
    setDraft({
      ...draft,
      criteria: [
        ...draft.criteria,
        { id: newCriterionId(draft.criteria), type: "denied_topics", name: "", definition: "", topics: [], decision: "deny", severity: "warn" },
      ],
    });
  const removeCriterion = (idx: number) => setDraft({ ...draft, criteria: draft.criteria.filter((_, i) => i !== idx) });

  async function submit(persist: boolean) {
    setBusy(persist ? "save" : "apply");
    setErr("");
    setIssues([]);
    try {
      const { status, data } = await postPolicy("/api/obs/admission/policy", draft, persist);
      setIssues(data.issues ?? []);
      if (status === 422 || !data.applied) {
        setErr(data.error || "Policy rejected - fix the issues below.");
        pushToast("Policy not applied - see issues", "danger");
        return;
      }
      if (persist && !data.persisted) {
        pushToast(`Applied live, but not saved: ${data.persist_error || "persist failed"}`, "warn");
      } else if (persist) {
        markRestartPending("admission policy");
        pushToast("Saved. Live on the front-door now; restart to update the proxy backstop.", "success");
      } else {
        pushToast("Applied live to the admission front-door.", "success");
      }
      policyApi.reload();
      onApplied?.();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      pushToast("Apply failed", "danger");
    } finally {
      setBusy("");
    }
  }

  return (
    <Card
      title="Admission policy"
      sub="The guardrail table plus its mode and deterministic pre-filter. Applying live affects the SDK front-door immediately; saving also writes config.toml (the proxy backstop needs a restart)."
    >
      {/* Policy-level controls */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <Labeled label="Mode">
          <SegmentedControl<AdmissionPolicy["mode"]>
            options={[
              { value: "off", label: "Off" },
              { value: "observe", label: "Observe" },
              { value: "enforce", label: "Enforce" },
            ]}
            value={draft.mode}
            onChange={(mode) => patch({ mode })}
          />
        </Labeled>
        <Labeled label="Scope">
          <SegmentedControl<AdmissionPolicy["scope"]>
            options={[
              { value: "last_user", label: "Last user msg" },
              { value: "conversation", label: "Conversation" },
            ]}
            value={draft.scope}
            onChange={(scope) => patch({ scope })}
          />
        </Labeled>
        <Toggle on={draft.strict} onChange={(strict) => patch({ strict })} label="Strict (fail-closed on judge error)" />
        <Labeled label="Secret + remote judge">
          <Select
            value={draft.secret_remote_judge}
            onChange={(v) => patch({ secret_remote_judge: v as AdmissionPolicy["secret_remote_judge"] })}
            options={[
              { value: "", label: "Off (scrub + send)" },
              { value: "allow", label: "allow" },
              { value: "flag", label: "flag" },
              { value: "ask", label: "ask" },
              { value: "deny", label: "deny locally" },
            ]}
          />
        </Labeled>
      </div>

      {draft.mode === "enforce" && (
        <div className="mt-3 rounded-2 border border-warn/30 bg-warn-soft px-3 py-2 text-[11px] text-warn">
          Enforce actively blocks or holds end-user requests. Confirm the observe-mode shadow verdicts looked right first.
        </div>
      )}

      {/* Criteria */}
      <div className="mt-5 flex items-center justify-between">
        <h4 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Criteria ({draft.criteria.length})</h4>
        <button type="button" onClick={addCriterion} className={btnGhost}>+ Add criterion</button>
      </div>
      <div className="mt-2 space-y-3">
        {draft.criteria.length === 0 && <Muted>No criteria - the policy allows everything. Add one, or apply a Template.</Muted>}
        {draft.criteria.map((c, idx) => (
          <CriterionRow
            key={idx}
            c={c}
            issues={issues.filter((i) => i.criterion_id === c.id)}
            onChange={(patch) => patchCriterion(idx, patch)}
            onRemove={() => removeCriterion(idx)}
          />
        ))}
      </div>

      {/* Prefilter */}
      <div className="mt-5">
        <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Deterministic pre-filter</h4>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Labeled label="Allow patterns (regex, one per line)" stacked>
            <TextArea
              value={draft.prefilter.allow.join("\n")}
              onChange={(v) => patch({ prefilter: { ...draft.prefilter, allow: splitLines(v) } })}
              rows={3}
              placeholder="^/health$"
            />
          </Labeled>
          <Labeled label="Deny patterns (regex, one per line)" stacked>
            <TextArea
              value={draft.prefilter.deny.join("\n")}
              onChange={(v) => patch({ prefilter: { ...draft.prefilter, deny: splitLines(v) } })}
              rows={3}
              placeholder="(?i)ignore previous instructions"
            />
          </Labeled>
        </div>
        <Labeled label="Max message bytes (0 = no cap)" className="mt-3">
          <NumberInput value={draft.prefilter.max_message_bytes} onChange={(n) => patch({ prefilter: { ...draft.prefilter, max_message_bytes: n } })} />
        </Labeled>
      </div>

      {globalIssues.length > 0 && <IssueList issues={globalIssues} />}
      {err && <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">{err}</div>}

      <div className="mt-4 flex items-center gap-2">
        <button type="button" disabled={busy !== ""} onClick={() => submit(false)} className={btnPrimary}>
          {busy === "apply" ? "Applying…" : "Apply live"}
        </button>
        <button type="button" disabled={busy !== ""} onClick={() => submit(true)} className={btnSecondary}>
          {busy === "save" ? "Saving…" : "Save & restart"}
        </button>
        <span className="text-[11px] text-fg-3">Apply live = front-door now · Save = durable + proxy on restart</span>
      </div>
    </Card>
  );
}

function CriterionRow({
  c,
  issues,
  onChange,
  onRemove,
}: {
  c: AdmissionCriterion;
  issues: LintIssue[];
  onChange: (patch: Partial<AdmissionCriterion>) => void;
  onRemove: () => void;
}) {
  const judged = isJudged(c.type);
  return (
    <div className="rounded-2 border border-line-1 bg-bg-2/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={c.type}
          onChange={(v) => onChange({ type: v as CriterionType })}
          options={CRITERION_TYPES.map((t) => ({ value: t.value, label: t.label }))}
        />
        {judged ? (
          <Pill variant="info" title="Calls the LLM judge - adds latency + judge tokens per request.">LLM-judged</Pill>
        ) : (
          <Pill variant="neutral" title="Deterministic - runs offline, no judge call.">deterministic</Pill>
        )}
        <input
          value={c.name}
          onChange={(e) => onChange({ name: e.target.value })}
          placeholder="name (e.g. on-scope)"
          className={inputClass + " min-w-[10rem] flex-1"}
        />
        <button type="button" onClick={onRemove} className={btnGhostDanger} title="Remove criterion">Remove</button>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Labeled label="Decision">
          <SegmentedControl<Decision>
            size="sm"
            options={DECISIONS.map((d) => ({ value: d, label: d }))}
            value={c.decision}
            onChange={(decision) => onChange({ decision })}
          />
        </Labeled>
        <Labeled label="Severity">
          <Select value={c.severity} onChange={(v) => onChange({ severity: v as Severity })} options={SEVERITIES.map((s) => ({ value: s, label: s }))} />
        </Labeled>
      </div>

      {judged && (
        <Labeled label="Definition (what the judge should decide)" stacked className="mt-2">
          <TextArea value={c.definition} onChange={(v) => onChange({ definition: v })} rows={2} placeholder="Allow only questions about using the Acme product…" />
        </Labeled>
      )}
      {c.type === "denied_topics" && (
        <Labeled label="Topics (comma-separated)" stacked className="mt-2">
          <input
            value={c.topics.join(", ")}
            onChange={(e) => onChange({ topics: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) })}
            placeholder="competitors, legal advice, medical advice"
            className={inputClass + " w-full"}
          />
        </Labeled>
      )}

      {issues.length > 0 && <IssueList issues={issues} />}
    </div>
  );
}

// ---------------- Judge ----------------

function JudgeEditor({ configApi }: { configApi: ReturnType<typeof useApi<ConfigResponse>> }) {
  const [draft, setDraft] = useState<JudgeConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    const j = configApi.data?.config.Observability.Judge;
    if (j) setDraft({ ...j });
  }, [configApi.data]);

  if (!draft) return <Card title="Judge"><Muted>Loading…</Muted></Card>;
  const hosting = judgeHosting(draft.BaseURL);
  const patch = (p: Partial<JudgeConfig>) => setDraft({ ...draft, ...p });

  async function save() {
    setBusy(true);
    setErr("");
    try {
      const res = await fetchJSON<{ saved: boolean; restart_required: boolean }>("/api/config/section/observability", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ Judge: draft }),
      });
      if (!res.saved) throw new Error("server did not confirm save");
      if (res.restart_required) markRestartPending("observability");
      pushToast("Judge saved · restart daemon to apply", "success");
      configApi.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      pushToast("Judge save failed", "danger");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title={<span className="inline-flex items-center gap-2">Judge <Pill variant="info">{hosting}</Pill></span>}
      sub="The LLM that evaluates judged criteria. Hosting is derived from the base URL - a loopback URL keeps requests local with no key egress. Read at daemon start, so this always needs a restart."
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Labeled label="Model" stacked>
          <input value={draft.Model} onChange={(e) => patch({ Model: e.target.value })} placeholder="qwen2.5:1.5b-instruct" className={inputClass + " w-full"} />
        </Labeled>
        <Labeled label="Base URL" stacked>
          <input value={draft.BaseURL} onChange={(e) => patch({ BaseURL: e.target.value })} placeholder="http://127.0.0.1:11434/v1" className={inputClass + " w-full"} />
        </Labeled>
        <Labeled label="API key env var" stacked>
          <input value={draft.APIKeyEnv} onChange={(e) => patch({ APIKeyEnv: e.target.value })} placeholder="OLLAMA_API_KEY" className={inputClass + " w-full"} />
        </Labeled>
        <div className="grid grid-cols-3 gap-2">
          <Labeled label="Timeout ms" stacked><NumberInput value={draft.TimeoutMS} onChange={(n) => patch({ TimeoutMS: n })} /></Labeled>
          <Labeled label="Max tokens" stacked><NumberInput value={draft.MaxTokens} onChange={(n) => patch({ MaxTokens: n })} /></Labeled>
          <Labeled label="Num ctx" stacked><NumberInput value={draft.NumCtx} onChange={(n) => patch({ NumCtx: n })} /></Labeled>
        </div>
      </div>
      {hosting !== "local" && hosting !== "none" && (
        <div className="mt-3 rounded-2 border border-warn/30 bg-warn-soft px-3 py-2 text-[11px] text-warn">
          This judge is remote - requests egress off-box (secret-scrubbed first). The API key comes from the named env var, never stored here.
        </div>
      )}
      {err && <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">{err}</div>}
      <div className="mt-4">
        <button type="button" disabled={busy} onClick={save} className={btnSecondary}>{busy ? "Saving…" : "Save & restart"}</button>
      </div>
    </Card>
  );
}

// ---------------- Budget ----------------

function BudgetEditor({ configApi }: { configApi: ReturnType<typeof useApi<ConfigResponse>> }) {
  const [draft, setDraft] = useState<BudgetConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    const b = configApi.data?.config.Observability.Admission.Budget;
    if (b) setDraft({ ...b });
  }, [configApi.data]);

  if (!draft) return <Card title="Per-user budget"><Muted>Loading…</Muted></Card>;
  const patch = (p: Partial<BudgetConfig>) => setDraft({ ...draft, ...p });

  async function save() {
    setBusy(true);
    setErr("");
    try {
      const res = await fetchJSON<{ saved: boolean; restart_required: boolean }>("/api/config/section/observability", undefined, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ Admission: { Budget: draft } }),
      });
      if (!res.saved) throw new Error("server did not confirm save");
      if (res.restart_required) markRestartPending("observability");
      pushToast("Budget saved · restart daemon to apply", "success");
      configApi.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      pushToast("Budget save failed", "danger");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Per-user budget"
      sub="A per-end-user spend cap evaluated at the admission chokepoint. A breach yields a Deny (shadow in observe, blocking in enforce). Needs the app to share the end-user identity; anonymous requests are inert."
    >
      <Toggle on={draft.Enabled} onChange={(Enabled) => patch({ Enabled })} label="Enforce per-user caps" />
      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Labeled label="5-hour cap (USD)" stacked><NumberInput value={draft.PerUser5hUSD} onChange={(n) => patch({ PerUser5hUSD: n })} step={0.5} /></Labeled>
        <Labeled label="Weekly cap (USD)" stacked><NumberInput value={draft.PerUserWeeklyUSD} onChange={(n) => patch({ PerUserWeeklyUSD: n })} step={1} /></Labeled>
        <Labeled label="Monthly cap (USD)" stacked><NumberInput value={draft.PerUserMonthlyUSD} onChange={(n) => patch({ PerUserMonthlyUSD: n })} step={1} /></Labeled>
      </div>
      <Labeled label="User header (proxy path; the SDK passes user directly)" stacked className="mt-3">
        <input value={draft.UserHeader} onChange={(e) => patch({ UserHeader: e.target.value })} placeholder="X-Superbased-User" className={inputClass + " w-full max-w-sm"} />
      </Labeled>
      {err && <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">{err}</div>}
      <div className="mt-4">
        <button type="button" disabled={busy} onClick={save} className={btnSecondary}>{busy ? "Saving…" : "Save & restart"}</button>
      </div>
    </Card>
  );
}

