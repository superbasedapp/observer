import { useEffect, useMemo, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import {
  Button,
  Callout,
  ChartShell,
  EmptyState,
  EntityMultiPicker,
  ErrorState,
  HostMark,
  Input,
  InlineLoading,
  Pill,
  SegmentedControl,
  SinglePicker,
  Toggle,
} from "@/components/primitives";
import { judgeHostingLabel } from "@shared/lib/obsVocab";
import { keepSelected, uniqueSorted } from "@/lib/pickerOptions";
import { useModelOptions } from "@/lib/usePickerSources";
import { TEMPLATE_CATALOG } from "./templates-catalog";
import { useApi } from "@/lib/useApi";
import { ConfigSaveCancelled, saveConfigSection } from "@/lib/configSectionSave";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import { useDaemonRestart } from "@/lib/useDaemonRestart";
import { RestartOverlay } from "@/components/RestartOverlay";
import { AdmissionOffNote, restartErrorText } from "./AdmissionOff";
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
  applyAdmissionPolicy,
  isJudged,
  judgeHosting,
  newCriterionId,
  policyErrorText,
  policyStatusText,
} from "./types";
import { IssueList, Labeled, NumberInput, Select, TextArea, TextInput, splitLines } from "./ui";

// Guardrails tab - the admission (input-guardrail) authoring surface. It edits
// three things with TWO distinct apply semantics, kept visually separate
// because the backend applies them by different paths:
//
//   • The POLICY (mode/strict/scope/secret-remote-judge, the deterministic
//     pre-filter, and the criterion table) is hot-swappable: "Apply" POSTs it
//     live AND saved (UI review U-27: a live-only apply was silently lost on
//     the next restart), on the front door and the proxy check at once.
//   • The JUDGE binding and the per-user BUDGET are read at daemon start and
//     are NOT hot-swappable, so they have "Save and restart": a config-section
//     PUT, then the daemon restart with its usual confirm (U-29: the button
//     used to only save). A declined restart leaves the restart-pending
//     banner.

const CRITERION_TYPES: { value: CriterionType; label: string; hint: string }[] = [
  { value: "valid_use_case", label: "Valid use case", hint: "LLM-judged - allow only requests that fit the app's purpose (needs a definition)." },
  { value: "denied_topics", label: "Denied topics", hint: "Deterministic - match whole words from a topic list (end a topic with * to match words that start with it)." },
  { value: "jailbreak", label: "Jailbreak", hint: "Deterministic - detect prompt-injection / jailbreak attempts." },
  { value: "custom", label: "Custom (judged)", hint: "LLM-judged against a free-form definition you write." },
];
const DECISIONS: Decision[] = ["allow", "flag", "ask", "deny"];
const SEVERITIES: Severity[] = ["info", "warn", "high", "critical"];

export function GuardrailsTab({ onApplied, admissionOff }: { onApplied?: () => void; admissionOff?: boolean }) {
  // With admission checks off the policy route answers 404: offer to turn
  // them on instead (U-13). The judge and budget are config and stay.
  const policyApi = useApi<AdmissionPolicyGet>(admissionOff ? null : "/api/obs/admission/policy");
  const configApi = useApi<ConfigResponse>("/api/config");
  const { restarting, error: restartError, restart } = useDaemonRestart();

  if (restarting) {
    return (
      <RestartOverlay
        title="Restarting the daemon…"
        body="Applying your changes and reconnecting. This page reloads automatically when the new process is up."
      />
    );
  }
  // saveAndRestart saves one config section, marks it pending, then asks to
  // restart (U-29). The pending banner stays if the restart is declined.
  async function saveAndRestart(what: string, body: unknown): Promise<boolean> {
    try {
      const res = await saveConfigSection("observability", body);
      if (!res.saved) {
        pushToast(`${what} was not saved. Try again.`, "danger");
        return false;
      }
      configApi.reload();
      if (!res.restart_required) {
        pushToast(`${what} saved.`, "success");
        return true;
      }
      markRestartPending("observability", res.restart_required_keys);
      await restart({ title: `Restart the daemon to apply the ${what.toLowerCase()}?`, lead: `The ${what.toLowerCase()} is saved and applies when the daemon starts again.` });
      return true;
    } catch (e) {
      if (e instanceof ConfigSaveCancelled) return false;
      pushToast(`${what} not saved. ${policyErrorText(e)}`, "danger");
      return false;
    }
  }

  return (
    <div className="space-y-4">
      {admissionOff ? <AdmissionOffNote what="edit the admission policy" /> : <PolicyEditor policyApi={policyApi} onApplied={onApplied} />}
      {restartError && (
        <Callout tone="warn" title="The daemon did not restart">
          {restartErrorText(restartError)}
        </Callout>
      )}
      <JudgeEditor configApi={configApi} saveAndRestart={saveAndRestart} />
      <BudgetEditor configApi={configApi} saveAndRestart={saveAndRestart} />
    </div>
  );
}

// SaveAndRestart is GuardrailsTab's save-then-restart flow for a config-read
// editor; it resolves whether the section was saved.
type SaveAndRestart = (what: string, body: unknown) => Promise<boolean>;

// ---------------- Policy (criteria + prefilter + mode) ----------------

function PolicyEditor({
  policyApi,
  onApplied,
}: {
  policyApi: ReturnType<typeof useApi<AdmissionPolicyGet>>;
  onApplied?: () => void;
}) {
  const [draft, setDraft] = useState<AdmissionPolicy | null>(null);
  const [busy, setBusy] = useState(false);
  const [issues, setIssues] = useState<LintIssue[]>([]);
  const [err, setErr] = useState("");

  // Hydrate the draft once the live policy loads. A structuredClone keeps the
  // edits local until the operator applies - a reload won't clobber in-progress
  // work unless it changes the loaded reference. The backend marshals empty
  // string slices as JSON null (regexpSources returns nil, criterion.Topics is
  // nil for non-topic types), so coerce every list to [] here - the form binds
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

  if (policyApi.loading && !draft) return <ChartShell title="Admission policy"><InlineLoading label="Loading admission policy" /></ChartShell>;
  if (!draft) {
    return (
      <ChartShell title="Admission policy">
        <ErrorState title="Couldn't load the admission policy" error={policyApi.error ?? "No policy came back."} onRetry={policyApi.reload} />
      </ChartShell>
    );
  }

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

  // submit applies the draft live and saves it (applyAdmissionPolicy, U-27).
  async function submit() {
    if (!draft) return;
    setBusy(true);
    setErr("");
    setIssues([]);
    try {
      const { status, data } = await applyAdmissionPolicy(draft);
      setIssues(data.issues ?? []);
      if (status === 409) {
        setErr(policyStatusText(409));
        return;
      }
      if (status === 422 || !data.applied) {
        setErr(data.error || "Fix the issues below, then apply again.");
        pushToast("Policy not applied. See the issues.", "danger");
        return;
      }
      if (!data.persisted) {
        // The live policy reads as unsaved on Policies until a save works.
        pushToast("Applied, but not saved: a daemon restart drops this policy.", "warn");
      } else {
        pushToast("Policy applied and saved.", "success");
      }
      policyApi.reload();
      onApplied?.();
    } catch (e) {
      setErr(policyErrorText(e));
      pushToast("Policy not applied.", "danger");
    } finally {
      setBusy(false);
    }
  }

  return (
    <ChartShell
      title="Admission policy"
      sub="The criteria, their mode and the deterministic pre-filter. Apply changes your app's front door and the proxy check now, and saves the policy."
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
              { value: "last_user", label: "Last user message" },
              { value: "conversation", label: "Conversation" },
            ]}
            value={draft.scope}
            onChange={(scope) => patch({ scope })}
          />
        </Labeled>
        <Toggle on={draft.strict} onChange={(strict) => patch({ strict })} label="Block when the judge fails" />
        <Labeled label="Secret with a remote judge">
          <Select
            value={draft.secret_remote_judge}
            onChange={(v) => patch({ secret_remote_judge: v as AdmissionPolicy["secret_remote_judge"] })}
            options={[
              { value: "", label: "Scrub and send" },
              { value: "allow", label: "Allow" },
              { value: "flag", label: "Flag" },
              { value: "ask", label: "Ask" },
              { value: "deny", label: "Deny on this machine" },
            ]}
          />
        </Labeled>
      </div>

      {draft.mode === "enforce" && (
        <Callout tone="warn" title="Enforce blocks end-user requests" className="mt-3">
          Check that the observe-only verdicts on Activity looked right first.
        </Callout>
      )}

      {/* Criteria */}
      <div className="mt-5 flex items-center justify-between">
        <h4 className="text-[12px] font-semibold text-fg-1">Criteria ({draft.criteria.length})</h4>
        <Button size="sm" iconLeft={Plus} onClick={addCriterion}>Add criterion</Button>
      </div>
      <div className="mt-2 space-y-3">
        {draft.criteria.length === 0 && (
          <EmptyState
            variant="inline"
            title="No criteria"
            body="The policy allows every request. Add a criterion, or apply a template."
          />
        )}
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
        <h4 className="mb-2 text-[12px] font-semibold text-fg-1">Deterministic pre-filter</h4>
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
        <Labeled label="Longest message in bytes (0 for no limit)" className="mt-3">
          <NumberInput className="w-32" min={0} value={draft.prefilter.max_message_bytes} onChange={(n) => patch({ prefilter: { ...draft.prefilter, max_message_bytes: n } })} />
        </Labeled>
      </div>

      {globalIssues.length > 0 && <IssueList issues={globalIssues} />}
      {err && <Callout tone="danger" title="Policy not applied" className="mt-3">{err}</Callout>}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button variant="primary" disabled={busy} loading={busy} onClick={() => void submit()}>
          {busy ? "Applying" : "Apply"}
        </Button>
      </div>
    </ChartShell>
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
    <div className="rounded-2 border border-line-2 bg-bg-3/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={c.type}
          onChange={(v) => onChange({ type: v as CriterionType })}
          options={CRITERION_TYPES.map((t) => ({ value: t.value, label: t.label }))}
          ariaLabel="Criterion type"
        />
        {judged ? (
          <Pill variant="info" title="Calls the LLM judge: adds latency and judge tokens per request.">LLM-judged</Pill>
        ) : (
          <Pill variant="neutral" title="Runs on this machine with no judge call.">deterministic</Pill>
        )}
        <TextInput
          value={c.name}
          onChange={(name) => onChange({ name })}
          placeholder="Name, e.g. on-scope"
          ariaLabel="Criterion name"
          className="w-auto min-w-[10rem] flex-1"
        />
        <Button size="sm" variant="ghost" iconLeft={Trash2} onClick={onRemove} aria-label={`Remove criterion ${c.name || c.id}`}>
          Remove
        </Button>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Labeled label="Decision">
          <SegmentedControl<Decision>
            size="sm"
            options={DECISIONS.map((d) => ({ value: d, label: d[0].toUpperCase() + d.slice(1) }))}
            value={c.decision}
            onChange={(decision) => onChange({ decision })}
          />
        </Labeled>
        <Labeled label="Severity">
          <Select value={c.severity} onChange={(v) => onChange({ severity: v as Severity })} options={SEVERITIES.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }))} />
        </Labeled>
      </div>

      {judged && (
        <Labeled label="Definition (what the judge should decide)" stacked className="mt-2">
          <TextArea value={c.definition} onChange={(v) => onChange({ definition: v })} rows={2} placeholder="Allow only questions about using the Acme product" />
        </Labeled>
      )}
      {c.type === "denied_topics" && (
        <Labeled label="Topics" stacked className="mt-2" group>
          <EntityMultiPicker
            options={keepSelected(TEMPLATE_TOPIC_OPTIONS, c.topics, "Your topics")}
            value={c.topics}
            onChange={(topics) => onChange({ topics })}
            allowFreeId
            freeIdLabel="Add topic"
            placeholder="Pick a topic, or type one and press Enter…"
            ariaLabel="Topics"
          />
          <p className="mt-1 text-[11px] text-fg-3">
            Each topic matches whole words in any letter case, and a plural or possessive form counts:
            "competitor" also catches "competitors" and "competitor's", but "hack" does not catch "hacking". End a
            topic with * to match every word that starts with it: "hack*" catches "hacking" and "hacker". A phrase
            matches only with its words in order. A topic needs at least one letter or digit.
          </p>
        </Labeled>
      )}

      {issues.length > 0 && <IssueList issues={issues} />}
    </div>
  );
}

// ---------------- Judge ----------------

// TEMPLATE_TOPIC_OPTIONS suggests the denied topics the shipped templates
// use; any other topic can still be typed (D-571: suggest known values).
const TEMPLATE_TOPIC_OPTIONS = uniqueSorted(
  TEMPLATE_CATALOG.flatMap((t) => (t.criteria ?? []).flatMap((c) => c.topics ?? [])),
).map((t) => ({ id: t, label: t, group: "From the templates" }));

function JudgeEditor({ configApi, saveAndRestart }: { configApi: ReturnType<typeof useApi<ConfigResponse>>; saveAndRestart: SaveAndRestart }) {
  const [draft, setDraft] = useState<JudgeConfig | null>(null);
  const models = useModelOptions();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const j = configApi.data?.config.Observability.Judge;
    if (j) setDraft({ ...j });
  }, [configApi.data]);

  if (!draft) {
    return (
      <ChartShell title="Judge">
        {configApi.error ? (
          <ErrorState title="Couldn't load the judge settings" error={configApi.error} onRetry={configApi.reload} />
        ) : (
          <InlineLoading label="Loading judge settings" />
        )}
      </ChartShell>
    );
  }
  const hosting = judgeHosting(draft.BaseURL);
  const patch = (p: Partial<JudgeConfig>) => setDraft({ ...draft, ...p });

  async function save() {
    setBusy(true);
    await saveAndRestart("Judge", { Judge: draft });
    setBusy(false);
  }

  return (
    <ChartShell
      title={
        <span className="inline-flex items-center gap-2">
          Judge <HostMark host={draft.BaseURL} size={12} />{" "}
          <Pill variant="info" case="none">{hosting === "none" ? "Not set up" : judgeHostingLabel(hosting)}</Pill>
        </span>
      }
      sub="The model that decides judged criteria. A local address keeps requests on this machine. Needs a restart."
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Labeled label="Model" stacked group>
          <SinglePicker
            options={keepSelected(models.options, draft.Model ? [draft.Model] : [])}
            value={draft.Model}
            onChange={(Model) => patch({ Model })}
            allowFree
            loading={models.loading}
            placeholder="qwen2.5:1.5b-instruct"
            ariaLabel="Judge model"
          />
        </Labeled>
        <Labeled label="Base URL" stacked>
          <Input value={draft.BaseURL} onChange={(e) => patch({ BaseURL: e.target.value })} placeholder="http://127.0.0.1:11434/v1" />
        </Labeled>
        <Labeled label="API key environment variable" stacked>
          <Input mono value={draft.APIKeyEnv} onChange={(e) => patch({ APIKeyEnv: e.target.value })} placeholder="OLLAMA_API_KEY" />
        </Labeled>
        <div className="grid grid-cols-3 gap-2">
          <Labeled label="Timeout (ms)" stacked><NumberInput min={0} value={draft.TimeoutMS} onChange={(n) => patch({ TimeoutMS: n })} /></Labeled>
          <Labeled label="Max tokens" stacked><NumberInput min={0} value={draft.MaxTokens} onChange={(n) => patch({ MaxTokens: n })} /></Labeled>
          <Labeled label="Context size" stacked><NumberInput min={0} value={draft.NumCtx} onChange={(n) => patch({ NumCtx: n })} /></Labeled>
        </div>
      </div>
      {hosting !== "local" && hosting !== "none" && (
        <Callout title="This judge runs off this machine" className="mt-3">
          Requests leave the machine with secrets scrubbed first. The key is read from the named variable, never stored here.
        </Callout>
      )}
      <div className="mt-4">
        <Button variant="primary" loading={busy} disabled={busy} onClick={() => void save()}>{busy ? "Saving" : "Save and restart"}</Button>
      </div>
    </ChartShell>
  );
}

// ---------------- Budget ----------------

function BudgetEditor({ configApi, saveAndRestart }: { configApi: ReturnType<typeof useApi<ConfigResponse>>; saveAndRestart: SaveAndRestart }) {
  const [draft, setDraft] = useState<BudgetConfig | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const b = configApi.data?.config.Observability.Admission.Budget;
    if (b) setDraft({ ...b });
  }, [configApi.data]);

  if (!draft) {
    return (
      <ChartShell title="Per-user budget">
        {configApi.error ? (
          <ErrorState title="Couldn't load the budget" error={configApi.error} onRetry={configApi.reload} />
        ) : (
          <InlineLoading label="Loading budget" />
        )}
      </ChartShell>
    );
  }
  const patch = (p: Partial<BudgetConfig>) => setDraft({ ...draft, ...p });

  async function save() {
    setBusy(true);
    await saveAndRestart("Budget", { Admission: { Budget: draft } });
    setBusy(false);
  }

  return (
    <ChartShell
      title="Per-user budget"
      sub="A spend cap for each end user. A breach is a deny, enforced only in enforce mode. Needs your app to name the end user."
    >
      <Toggle on={draft.Enabled} onChange={(Enabled) => patch({ Enabled })} label="Enforce per-user caps" />
      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Labeled label="5-hour cap (USD)" stacked><NumberInput min={0} value={draft.PerUser5hUSD} onChange={(n) => patch({ PerUser5hUSD: n })} step={0.5} /></Labeled>
        <Labeled label="Weekly cap (USD)" stacked><NumberInput min={0} value={draft.PerUserWeeklyUSD} onChange={(n) => patch({ PerUserWeeklyUSD: n })} step={1} /></Labeled>
        <Labeled label="Monthly cap (USD)" stacked><NumberInput min={0} value={draft.PerUserMonthlyUSD} onChange={(n) => patch({ PerUserMonthlyUSD: n })} step={1} /></Labeled>
      </div>
      <Labeled label="End-user header on proxied requests" stacked className="mt-3">
        <Input mono value={draft.UserHeader} onChange={(e) => patch({ UserHeader: e.target.value })} placeholder="X-Superbased-User" className="w-full max-w-sm" />
      </Labeled>
      <div className="mt-4">
        <Button variant="primary" loading={busy} disabled={busy} onClick={() => void save()}>{busy ? "Saving" : "Save and restart"}</Button>
      </div>
    </ChartShell>
  );
}

