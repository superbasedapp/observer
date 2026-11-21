import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Callout,
  ChartShell,
  EmptyState,
  ErrorState,
  HostMark,
  Input,
  InlineLoading,
  Pill,
  SegmentedControl,
  SinglePicker,
  Tooltip,
} from "@/components/primitives";
import { contentClassOptions, keepSelected, uniqueSorted, type PickOption } from "@/lib/pickerOptions";
import { useCriterionIds, useEndUserOptions, useModelOptions } from "@/lib/usePickerSources";
import { Summary } from "@/components/Summary";
import { useApi } from "@/lib/useApi";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import { useDaemonRestart } from "@/lib/useDaemonRestart";
import { RestartOverlay } from "@/components/RestartOverlay";
import { restartErrorText } from "./AdmissionOff";
import {
  EGRESS_REASON_CODES,
  type EgressAction,
  type EgressActionKind,
  type EgressPolicy,
  type EgressPolicyGet,
  type EgressRule,
  type EgressTarget,
  type EgressWhen,
  type LintIssue,
  egressActionKind,
  emptyEgressWhen,
  policyErrorText,
  postPolicy,
} from "./types";
import { IssueList, Labeled, NumberInput, Select, TextInput } from "./ui";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { EGRESS_REASON_LABEL, TARGET_SHAPE_LABEL, wordsFor } from "./vocab";

// Routing tab - the Plane-A egress (routing) authoring surface: typed upstream
// targets + a first-match-wins WHEN→ROUTE rule table. Egress only takes real
// effect on the PROXY path (only the proxy can reroute an upstream), and the
// proxy holds a SEPARATE service instance - so "Check" validates and
// updates this dashboard's egress preview, but the routing behavior changes
// only after "Save & restart". The buttons say so.

const VERDICTS = ["", "allow", "flag", "ask", "deny"];
const SEVERITIES = ["", "info", "warn", "high", "critical"];
const EFFORTS = ["minimal", "low", "medium", "high"];
const ACTION_KINDS: { value: EgressActionKind; label: string }[] = [
  { value: "route_to_upstream", label: "Route to upstream" },
  { value: "route_to_model", label: "Swap model" },
  { value: "set_effort", label: "Set effort" },
  { value: "deny", label: "Deny" },
  { value: "no_route", label: "Log only" },
];
const cap = (v: string) => (v ? v[0].toUpperCase() + v.slice(1) : v);
const SHAPE_OPTIONS = ["openai", "anthropic"].map((v) => ({ value: v, label: wordsFor(TARGET_SHAPE_LABEL, v) }));

// RulePickers carries the known sets a rule's matchers and actions pick from
// (D-571): criterion ids of the admission policy, the draft's cohort labels,
// end users seen on verdicts, and the models this node uses or prices.
type RulePickers = {
  criteria: string[];
  cohorts: string[];
  users: PickOption[];
  models: { options: PickOption[]; loading: boolean };
};

export function RoutingTab({ onApplied }: { onApplied?: () => void }) {
  const api = useApi<EgressPolicyGet>("/api/obs/egress/policy");
  const [draft, setDraft] = useState<EgressPolicy | null>(null);
  const criteria = useCriterionIds();
  const models = useModelOptions();
  const namedUsers = useMemo(
    () => [...Object.keys(draft?.cohorts ?? {}), ...(draft?.rules ?? []).map((r) => r.when.user)],
    [draft],
  );
  const users = useEndUserOptions(namedUsers);
  const [busy, setBusy] = useState<"" | "apply" | "save">("");
  const [issues, setIssues] = useState<LintIssue[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!api.data) return;
    const p = structuredClone(api.data.policy);
    p.targets = p.targets ?? [];
    p.rules = (p.rules ?? []).map((r) => ({ ...r, when: { ...emptyEgressWhen(), ...r.when } }));
    p.cohorts = p.cohorts ?? {};
    setDraft(p);
  }, [api.data]);

  const globalIssues = useMemo(() => issues.filter((i) => !i.rule_name), [issues]);
  // "Save and restart" restarts (with the usual confirm), not only saves
  // (UI review U-29).
  const { restarting, error: restartError, restart } = useDaemonRestart();

  if (restarting) {
    return (
      <RestartOverlay
        title="Restarting the daemon…"
        body="Applying the routing policy and reconnecting. This page reloads automatically when the new process is up."
      />
    );
  }
  if (api.loading && !draft) return <ChartShell title="Egress policy"><InlineLoading label="Loading egress policy" /></ChartShell>;
  if (!draft) {
    return (
      <ChartShell title="Egress policy">
        <ErrorState title="Couldn't load the routing policy" error={api.error ?? "No policy came back."} onRetry={api.reload} />
      </ChartShell>
    );
  }

  const patch = (p: Partial<EgressPolicy>) => setDraft({ ...draft, ...p });
  const patchTarget = (i: number, t: Partial<EgressTarget>) =>
    setDraft({ ...draft, targets: draft.targets.map((x, n) => (n === i ? { ...x, ...t } : x)) });
  const patchRule = (i: number, r: Partial<EgressRule>) =>
    setDraft({ ...draft, rules: draft.rules.map((x, n) => (n === i ? { ...x, ...r } : x)) });
  const moveRule = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= draft.rules.length) return;
    const rules = draft.rules.slice();
    [rules[i], rules[j]] = [rules[j], rules[i]];
    setDraft({ ...draft, rules });
  };

  async function submit(persist: boolean) {
    setBusy(persist ? "save" : "apply");
    setErr("");
    setIssues([]);
    try {
      const { status, data } = await postPolicy("/api/obs/egress/policy", draft, persist);
      setIssues(data.issues ?? []);
      if (status === 422 || !data.applied) {
        setErr(data.error || "Policy rejected - fix the issues below.");
        pushToast("Egress policy not applied - see issues", "danger");
        return;
      }
      api.reload();
      onApplied?.();
      if (persist && !data.persisted) {
        pushToast("Checked, but not saved. Check that the config file is writable.", "warn");
      } else if (persist) {
        markRestartPending("egress policy");
        await restart({
          title: "Restart the daemon to apply the routing policy?",
          lead: "The routing policy is saved and applies on the proxy when the daemon starts again.",
        });
      } else {
        pushToast("Checked. The preview is updated; routing changes after Save and restart.", "success");
      }
    } catch (e) {
      setErr(policyErrorText(e));
      pushToast("Routing policy not applied.", "danger");
    } finally {
      setBusy("");
    }
  }

  const targetIds = draft.targets.map((t) => t.id).filter(Boolean);
  const pickers: RulePickers = {
    criteria: criteria.ids,
    cohorts: uniqueSorted(Object.values(draft.cohorts ?? {})),
    users: users.options,
    models,
  };

  return (
    <div className="space-y-4">
      {/* Targets */}
      <ChartShell
        title="Upstream targets"
        sub="Named upstreams a rule can route to. A route only goes to a target with the same API shape."
      >
        <div className="space-y-2">
          {draft.targets.length === 0 && (
            <EmptyState variant="inline" title="No targets" body="Add one before a rule can route to it." />
          )}
          {draft.targets.map((t, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2">
              {/* Serving-host mark resolved from the id / url (unknown renders nothing). */}
              <HostMark host={`${t.id} ${t.url}`} size={12} />
              <TextInput value={t.id} onChange={(id) => patchTarget(i, { id })} placeholder="Name, e.g. ollama-local" ariaLabel="Target name" className="w-auto min-w-[9rem]" />
              <TextInput value={t.url} onChange={(url) => patchTarget(i, { url })} placeholder="http://127.0.0.1:11434" ariaLabel="Target URL" className="w-auto min-w-[14rem] flex-1" />
              <Select
                value={t.shape}
                onChange={(shape) => patchTarget(i, { shape: shape as EgressTarget["shape"] })}
                options={SHAPE_OPTIONS}
                ariaLabel="API shape"
              />
              <Button
                size="sm"
                variant="ghost"
                iconLeft={Trash2}
                onClick={() => patch({ targets: draft.targets.filter((_, n) => n !== i) })}
                aria-label={`Remove target ${t.id || i + 1}`}
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
        <Button
          size="sm"
          iconLeft={Plus}
          className="mt-3"
          onClick={() => patch({ targets: [...draft.targets, { id: "", url: "", shape: "openai" }] })}
        >
          Add target
        </Button>
      </ChartShell>

      {/* Cohorts */}
      <CohortsCard value={draft.cohorts} onChange={(cohorts) => patch({ cohorts })} users={users.options} />

      {/* Rules */}
      <ChartShell
        title="Routing rules"
        sub="First match wins, so order matters. Each rule matches on the verdict, budget, cohort or request, then takes one action."
      >
        <div className="mb-3 flex flex-wrap items-center gap-x-6 gap-y-3">
          <Labeled label="Mode">
            <SegmentedControl<EgressPolicy["mode"]>
              options={[
                { value: "off", label: "Off" },
                { value: "advise", label: "Advise" },
                { value: "enforce", label: "Enforce" },
              ]}
              value={draft.mode}
              onChange={(mode) => patch({ mode })}
            />
          </Labeled>
          <Labeled label="Model switch cooldown (seconds)">
            <NumberInput className="w-24" min={0} value={draft.cooldown_seconds} onChange={(cooldown_seconds) => patch({ cooldown_seconds })} />
          </Labeled>
        </div>

        {draft.mode === "enforce" && (
          <Callout tone="warn" title="Enforce reroutes or denies end-user traffic" className="mb-3">
            Check that the advise-only decisions on Activity looked right first.
          </Callout>
        )}

        <div className="space-y-3">
          {draft.rules.length === 0 && (
            <EmptyState variant="inline" title="No rules" body="Nothing is rerouted. Add a rule, or apply a template." />
          )}
          {draft.rules.map((r, i) => (
            <RuleRow
              key={i}
              rule={r}
              index={i}
              count={draft.rules.length}
              targetIds={targetIds}
              pickers={pickers}
              issues={issues.filter((x) => x.rule_name === r.name && r.name !== "")}
              onChange={(p) => patchRule(i, p)}
              onRemove={() => patch({ rules: draft.rules.filter((_, n) => n !== i) })}
              onMove={(dir) => moveRule(i, dir)}
            />
          ))}
        </div>
        <Button
          size="sm"
          iconLeft={Plus}
          className="mt-3"
          onClick={() =>
            patch({
              rules: [
                ...draft.rules,
                { name: `rule-${draft.rules.length + 1}`, when: emptyEgressWhen(), action: { route_to_upstream: targetIds[0] ?? "", route_to_model: "", set_effort: "", deny: false, no_route: false }, on_unavailable: "fail_open", reason: "", reason_code: "" },
              ],
            })
          }
        >
          Add rule
        </Button>

        {globalIssues.length > 0 && <IssueList issues={globalIssues} />}
        {err && <Callout tone="danger" title="Policy not applied" className="mt-3">{err}</Callout>}
        {restartError && (
          <Callout tone="warn" title="The daemon did not restart" className="mt-3">
            {restartErrorText(restartError)}
          </Callout>
        )}

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Button disabled={busy !== ""} loading={busy === "apply"} onClick={() => void submit(false)}>
            {busy === "apply" ? "Checking" : "Check"}
          </Button>
          <Button variant="primary" disabled={busy !== ""} loading={busy === "save"} onClick={() => void submit(true)}>
            {busy === "save" ? "Saving" : "Save and restart"}
          </Button>
        </div>
      </ChartShell>
    </div>
  );
}

// CohortsCard edits the end-user → cohort map that a rule's user_cohort matcher
// keys on. It holds the rows in local state (seeded once) so a user id - the map
// KEY - can be typed without the entry vanishing mid-edit; every change emits a
// cleaned map (empty user ids dropped, values trimmed) up to the draft.
function CohortsCard({
  value,
  onChange,
  users,
}: {
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  users: PickOption[];
}) {
  const [rows, setRows] = useState<[string, string][]>(() => Object.entries(value ?? {}));
  const emit = (next: [string, string][]) => {
    setRows(next);
    const map: Record<string, string> = {};
    for (const [u, c] of next) if (u.trim()) map[u.trim()] = c.trim();
    onChange(map);
  };
  return (
    <ChartShell title="Cohorts" sub="Put end users in a named cohort so a rule can match on it. Optional, kept on this machine.">
      <div className="space-y-2">
        {rows.length === 0 && <EmptyState variant="inline" title="No cohorts" />}
        {rows.map(([u, c], i) => (
          <div key={i} className="flex flex-wrap items-center gap-2">
            <SinglePicker
              className="min-w-[12rem]"
              options={keepSelected(users, u ? [u] : [])}
              value={u}
              onChange={(v) => emit(rows.map((r, n) => (n === i ? [v, r[1]] : r)))}
              allowFree
              placeholder="end user"
              ariaLabel="End user id"
            />
            <span className="text-fg-3">→</span>
            <SinglePicker
              className="min-w-[10rem]"
              options={uniqueSorted(rows.map((r) => r[1]))}
              value={c}
              onChange={(v) => emit(rows.map((r, n) => (n === i ? [r[0], v] : r)))}
              allowFree
              freeLabel="New cohort"
              placeholder="cohort, e.g. eu"
              ariaLabel="Cohort"
            />
            <Button size="sm" variant="ghost" iconLeft={Trash2} onClick={() => emit(rows.filter((_, n) => n !== i))} aria-label={`Remove cohort entry ${u || i + 1}`}>
              Remove
            </Button>
          </div>
        ))}
      </div>
      <Button size="sm" iconLeft={Plus} className="mt-3" onClick={() => emit([...rows, ["", ""]])}>Add cohort</Button>
    </ChartShell>
  );
}

function RuleRow({
  rule,
  index,
  count,
  targetIds,
  pickers,
  issues,
  onChange,
  onRemove,
  onMove,
}: {
  rule: EgressRule;
  index: number;
  count: number;
  targetIds: string[];
  pickers: RulePickers;
  issues: LintIssue[];
  onChange: (p: Partial<EgressRule>) => void;
  onRemove: () => void;
  onMove: (dir: -1 | 1) => void;
}) {
  const kind = egressActionKind(rule.action);
  const setWhen = (w: Partial<EgressWhen>) => onChange({ when: { ...rule.when, ...w } });
  const setKind = (k: EgressActionKind) => {
    // One-hot the action so exactly one primary is set (lint requirement).
    const a: EgressAction = { route_to_upstream: "", route_to_model: "", set_effort: "", deny: false, no_route: false };
    if (k === "route_to_upstream") a.route_to_upstream = targetIds[0] ?? "";
    else if (k === "route_to_model") a.route_to_model = "";
    else if (k === "set_effort") a.set_effort = "medium";
    else if (k === "deny") a.deny = true;
    else a.no_route = true;
    onChange({ action: a });
  };
  const setAction = (a: Partial<EgressAction>) => onChange({ action: { ...rule.action, ...a } });

  return (
    <div className="rounded-2 border border-line-2 bg-bg-3/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10.5px] font-mono text-fg-3">#{index + 1}</span>
        <TextInput value={rule.name} onChange={(name) => onChange({ name })} placeholder="Rule name" ariaLabel="Rule name" className="w-auto min-w-[10rem] flex-1" />
        <div className="flex items-center gap-1">
          <Tooltip content="Move up (earlier match)">
            <Button size="sm" variant="ghost" iconLeft={ArrowUp} disabled={index === 0} onClick={() => onMove(-1)} aria-label="Move up (earlier match)" />
          </Tooltip>
          <Tooltip content="Move down">
            <Button size="sm" variant="ghost" iconLeft={ArrowDown} disabled={index === count - 1} onClick={() => onMove(1)} aria-label="Move down" />
          </Tooltip>
          <Button size="sm" variant="ghost" iconLeft={Trash2} onClick={onRemove} aria-label={`Remove rule ${rule.name || index + 1}`}>
            Remove
          </Button>
        </div>
      </div>

      {/* WHEN */}
      <div className="mt-2">
        <div className="mb-1 text-[11px] font-semibold text-fg-2">When</div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Labeled label="Verdict at least">
            <Select value={rule.when.verdict_at_least} onChange={(v) => setWhen({ verdict_at_least: v })} options={VERDICTS.map((v) => ({ value: v, label: cap(v) || "Any" }))} />
          </Labeled>
          <Labeled label="Severity at least">
            <Select value={rule.when.severity_at_least} onChange={(v) => setWhen({ severity_at_least: v })} options={SEVERITIES.map((s) => ({ value: s, label: cap(s) || "Any" }))} />
          </Labeled>
          <Labeled label="Criterion" group>
            <SinglePicker
              className="min-w-[10rem]"
              options={keepSelected(
                pickers.criteria.map((c) => ({ id: c, label: c })),
                rule.when.criterion ? [rule.when.criterion] : [],
                "Not in the admission policy",
              )}
              value={rule.when.criterion}
              onChange={(v) => setWhen({ criterion: v })}
              placeholder="(any)"
              emptyHint="The admission policy has no criteria yet."
              ariaLabel="Criterion"
            />
          </Labeled>
          <Labeled label="Provider">
            <Select value={rule.when.provider} onChange={(v) => setWhen({ provider: v })} options={[{ value: "", label: "Any" }, ...SHAPE_OPTIONS]} />
          </Labeled>
          <Labeled label="Budget used at least (0 to 1)">
            <Input
              type="number"
              step={0.1}
              min={0}
              max={1}
              value={rule.when.budget_band_at_least ?? ""}
              placeholder="unset"
              onChange={(e) => setWhen({ budget_band_at_least: e.target.value === "" ? null : Number(e.target.value) })}
              className="w-24"
            />
          </Labeled>
          <Labeled label="Cohort">
            <Select
              value={rule.when.user_cohort}
              onChange={(v) => setWhen({ user_cohort: v })}
              options={[
                { value: "", label: "Any" },
                ...uniqueSorted([...pickers.cohorts, rule.when.user_cohort]).map((c) => ({ value: c, label: c })),
              ]}
            />
          </Labeled>
        </div>
        <details className="mt-2">
          <Summary className="w-fit text-[10.5px] text-fg-3 hover:text-fg-2">More matchers</Summary>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
            <Labeled label="Content class" group>
              <SinglePicker
                className="min-w-[12rem]"
                options={keepSelected(
                  contentClassOptions(pickers.criteria, SEVERITIES),
                  rule.when.content_class ? [rule.when.content_class] : [],
                )}
                value={rule.when.content_class}
                onChange={(v) => setWhen({ content_class: v })}
                placeholder="(any)"
                ariaLabel="Content class"
              />
            </Labeled>
            <Labeled label="Model glob" group>
              <SinglePicker
                className="min-w-[12rem]"
                options={keepSelected(pickers.models.options, rule.when.model_glob ? [rule.when.model_glob] : [])}
                value={rule.when.model_glob}
                onChange={(v) => setWhen({ model_glob: v })}
                allowFree
                freeLabel="Use glob"
                loading={pickers.models.loading}
                placeholder="(any)"
                ariaLabel="Model glob"
              />
            </Labeled>
            <Labeled label="User" group>
              <SinglePicker
                className="min-w-[10rem]"
                options={keepSelected(pickers.users, rule.when.user ? [rule.when.user] : [])}
                value={rule.when.user}
                onChange={(v) => setWhen({ user: v })}
                allowFree
                placeholder="(any)"
                ariaLabel="User"
              />
            </Labeled>
            <Labeled label="Min prompt tokens"><NumberInput className="w-28" min={0} value={rule.when.min_prompt_tokens} onChange={(n) => setWhen({ min_prompt_tokens: n })} /></Labeled>
          </div>
        </details>
      </div>

      {/* THEN */}
      <div className="mt-3">
        <div className="mb-1 text-[11px] font-semibold text-fg-2">Then</div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Select value={kind} onChange={(k) => setKind(k as EgressActionKind)} options={ACTION_KINDS} ariaLabel="Action" />
          {kind === "route_to_upstream" && (
            <Labeled label="Target">
              {targetIds.length > 0 ? (
                <Select value={rule.action.route_to_upstream} onChange={(v) => setAction({ route_to_upstream: v })} options={targetIds.map((id) => ({ value: id, label: id }))} />
              ) : (
                <span className="text-[11px] text-fg-3">Add a target under Upstream targets first.</span>
              )}
            </Labeled>
          )}
          {kind === "route_to_model" && (
            <Labeled label="Model" group>
              <SinglePicker
                className="min-w-[12rem]"
                options={keepSelected(
                  pickers.models.options,
                  rule.action.route_to_model ? [rule.action.route_to_model] : [],
                )}
                value={rule.action.route_to_model}
                onChange={(v) => setAction({ route_to_model: v })}
                allowFree
                loading={pickers.models.loading}
                placeholder="Pick a model…"
                ariaLabel="Route to model"
              />
            </Labeled>
          )}
          {kind === "set_effort" && (
            <Labeled label="Effort">
              <Select value={rule.action.set_effort} onChange={(v) => setAction({ set_effort: v })} options={EFFORTS.map((e) => ({ value: e, label: cap(e) }))} />
            </Labeled>
          )}
          <Labeled label="On unavailable">
            <Select value={rule.on_unavailable} onChange={(v) => onChange({ on_unavailable: v })} options={[{ value: "fail_open", label: "Fall through" }, { value: "deny", label: "Deny" }]} />
          </Labeled>
          <Labeled label="Reason">
            <Select value={rule.reason_code} onChange={(v) => onChange({ reason_code: v })} options={EGRESS_REASON_CODES.map((c) => ({ value: c, label: wordsFor(EGRESS_REASON_LABEL, c) }))} />
          </Labeled>
        </div>
      </div>

      <div className="mt-2 rounded-2 bg-bg-3/60 px-2.5 py-1.5 text-[11px] leading-relaxed text-fg-2">
        <Pill variant="neutral" className="mr-1.5">preview</Pill>
        {previewSentence(rule)}
      </div>

      <IssueList issues={issues} />
    </div>
  );
}

// previewSentence renders a rule as a plain-English WHEN → THEN sentence so the
// operator can read the intent without decoding the matcher grid.
function previewSentence(r: EgressRule): string {
  const w = r.when;
  const conds: string[] = [];
  if (w.verdict_at_least) conds.push(`the verdict is at least ${w.verdict_at_least}`);
  if (w.severity_at_least) conds.push(`severity ≥ ${w.severity_at_least}`);
  if (w.criterion) conds.push(`criterion "${w.criterion}" fired`);
  if (w.provider) conds.push(`the provider is ${w.provider}`);
  if (w.budget_band_at_least != null) conds.push(`the user's budget burn ≥ ${Math.round(w.budget_band_at_least * 100)}%`);
  if (w.user_cohort) conds.push(`the user is in cohort "${w.user_cohort}"`);
  if (w.content_class) conds.push(`content class is "${w.content_class}"`);
  if (w.model_glob) conds.push(`the model matches "${w.model_glob}"`);
  if (w.user) conds.push(`the user is "${w.user}"`);
  if (w.min_prompt_tokens > 0) conds.push(`the prompt is ≥ ${w.min_prompt_tokens} tokens`);
  const when = conds.length ? conds.join(" and ") : "every request";

  const a = r.action;
  let then = "leave routing unchanged (log only)";
  if (a.deny) then = "deny the request";
  else if (a.route_to_upstream) then = `route to upstream "${a.route_to_upstream}"`;
  else if (a.route_to_model) then = `swap to model "${a.route_to_model}"`;
  else if (a.set_effort) then = `set reasoning effort to ${a.set_effort}`;

  const tail =
    a.route_to_upstream && r.on_unavailable === "deny"
      ? "; if that upstream is unavailable, deny"
      : a.route_to_upstream
        ? "; if unavailable, fall through"
        : "";

  return `When ${when}, ${then}${tail}.`;
}
