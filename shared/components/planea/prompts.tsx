import { useState, type ReactNode } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { History, RotateCcw, Tag } from "lucide-react";
import { Button } from "../../primitives/Button";
import { Icon } from "../../primitives/Icon";
import { Input } from "../../primitives/Input";
import { Select } from "../../primitives/Select";
import { Textarea } from "../../primitives/Textarea";
import { Toggle } from "../../primitives/Toggle";
import { Pill } from "../../primitives/Pill";
import { shortDate } from "../../lib/displayFormat";
import { PROMPT_TYPE } from "../../lib/obsVocab";
import { VocabDefPill } from "../../primitives/VocabDefPill";

// prompts - the pure Plane A prompt registry views (W3-3, lane B8; contract
// docs/plans/plane-a-sdk-buildout/contracts/prompts.md). The org dashboard
// (web2 /trajectories/prompts) and the machine dashboard (web, lane B5) render
// these over their own routes: /api/org/obs/prompts/* and /api/obs/prompts/*
// answer the same shapes (both are internal/promptreg's). Nothing here
// fetches or routes: data comes in through props, links and writes through
// callbacks. Diff, staged rollout and approval (W5-3, lane C8) are in
// promptRollout.tsx.

/** The two labels, in display order. */
export const PROMPT_LABELS = ["production", "staging"] as const;
export type PromptLabel = (typeof PROMPT_LABELS)[number];

/** A label -> version map; an unset label is absent. */
export type PromptLabelState = Partial<Record<PromptLabel, number>>;

/** A label's staged rollout (promptreg.Rollout): percent% of end users are
 *  served version instead of the label's own. */
export interface PromptRollout {
  version: number;
  percent: number;
}

/** The active rollout of each label; a label with none is absent. */
export type PromptRolloutState = Partial<Record<PromptLabel, PromptRollout>>;

/** One prompt in a list (promptreg.Summary). */
export interface PromptSummary {
  name: string;
  type: "text" | "chat";
  latest_version: number;
  labels: PromptLabelState;
  /** Only labels with a rollout (W5-3). */
  rollouts?: PromptRolloutState;
  updated_at: string;
}

/** A list page (promptreg.ListBody). */
export interface PromptListResult {
  api_version: string;
  prompts: PromptSummary[];
  next_after: string;
}

/** A chat message. */
export interface PromptMessage {
  role: string;
  content: string;
}

/** One version on the detail (promptreg.VersionView). */
export interface PromptVersionView {
  version: number;
  type: "text" | "chat";
  prompt: string | PromptMessage[];
  config: Record<string, unknown>;
  variables: string[];
  labels: PromptLabel[];
  digest: string;
  commit_message: string;
  created_by: string;
  created_at: string;
}

/** One label move (promptreg.MoveView). */
export interface PromptMoveView {
  label: PromptLabel;
  from_version: number;
  to_version: number;
  rollback: boolean;
  /** A rollout step (W5-3): the label's own version is unchanged and
   *  rollout_version / rollout_percent are its rollout after the step. */
  rollout?: boolean;
  rollout_version?: number;
  rollout_percent?: number;
  actor: string;
  at: string;
}

/** The management detail of one prompt (promptreg.DetailBody). */
export interface PromptDetail {
  name: string;
  type: "text" | "chat";
  latest_version: number;
  labels: PromptLabelState;
  versions: PromptVersionView[];
  history: PromptMoveView[];
  /** Per set label, the version a rollback would move it to. */
  rollback_targets: PromptLabelState;
  /** W5-3: each label's rollout, the org's approval setting (always false
   *  on a machine) and the pending proposals, newest first. */
  rollouts?: PromptRolloutState;
  approval_required?: boolean;
  proposals?: PromptProposal[];
}

/** One proposed production change (promptreg.ProposalView). */
export interface PromptProposal {
  id: string;
  name: string;
  label: PromptLabel;
  kind: "move" | "rollout";
  version: number;
  percent: number;
  base_version: number;
  base_rollout_version: number;
  base_rollout_percent: number;
  note: string;
  status: "pending" | "approved" | "rejected" | "stale";
  proposed_by: string;
  proposed_at: string;
  decided_by: string;
  decided_at: string;
  decision_note: string;
  /** The change in words, e.g. "production: 20% on version 4". */
  summary: string;
}

/** A create-version request (promptreg.Draft). */
export interface PromptDraft {
  type?: "text" | "chat";
  prompt: string | PromptMessage[];
  config?: Record<string, unknown>;
  commit_message?: string;
  labels?: PromptLabel[];
}

/** PromptLabelPills: one pill per label on a version. */
export function PromptLabelPills({ labels }: { labels: PromptLabel[] }) {
  if (labels.length === 0) return <span className="text-[11px] text-fg-3">-</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {labels.map((l) => (
        <Pill key={l} variant={l === "production" ? "success" : "info"}>
          {l}
        </Pill>
      ))}
    </span>
  );
}

function labelVersion(v: number | undefined): string {
  return v ? `v${v}` : "-";
}

/** promptColumns: name (via renderName), type, latest, the two labels, updated. */
export function promptColumns<R extends PromptSummary>(renderName: (row: R) => ReactNode): ColumnDef<R, any>[] {
  return [
    { accessorKey: "name", header: "Name", cell: ({ row }) => renderName(row.original) },
    { accessorKey: "type", header: "Type", cell: ({ row }) => <VocabDefPill of={PROMPT_TYPE} value={row.original.type} /> },
    {
      accessorKey: "latest_version",
      header: "Latest",
      cell: ({ row }) => `v${row.original.latest_version}`,
      meta: { align: "right" },
    },
    { id: "production", header: "Production", cell: ({ row }) => labelVersion(row.original.labels.production) },
    { id: "staging", header: "Staging", cell: ({ row }) => labelVersion(row.original.labels.staging) },
    { accessorKey: "updated_at", header: "Updated", cell: ({ row }) => shortDate(row.original.updated_at) },
  ];
}

/** PromptBodyView: a text body as preformatted text, a chat body as its
 *  messages. Placeholders stay visible as written ({{name}}). */
export function PromptBodyView({ prompt }: { prompt: string | PromptMessage[] }) {
  if (typeof prompt === "string") {
    return (
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded border border-line-2 bg-bg-2 p-3 font-mono text-[12px] text-fg-1">
        {prompt}
      </pre>
    );
  }
  return (
    <div className="grid gap-2">
      {prompt.map((m, i) => (
        <div key={i} className="rounded border border-line-2 bg-bg-2 p-2">
          <div className="mb-1 text-[11px] font-medium uppercase tracking-[0.06em] text-fg-3">{m.role}</div>
          <pre className="whitespace-pre-wrap break-words font-mono text-[12px] text-fg-1">{m.content}</pre>
        </div>
      ))}
    </div>
  );
}

/** The writes a version list offers; absent means read-only. */
export interface PromptWriteActions {
  /** Point label at version. */
  onMoveLabel: (label: PromptLabel, version: number) => void;
  /** Roll label back to detail.rollback_targets[label]. */
  onRollback: (label: PromptLabel) => void;
  /** The write in flight, if any (disables every control). */
  busy?: boolean;
}

/** PromptLabelBar: each label's current version, with its rollback. */
export function PromptLabelBar({ detail, actions }: { detail: PromptDetail; actions?: PromptWriteActions }) {
  return (
    <div className="flex flex-wrap gap-3">
      {PROMPT_LABELS.map((l) => {
        const current = detail.labels[l];
        const target = detail.rollback_targets[l];
        const ro = detail.rollouts?.[l];
        return (
          <div key={l} className="flex items-center gap-2 rounded border border-line-2 bg-bg-2 px-3 py-2">
            <Icon icon={Tag} size="sm" className="text-fg-3" />
            <span className="text-[12px] font-medium text-fg-1">{l}</span>
            <span className="text-[12px] text-fg-2">{current ? `version ${current}` : "not set"}</span>
            {ro ? (
              <Pill variant="warn">
                v{ro.version} to {ro.percent}%
              </Pill>
            ) : null}
            {actions && target ? (
              <Button size="sm" variant="ghost" iconLeft={RotateCcw} disabled={actions.busy} onClick={() => actions.onRollback(l)}>
                {ro ? "End rollout" : `Roll back to v${target}`}
              </Button>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

/** PromptVersionList: every version, newest first, with its body, variables,
 *  labels and (when actions are given) the label moves onto it. */
export function PromptVersionList({ detail, actions }: { detail: PromptDetail; actions?: PromptWriteActions }) {
  const [open, setOpen] = useState<number | null>(detail.versions[0]?.version ?? null);
  return (
    <div className="grid gap-2">
      {detail.versions.map((v) => (
        <div key={v.version} className="rounded border border-line-2">
          <button
            type="button"
            className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left hover:bg-bg-2"
            aria-expanded={open === v.version}
            onClick={() => setOpen(open === v.version ? null : v.version)}
          >
            <span className="flex min-w-0 items-center gap-3">
              <span className="font-mono text-[12px] font-medium text-fg-1">v{v.version}</span>
              <PromptLabelPills labels={v.labels} />
              <span className="truncate text-[12px] text-fg-3">{v.commit_message}</span>
            </span>
            <span className="shrink-0 text-[11px] text-fg-3">
              {v.created_by ? `${v.created_by} · ` : ""}
              {shortDate(v.created_at)}
            </span>
          </button>
          {open === v.version && (
            <div className="grid gap-3 border-t border-line-2 p-3">
              <PromptBodyView prompt={v.prompt} />
              <div className="flex flex-wrap gap-x-6 gap-y-1 text-[11px] text-fg-3">
                <span>Variables: {v.variables.length ? v.variables.join(", ") : "none"}</span>
                <span>Config: {Object.keys(v.config).length ? JSON.stringify(v.config) : "none"}</span>
                <span className="font-mono">{v.digest.slice(0, 19)}</span>
              </div>
              {actions && (
                <div className="flex flex-wrap gap-2">
                  {PROMPT_LABELS.filter((l) => !v.labels.includes(l)).map((l) => (
                    <Button key={l} size="sm" variant="secondary" iconLeft={Tag} disabled={actions.busy} onClick={() => actions.onMoveLabel(l, v.version)}>
                      Set {l}
                    </Button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/** PromptHistoryList: every label move, newest first. */
export function PromptHistoryList({ history }: { history: PromptMoveView[] }) {
  if (history.length === 0) return <p className="text-[12px] text-fg-3">No label has been set yet.</p>;
  return (
    <ul className="grid gap-1">
      {history.map((m, i) => (
        <li key={i} className="flex items-center gap-2 text-[12px] text-fg-2">
          <Icon icon={History} size="xs" className="text-fg-3" />
          <span className="font-medium text-fg-1">{m.label}</span>
          {m.rollout ? (
            <span>
              {m.rollout_percent ? `v${m.rollout_version} to ${m.rollout_percent}% (base v${m.to_version})` : `rollout ended (base v${m.to_version})`}
            </span>
          ) : (
            <span>
              {m.from_version ? `v${m.from_version}` : "unset"} → v{m.to_version}
            </span>
          )}
          {m.rollout && <Pill variant="info">rollout</Pill>}
          {m.rollback && <Pill variant="warn">rollback</Pill>}
          <span className="text-fg-3">
            {m.actor ? `${m.actor} · ` : ""}
            {shortDate(m.at)}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** parseChatMessages reads a chat body typed as JSON; null when it is not a
 *  non-empty array of {role, content} strings. */
export function parseChatMessages(text: string): PromptMessage[] | null {
  try {
    const v: unknown = JSON.parse(text);
    if (!Array.isArray(v) || v.length === 0) return null;
    for (const m of v) {
      if (typeof m !== "object" || m === null || typeof (m as PromptMessage).role !== "string" || typeof (m as PromptMessage).content !== "string") {
        return null;
      }
    }
    return v as PromptMessage[];
  } catch {
    return null;
  }
}

/** PromptDraftForm: a new version. name is fixed when the prompt exists
 *  (lockedName) and typed otherwise; the type follows an existing prompt. */
export function PromptDraftForm({
  lockedName,
  lockedType,
  initial,
  busy,
  error,
  onSubmit,
}: {
  lockedName?: string;
  lockedType?: "text" | "chat";
  /** Prefill from the latest version. */
  initial?: PromptVersionView;
  busy?: boolean;
  error?: string | null;
  onSubmit: (name: string, draft: PromptDraft) => void;
}) {
  const [name, setName] = useState(lockedName ?? "");
  const [type, setType] = useState<"text" | "chat">(lockedType ?? initial?.type ?? "text");
  const [body, setBody] = useState(
    initial ? (typeof initial.prompt === "string" ? initial.prompt : JSON.stringify(initial.prompt, null, 2)) : "",
  );
  const [config, setConfig] = useState(initial && Object.keys(initial.config).length ? JSON.stringify(initial.config) : "");
  const [message, setMessage] = useState("");
  const [labels, setLabels] = useState<PromptLabel[]>([]);
  const [local, setLocal] = useState<string | null>(null);

  function submit() {
    const n = name.trim();
    if (!n) return setLocal("Name is required.");
    let prompt: string | PromptMessage[] = body;
    if (type === "chat") {
      const msgs = parseChatMessages(body);
      if (!msgs) return setLocal('A chat prompt is a JSON list of {"role": ..., "content": ...} messages.');
      prompt = msgs;
    } else if (!body) {
      return setLocal("The prompt is empty.");
    }
    let cfg: Record<string, unknown> | undefined;
    if (config.trim()) {
      try {
        const parsed: unknown = JSON.parse(config);
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("not an object");
        cfg = parsed as Record<string, unknown>;
      } catch {
        return setLocal("Config is a JSON object, for example {\"model\": \"gpt-5.1-mini\"}.");
      }
    }
    setLocal(null);
    onSubmit(n, { type, prompt, config: cfg, commit_message: message.trim() || undefined, labels: labels.length ? labels : undefined });
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!busy) submit();
      }}
      className="grid gap-3"
    >
      <Input label="Name" value={name} disabled={!!lockedName} maxLength={128} placeholder="e.g. support-reply" onChange={(e) => setName(e.target.value)} />
      <Select
        label="Type"
        value={type}
        disabled={!!lockedType}
        onChange={(e) => setType(e.target.value as "text" | "chat")}
        options={[
          { value: "text", label: "Text" },
          { value: "chat", label: "Chat (a JSON list of messages)" },
        ]}
      />
      <Textarea label={<>Prompt (placeholders are {"{{name}}"})</>} mono className="min-h-40" value={body} onChange={(e) => setBody(e.target.value)} />
      <Input
        label="Config (optional JSON object)"
        mono
        value={config}
        onChange={(e) => setConfig(e.target.value)}
        placeholder='{"model": "gpt-5.1-mini", "temperature": 0.2}'
      />
      <Input label="Note (optional)" value={message} maxLength={500} onChange={(e) => setMessage(e.target.value)} />
      <fieldset className="space-y-1.5">
        <legend className="mb-1 text-xs font-medium text-fg-2">Move labels onto the new version</legend>
        <div className="flex flex-wrap gap-4">
          {PROMPT_LABELS.map((l) => (
            <Toggle
              key={l}
              on={labels.includes(l)}
              onChange={(on) => setLabels(on ? [...labels, l] : labels.filter((x) => x !== l))}
              label={l.charAt(0).toUpperCase() + l.slice(1)}
            />
          ))}
        </div>
      </fieldset>
      <div>
        <Button type="submit" variant="primary" loading={busy}>
          Create version
        </Button>
      </div>
      {(local || error) && (
        <p role="alert" className="text-[11px] text-danger">
          {local ?? error}
        </p>
      )}
    </form>
  );
}
