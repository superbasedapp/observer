import { useState } from "react";
import { Check, GitCompare, Percent, X } from "lucide-react";
import { Button } from "../../primitives/Button";
import { Icon } from "../../primitives/Icon";
import { Input } from "../../primitives/Input";
import { Select } from "../../primitives/Select";
import { Pill } from "../../primitives/Pill";
import { shortDate } from "../../lib/displayFormat";
import { PROMPT_LABELS, type PromptDetail, type PromptLabel, type PromptProposal } from "./prompts";

// promptRollout - the pure W5-3 prompt views (lane C8; contract
// docs/plans/plane-a-sdk-buildout/contracts/prompts.md section 9): the
// version diff, a label's staged rollout, and production approval. The org
// dashboard renders all three; the machine dashboard renders the diff and
// the rollout (a machine has one user, so approval does not apply there).
// Nothing here fetches or routes: data comes in through props, writes go out
// through callbacks.

/** One line of a text diff (promptreg.DiffLine). */
export interface PromptDiffLine {
  op: "equal" | "add" | "remove";
  text: string;
}

/** One chat message's diff (promptreg.MessageDiff). */
export interface PromptMessageDiff {
  index: number;
  status: "added" | "removed" | "changed" | "same";
  from_role?: string;
  to_role?: string;
  lines: PromptDiffLine[];
}

/** One top-level config key that differs (promptreg.ConfigChange). */
export interface PromptConfigChange {
  key: string;
  status: "added" | "removed" | "changed";
  from?: unknown;
  to?: unknown;
}

/** A version-to-version diff (promptreg.DiffBody). */
export interface PromptDiff {
  name: string;
  from_version: number;
  to_version: number;
  type: "text" | "chat";
  identical: boolean;
  lines?: PromptDiffLine[];
  messages?: PromptMessageDiff[];
  variables_added: string[];
  variables_removed: string[];
  config: PromptConfigChange[];
  commit_message: string;
  approximate: boolean;
}

const LINE_CLASS: Record<PromptDiffLine["op"], string> = {
  equal: "text-fg-2",
  add: "bg-success-soft text-success",
  remove: "bg-danger-soft text-danger",
};
const LINE_MARK: Record<PromptDiffLine["op"], string> = { equal: " ", add: "+", remove: "-" };

function DiffLines({ lines }: { lines: PromptDiffLine[] }) {
  if (lines.length === 0) return <p className="text-[11px] text-fg-3">(empty)</p>;
  return (
    <pre className="max-h-96 overflow-auto rounded border border-line-2 bg-bg-2 font-mono text-[12px]">
      {lines.map((l, i) => (
        <div key={i} className={`whitespace-pre-wrap break-words px-2 ${LINE_CLASS[l.op]}`}>
          <span aria-hidden className="select-none pr-2 text-fg-3">
            {LINE_MARK[l.op]}
          </span>
          <span className="sr-only">{l.op === "equal" ? "" : l.op === "add" ? "added: " : "removed: "}</span>
          {l.text}
        </div>
      ))}
    </pre>
  );
}

function jsonText(v: unknown): string {
  return v === undefined ? "-" : JSON.stringify(v);
}

/** PromptDiffView: what changed from one version to another. */
export function PromptDiffView({ diff }: { diff: PromptDiff }) {
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-2">
        <Icon icon={GitCompare} size="sm" className="text-fg-3" />
        <span>
          v{diff.from_version} → v{diff.to_version}
        </span>
        {diff.identical && <Pill variant="neutral">same content</Pill>}
        {diff.approximate && <Pill variant="warn">long text: the middle is shown replaced whole</Pill>}
        {diff.commit_message && <span className="text-fg-3">“{diff.commit_message}”</span>}
      </div>
      {diff.lines && <DiffLines lines={diff.lines} />}
      {diff.messages?.map((m) => (
        <div key={m.index} className="grid gap-1">
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.06em] text-fg-3">
            <span>Message {m.index + 1}</span>
            <span>{m.from_role && m.to_role && m.from_role !== m.to_role ? `${m.from_role} → ${m.to_role}` : (m.to_role ?? m.from_role)}</span>
            {m.status !== "same" && <Pill variant={m.status === "added" ? "success" : m.status === "removed" ? "danger" : "info"}>{m.status}</Pill>}
          </div>
          <DiffLines lines={m.lines} />
        </div>
      ))}
      <div className="grid gap-1 text-[12px] text-fg-2">
        <span>
          Variables added: {diff.variables_added.length ? diff.variables_added.join(", ") : "none"}; removed:{" "}
          {diff.variables_removed.length ? diff.variables_removed.join(", ") : "none"}
        </span>
        {diff.config.length === 0 ? (
          <span>Config: unchanged</span>
        ) : (
          <ul className="grid gap-0.5">
            {diff.config.map((c) => (
              <li key={c.key} className="font-mono text-[11px]">
                {c.key}: {c.status === "added" ? `+ ${jsonText(c.to)}` : c.status === "removed" ? `- ${jsonText(c.from)}` : `${jsonText(c.from)} → ${jsonText(c.to)}`}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

/** PromptDiffPicker: choose the two versions to compare. */
export function PromptDiffPicker({
  latest,
  from,
  to,
  onChange,
}: {
  latest: number;
  from: number;
  to: number;
  onChange: (from: number, to: number) => void;
}) {
  const versions = Array.from({ length: latest }, (_, i) => latest - i);
  const opts = versions.map((v) => ({ value: String(v), label: `v${v}` }));
  return (
    <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-2">
      <span>Compare</span>
      <Select aria-label="From version" className="w-auto" value={String(from)} onChange={(e) => onChange(Number(e.target.value), to)} options={opts} />
      <span>with</span>
      <Select aria-label="To version" className="w-auto" value={String(to)} onChange={(e) => onChange(from, Number(e.target.value))} options={opts} />
    </div>
  );
}

/** The rollout writes a page offers; absent means read-only. */
export interface PromptRolloutActions {
  /** Set label's rollout: percent 1-99 starts or changes it, 100 promotes the
   *  candidate, 0 ends the rollout. */
  onSetRollout: (label: PromptLabel, version: number, percent: number) => void;
  busy?: boolean;
  /** When set, a production change that raises what it serves is proposed
   *  instead (the org requires approval): the button says Propose. */
  approvalRequired?: boolean;
}

/** PromptRolloutPanel: each set label's staged rollout, with the controls to
 *  start, change, promote and end it. */
export function PromptRolloutPanel({ detail, actions }: { detail: PromptDetail; actions?: PromptRolloutActions }) {
  return (
    <div className="grid gap-3">
      <p className="text-[12px] text-fg-3">
        A rollout serves a candidate version to a percent of a label's end users (by end user, else session), so you can try
        it on some traffic first. 100% promotes it to the label; 0% or a rollback ends it. Only SDKs that send an end user or
        session take part; others keep getting the label's own version.
      </p>
      {PROMPT_LABELS.map((l) => (
        <RolloutRow key={l} label={l} detail={detail} actions={actions} />
      ))}
    </div>
  );
}

function RolloutRow({ label, detail, actions }: { label: PromptLabel; detail: PromptDetail; actions?: PromptRolloutActions }) {
  const base = detail.labels[label];
  const ro = detail.rollouts?.[label];
  const candidates = detail.versions.map((v) => v.version).filter((v) => v !== base);
  const [candidate, setCandidate] = useState<number>(ro?.version ?? candidates[0] ?? 0);
  const [percent, setPercent] = useState<number>(ro?.percent ?? 10);
  if (!base) {
    return (
      <div className="rounded border border-line-2 px-3 py-2 text-[12px] text-fg-3">
        <span className="font-medium text-fg-1">{label}</span>: set the label before rolling a version out on it.
      </div>
    );
  }
  const gated = actions?.approvalRequired && label === "production";
  const raises = (p: number) => !ro || ro.version !== candidate || p > ro.percent;
  const verb = (p: number) => (gated && raises(p) ? "Propose" : p >= 100 ? "Promote" : ro ? "Update" : "Start");
  return (
    <div className="grid gap-2 rounded border border-line-2 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <span className="font-medium text-fg-1">{label}</span>
        <span className="text-fg-2">serves v{base}</span>
        {ro ? (
          <Pill variant="warn">
            v{ro.version} to {ro.percent}% of end users
          </Pill>
        ) : (
          <span className="text-fg-3">no rollout</span>
        )}
      </div>
      {actions && candidates.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <label className="inline-flex items-center gap-1 text-[12px] text-fg-2">
            Candidate
            <Select
              className="w-auto"
              value={String(candidate)}
              disabled={actions.busy}
              onChange={(e) => setCandidate(Number(e.target.value))}
              options={candidates.map((v) => ({ value: String(v), label: `v${v}` }))}
            />
          </label>
          <label className="inline-flex items-center gap-1 text-[12px] text-fg-2">
            <Icon icon={Percent} size="xs" className="text-fg-3" />
            <Input
              type="number"
              min={1}
              max={99}
              className="w-20"
              value={percent}
              disabled={actions.busy}
              onChange={(e) => setPercent(Math.max(1, Math.min(99, Number(e.target.value) || 1)))}
              aria-label={`${label} rollout percent`}
            />
          </label>
          <Button size="sm" variant="secondary" disabled={actions.busy} onClick={() => actions.onSetRollout(label, candidate, percent)}>
            {verb(percent)} {percent}%
          </Button>
          <Button size="sm" variant="secondary" disabled={actions.busy} onClick={() => actions.onSetRollout(label, candidate, 100)}>
            {gated ? "Propose promoting" : "Promote"} v{candidate}
          </Button>
          {ro && (
            <Button size="sm" variant="ghost" disabled={actions.busy} onClick={() => actions.onSetRollout(label, ro.version, 0)}>
              End rollout
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

const STATUS_TONE: Record<PromptProposal["status"], "info" | "success" | "neutral" | "warn"> = {
  pending: "info",
  approved: "success",
  rejected: "neutral",
  stale: "warn",
};

/** The proposal decisions a page offers; absent means read-only. */
export interface PromptProposalActions {
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
  busy?: boolean;
  /** The signed-in member: their own proposals offer Withdraw, never Approve. */
  me?: string;
}

/** PromptProposalList: proposed label changes, with approve and reject. */
export function PromptProposalList({
  proposals,
  actions,
  showName,
}: {
  proposals: PromptProposal[];
  actions?: PromptProposalActions;
  /** Show each proposal's prompt name (the org-wide list). */
  showName?: boolean;
}) {
  if (proposals.length === 0) return <p className="text-[12px] text-fg-3">No proposals waiting.</p>;
  return (
    <ul className="grid gap-2">
      {proposals.map((p) => {
        const mine = !!actions?.me && actions.me === p.proposed_by;
        return (
          <li key={p.id} className="flex flex-wrap items-center gap-2 rounded border border-line-2 px-3 py-2 text-[12px]">
            <Pill variant={STATUS_TONE[p.status]}>{p.status}</Pill>
            {showName && <span className="font-medium text-fg-1">{p.name}</span>}
            <span className="text-fg-1">{p.summary}</span>
            <span className="text-fg-3">
              by {p.proposed_by || "unknown"} · {shortDate(p.proposed_at)}
            </span>
            {p.note && <span className="text-fg-2">“{p.note}”</span>}
            {p.decided_by && (
              <span className="text-fg-3">
                {p.status} by {p.decided_by}
              </span>
            )}
            {actions && p.status === "pending" && (
              <span className="ml-auto inline-flex gap-2">
                {!mine && (
                  <Button size="sm" variant="primary" iconLeft={Check} disabled={actions.busy} onClick={() => actions.onApprove(p.id)}>
                    Approve
                  </Button>
                )}
                <Button size="sm" variant="ghost" iconLeft={X} disabled={actions.busy} onClick={() => actions.onReject(p.id)}>
                  {mine ? "Withdraw" : "Reject"}
                </Button>
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** PromptApprovalSetting: the org's "require approval for production" switch.
 * Turning it on needs policy write access; turning it off also needs the
 * organization's super admin (ruling D28), so for anyone else the switch
 * stays on and says who can turn it off (E-74). */
export function PromptApprovalSetting({
  required,
  onChange,
  busy,
  canTurnOff = true,
}: {
  required: boolean;
  /** Absent means read-only. */
  onChange?: (required: boolean) => void;
  busy?: boolean;
  /** False when the viewer is not the organization's super admin. */
  canTurnOff?: boolean;
}) {
  const lockedOn = required && !canTurnOff;
  return (
    <label className="inline-flex items-start gap-2 text-[12px] text-fg-1">
      <input
        type="checkbox"
        className="mt-0.5"
        checked={required}
        disabled={!onChange || busy || lockedOn}
        title={lockedOn ? "Only the organization's super admin can turn this off." : undefined}
        onChange={(e) => onChange?.(e.target.checked)}
      />
      <span>
        Require a second member's approval before production changes
        <span className="block text-[11px] text-fg-3">
          A move, a new version labelled production, or a rollout that raises what production serves is proposed, then approved
          by a different member with policy write access. Rollbacks and ending or lowering a rollout never wait.
        </span>
        <span className="block text-[11px] text-fg-3">
          {lockedOn
            ? "Only the organization's super admin can turn this off. Ask them if production changes should stop waiting for approval."
            : "Any member with policy write access can turn this on; only the organization's super admin can turn it off."}
        </span>
      </span>
    </label>
  );
}
