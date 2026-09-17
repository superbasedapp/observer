import type { CloudEvidenceSettings } from "@/lib/cloud";
import { Input, Toggle } from "@/components/primitives";

export const DEFAULT_EVIDENCE_SETTINGS: CloudEvidenceSettings = {
  version: 1, user_messages: 15, assistant_messages: 1, failure_classes: 3,
  action_summaries: 256, excerpt_bytes: 1024, milestones: true, outcomes: true,
};

export function effectiveEvidenceSettings(value: CloudEvidenceSettings, excerpts: boolean): CloudEvidenceSettings {
  return excerpts ? value : { ...value, user_messages: Math.min(1, value.user_messages), assistant_messages: 0, failure_classes: 0 };
}

export function evidenceSettingsError(value: CloudEvidenceSettings): string | null {
  const counts = [value.user_messages, value.assistant_messages, value.failure_classes, value.action_summaries, value.excerpt_bytes];
  if (counts.some((n) => !Number.isInteger(n) || n < 0)) return "Use whole numbers of zero or more.";
  if (value.user_messages + value.assistant_messages + value.failure_classes > 20) return "Choose at most 20 message excerpts and failure classes in total.";
  if (value.failure_classes > 3 || value.action_summaries > 256 || value.excerpt_bytes < 128 || value.excerpt_bytes > 1024) return "Keep each value within the range shown.";
  return null;
}

export default function CloudEvidenceSettingsEditor({ value, excerpts, disabled, onChange }: {
  value: CloudEvidenceSettings;
  excerpts: boolean;
  disabled: boolean;
  onChange: (value: CloudEvidenceSettings) => void;
}) {
  const effective = effectiveEvidenceSettings(value, excerpts);
  const fields = [
    { key: "user_messages", label: "User messages", max: excerpts ? 20 : 1, min: 0, help: "Includes the first prompt. Later prompts are sampled across the session." },
    { key: "assistant_messages", label: "Latest assistant messages", max: 20, min: 0, help: "Short excerpts of the latest assistant replies, in time order.", needsExcerpts: true },
    { key: "failure_classes", label: "Failure categories", max: 3, min: 0, help: "Classified error labels and counts; no raw error output.", needsExcerpts: true },
    { key: "action_summaries", label: "Tool activity summaries", max: 256, min: 0, help: "Sampled operations and file categories; no file contents or paths." },
    { key: "excerpt_bytes", label: "Maximum bytes per message", max: 1024, min: 128, help: "Long messages are shortened and secrets are scrubbed." },
  ] as const;
  const error = evidenceSettingsError(effective);
  return (
    <fieldset disabled={disabled} className="mt-4 rounded-2 border border-line-2 p-3">
      <legend className="px-1 text-[12px] font-semibold text-fg-1">Evidence used for enrichment</legend>
      <p className="mb-3 text-[11.5px] leading-relaxed text-fg-3">
        These are maximum counts per session. Zero excludes a category. Settings apply to future background enrichment and become the defaults for Enrich now.
        {!excerpts && " Title only allows up to one user prompt. Turn on excerpts above to include more messages."}
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        {fields.map((field) => (
          <Input
            key={field.key}
            type="number"
            min={field.min}
            max={field.max}
            step={1}
            value={effective[field.key]}
            disabled={disabled || ("needsExcerpts" in field && !excerpts)}
            onChange={(event) => onChange({ ...effective, [field.key]: Number(event.target.value) })}
            label={field.label}
            help={`${field.min}–${field.max}. ${field.help}`}
          />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2">
        <Toggle
          on={effective.milestones}
          onChange={(next) => onChange({ ...effective, milestones: next })}
          disabled={disabled}
          label="Activity milestones"
        />
        <Toggle
          on={effective.outcomes}
          onChange={(next) => onChange({ ...effective, outcomes: next })}
          disabled={disabled}
          label="Test and build outcomes"
        />
      </div>
      <p className="mt-3 text-[11px] text-fg-3">{effective.user_messages + effective.assistant_messages + effective.failure_classes}/20 excerpt slots. Session identity, duration, token/cost totals, and activity counts remain in the structural summary. Raw tool output, reasoning, and file contents are excluded.</p>
      <p className="mt-2 text-[11px] text-fg-3">Saving cancels queued background uploads made under previous settings. Already delivered results stay available.</p>
      {error && <p role="alert" className="mt-2 text-[11.5px] text-danger">{error}</p>}
    </fieldset>
  );
}
