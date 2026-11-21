// HostedCloneWhereField.tsx is the Hosted sandboxes panel's clone location
// setting (lane CLONE2, decision SBXD-5): where a hosted row's "Clone a
// remote URL" source clones. Automatic (the default) clones a repository
// anyone can read inside the box and any other on this machine; the two
// pinned values always clone there. The panel mounts it with one line and
// owns the save (the same PUT as its sibling keys).

import { ComboChip } from "@/components/primitives";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";
import { CLONE_WHERE_VALUES } from "@/lib/hostedClone";

/** CLONE_WHERE_SETTING describes each value in plain words. */
const CLONE_WHERE_SETTING: Record<string, { label: string; hint: string }> = {
  auto: {
    label: "Automatically",
    hint: "A repository anyone can read is cloned inside the box. Any other is cloned on this machine with your git login, and its tracked files are uploaded. The New Terminal dialog can choose per launch.",
  },
  box: {
    label: "Inside the box",
    hint: "The box clones the repository itself: public repositories only, and only when the box may use the internet. Nothing of this machine's is uploaded.",
  },
  home: {
    label: "On this machine",
    hint: "This machine clones the repository with your git login and uploads its tracked files, never its history or a git credential. Private repositories work on every network setting.",
  },
};

export function HostedCloneWhereField({
  settingKey,
  value,
  disabled,
  pinned,
  onChange,
}: {
  /** settingKey names the config key this field edits (for the inventory). */
  settingKey: "clone_where";
  value: string;
  disabled: boolean;
  pinned: boolean;
  onChange: (next: string) => void;
}) {
  const current = CLONE_WHERE_SETTING[value] ? value : "auto";
  return (
    <div className="space-y-1" data-setting={settingKey}>
      <span id="sandbox-hosted-clone-where" className="block font-medium text-fg-1">
        Where a remote URL is cloned
        <HelpTooltip
          technical
          subject="the clone location"
          content="[terminal.sandbox.hosted].clone_where = auto | box | home (default auto); an organization may pin terminal.sandbox.hosted.clone_where"
          className="ml-1 align-middle"
        />
      </span>
      <ComboChip
        label="Where a remote URL is cloned"
        labelledBy="sandbox-hosted-clone-where"
        hideTriggerLabel
        fullWidth
        value={current}
        disabled={disabled}
        onChange={(v) => onChange(v)}
        options={CLONE_WHERE_VALUES.map((v) => ({ value: v, label: <span>{CLONE_WHERE_SETTING[v].label}</span>, searchable: CLONE_WHERE_SETTING[v].label }))}
        buttonValueRender={() => <span>{CLONE_WHERE_SETTING[current].label}</span>}
      />
      <span className="block text-[11px] text-fg-3">{CLONE_WHERE_SETTING[current].hint}</span>
      {pinned && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
    </div>
  );
}
