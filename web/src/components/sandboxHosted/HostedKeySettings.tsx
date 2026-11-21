// HostedKeySettings.tsx edits the per-agent key settings of
// [terminal.sandbox.hosted] (decisions SBXD-1 and SBXD-4,
// docs/decisions/sandbox-terminal-decisions-2026-11.md): where each agent's
// model key sits when it differs from the setting for every hosted sandbox,
// and the two opt-in sources of a key put in the box (an agent's own saved
// keys, its login's access token). The Hosted sandboxes panel mounts it with
// one line; the card owns the save (the same PUT as the panel's other keys).
// The agents it can name come from the daemon (key_tools, read from the
// integration registry), never from this file.

import { ComboChip } from "@/components/primitives";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";

/** The per-agent key settings of the hosted block, as the daemon sends them. */
export type HostedKeySettingsValue = {
  key_custody_by_tool?: Record<string, string>;
  tool_keys?: Record<string, boolean>;
  login_seed?: Record<string, boolean>;
  /** Read-only: the agents these settings can name (ignored on save). */
  key_tools?: { tools: { id: string; name: string }[]; saved_keys: string[]; login_seed: string[] };
};

const CHOICES = [
  { value: "auto", label: "Keep it on this machine when Observer can add it, else in the box" },
  { value: "home_relay", label: "Always keep it on this machine" },
  { value: "in_box_api_key", label: "Always put the API key in the box (disclosed)" },
];

export function HostedKeySettings({
  value,
  writable,
  onChange,
}: {
  value: HostedKeySettingsValue;
  writable: boolean;
  onChange: (next: HostedKeySettingsValue) => void;
}) {
  const tools = value.key_tools?.tools ?? [];
  if (tools.length === 0) return null; // a daemon that predates these settings
  const name = (id: string) => tools.find((t) => t.id === id)?.name ?? id;
  const byTool = value.key_custody_by_tool ?? {};
  const set = (next: Partial<HostedKeySettingsValue>) => onChange({ ...value, ...next });
  const setTool = (id: string, c: string | null) => {
    const m = { ...byTool };
    if (c === null) delete m[id];
    else m[id] = c;
    set({ key_custody_by_tool: m });
  };
  const flag = (key: "tool_keys" | "login_seed", id: string, on: boolean) => {
    const m = { ...(value[key] ?? {}) };
    if (on) m[id] = true;
    else delete m[id];
    set({ [key]: m });
  };
  const unset = tools.filter((t) => !(t.id in byTool));
  return (
    <div className="space-y-3 rounded-2 border border-line-2 p-3 md:col-span-2" data-testid="sandbox-hosted-key-settings">
      <div className="font-medium text-fg-1">
        Model key per agent
        <HelpTooltip
          technical
          subject="the per-agent key settings"
          content="[terminal.sandbox.hosted.key_custody_by_tool] (tool -> auto, home_relay or in_box_api_key) wins over key_custody for that tool. [terminal.sandbox.hosted.tool_keys] and [terminal.sandbox.hosted.login_seed] (tool -> true) are read only when the key goes in the box. All three default to empty, and the hosted consent binds them."
          className="ml-1 align-middle"
        />
      </div>
      <p className="text-[11px] text-fg-3">
        Set an agent apart from the setting above. The New Terminal dialog says which one each launch uses before Start.
      </p>
      <ul className="space-y-2">
        {Object.keys(byTool)
          .sort()
          .map((id) => (
            <li key={id} className="flex flex-wrap items-center gap-2">
              <span className="min-w-[8rem] text-fg-2">{name(id)}</span>
              <div className="min-w-0 flex-1">
                <ComboChip
                  label={`${name(id)} model key`}
                  hideTriggerLabel
                  fullWidth
                  value={byTool[id]}
                  disabled={!writable}
                  onChange={(v) => setTool(id, v)}
                  options={CHOICES.map((c) => ({ value: c.value, label: <span>{c.label}</span>, searchable: c.label }))}
                  buttonValueRender={() => <span>{CHOICES.find((c) => c.value === byTool[id])?.label ?? byTool[id]}</span>}
                />
              </div>
              <button type="button" className="text-[11px] text-fg-3 underline" disabled={!writable} onClick={() => setTool(id, null)}>
                Remove
              </button>
            </li>
          ))}
      </ul>
      {unset.length > 0 && (
        <ComboChip
          label="Set an agent apart"
          hideTriggerLabel
          fullWidth
          value=""
          disabled={!writable}
          onChange={(v) => v && setTool(v, "auto")}
          options={unset.map((t) => ({ value: t.id, label: <span>{t.name}</span>, searchable: t.name }))}
          buttonValueRender={() => <span>Set an agent apart…</span>}
        />
      )}
      {[
        { key: "tool_keys" as const, ids: value.key_tools?.saved_keys ?? [], label: (n: string) => `Also use the keys ${n} saved itself` },
        { key: "login_seed" as const, ids: value.key_tools?.login_seed ?? [], label: (n: string) => `Also copy my ${n} login (its short-lived access token only, never the refresh token)` },
      ].map(({ key, ids, label }) =>
        ids.map((id) => (
          <label key={key + id} className="flex items-start gap-2">
            <input type="checkbox" className="mt-0.5" checked={!!value[key]?.[id]} disabled={!writable} onChange={(e) => flag(key, id, e.target.checked)} />
            <span>
              <span className="text-fg-1">{label(name(id))}</span>
              <span className="block text-[11px] text-fg-3">
                Off by default. Used only when this agent&apos;s key goes in the box, read when the run starts, and named on the
                consent screen before it is first used.
              </span>
            </span>
          </label>
        )),
      )}
    </div>
  );
}
