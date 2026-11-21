// SandboxHostedPanel.tsx is the "Hosted sandboxes" sub-panel of the Sandbox
// isolation card (sandbox plan v2 sections 9, 10.1 and 13 P7, lane SBX-P7):
// the editor for [terminal.sandbox.hosted], the E2B, Modal and Vercel Sandbox
// rows (each beta). The card mounts it with one line and owns the save; this
// panel edits its own block with pickers only, and renders nothing unless a
// [components] block selects one of the hosted drivers (they are opt-in and
// inactive in every distro). No credential is ever part of this block. Each
// provider's template and in-box observer binary are typed here (dashboard
// CLI parity plan item B-G6; both are checked again by the daemon's config
// validation on save).

import { useLocation } from "react-router-dom";
import { ComboChip, Input } from "@/components/primitives";
import { SandboxHostedStatus } from "@/components/SandboxHostedStatus";
import { PrivateRangesField } from "@/components/sandboxHosted/PrivateRangesField";
import { GuardHooksField } from "@/components/sandboxHosted/GuardHooksField";
import { HostedCloneWhereField } from "@/components/sandboxHosted/HostedCloneWhereField";
import { HostedKeySettings, type HostedKeySettingsValue } from "@/components/sandboxHosted/HostedKeySettings";
import { HostedUploadFields } from "@/components/sandboxHosted/HostedUploadFields";
import type { ComponentsView } from "@/lib/componentState";
import { absPathProblem, hostedTemplateProblem } from "@/lib/sandboxParity";
import { TERMINALS_HOSTED_SANDBOXES_HASH } from "@/lib/nodePageTabs";
import { HIGHLIGHT_CLASS, hashNames } from "@/lib/scrollHighlight";
import { useScrollHighlight } from "@/lib/useScrollHighlight";

export type SandboxHostedProvider = {
  region: string;
  template: string;
  box_binary: string;
};

export type SandboxHostedConfig = HostedKeySettingsValue & {
  min_session_minutes: number;
  key_custody: string;
  memory_images: string;
  checkpoint_minutes: number;
  max_run_minutes: number;
  daily_box_minutes: number;
  // db_export is the opt-in in-box database export at teardown (ruling
  // P-141); absent from a daemon that predates it.
  db_export?: boolean;
  // diff_against is what an upload run's saved diff is taken against
  // ("baseline", the default, or "head"); absent from a daemon that
  // predates it.
  diff_against?: string;
  // guard_hooks is whether a box gets guard's hooks (auto, on, off; lane
  // HOOKS); absent from a daemon that predates it.
  guard_hooks?: string;
  // clone_where is where a remote URL is cloned (decision SBXD-5); absent
  // from a daemon that predates it.
  clone_where?: string;
  // upload_non_git and upload_ignore (decision SBXD-8, the HostedUploadFields
  // block); absent from a daemon that predates them.
  upload_non_git?: boolean;
  upload_ignore?: string[];
  e2b: SandboxHostedProvider;
  modal: SandboxHostedProvider;
  vercel: SandboxHostedProvider;
  docker: SandboxHostedProvider;
  // instabox is absent from a daemon that predates the row.
  instabox?: SandboxHostedProvider;
  // daytona is a hosted row's table; absent from a daemon that
  // predates it.
  daytona?: SandboxHostedProvider;
};

// EMPTY_PROVIDER stands in for a provider table the daemon did not send.
const EMPTY_PROVIDER: SandboxHostedProvider = { region: "", template: "", box_binary: "" };

// HOSTED_DRIVERS are the hosted rows: their component, their config table and
// the regions each vendor documents (sandbox plan section 7.1; the vendor table
// in internal/sandboxremote is the source).
export const HOSTED_DRIVERS = [
  {
    id: "e2b",
    table: "e2b" as const,
    name: "E2B",
    component: "terminals.sandbox.e2b",
    regions: ["us-west-1"],
    regionNote: "An E2B key belongs to one region's endpoint. Only us-west-1 (api.e2b.app) is offered: other E2B regions are added once E2B's own documentation names them.",
  },
  {
    id: "modal",
    table: "modal" as const,
    name: "Modal",
    component: "terminals.sandbox.modal",
    regions: ["us", "eu", "ap", "us-east", "us-central", "us-south", "us-west", "eu-west", "eu-north", "eu-south", "ap-northeast", "ap-southeast", "ap-south", "ap-melbourne", "jp", "au", "uk", "ca", "me", "sa", "af", "mx"],
    regionNote: "Unset means Modal chooses (an organization region floor then refuses the launch).",
  },
  {
    id: "vercel-sandbox",
    table: "vercel" as const,
    name: "Vercel Sandbox",
    component: "terminals.sandbox.vercel",
    regions: ["arn1", "bom1", "cdg1", "cle1", "cpt1", "dub1", "fra1", "gru1", "hkg1", "hnd1", "iad1", "icn1", "kix1", "lhr1", "pdx1", "sfo1", "sin1", "syd1", "yul1"],
    regionNote: "The default is iad1. A Hobby plan caps a box at 45 minutes.",
  },
  {
    id: "docker-sandboxes",
    table: "docker" as const,
    name: "Docker Sandboxes",
    component: "terminals.sandbox.docker",
    regions: [],
    regionNote: "Docker documents no regions for cloud sandboxes: Docker chooses (an organization region floor then refuses the launch). A box lasts at most 24 hours.",
  },
  {
    id: "instabox",
    table: "instabox" as const,
    name: "InstaBox",
    component: "terminals.sandbox.instabox",
    regions: [] as string[],
    regionNote: "InstaBox takes no region: it places the machine itself (an organization region floor then refuses the launch). Internet tier only, and the free plan pauses a machine after 30 idle minutes and after 480 minutes of running.",
  },
  {
    id: "daytona",
    table: "daytona" as const,
    name: "Daytona",
    component: "terminals.sandbox.daytona",
    regions: ["us", "eu"],
    regionNote: "Unset means your Daytona organization's default target (an organization region floor then refuses the launch). The template is a Daytona snapshot name.",
  },
];

// The model key's custody. "Stays on this machine" works only when this
// machine adds the key to the agent's requests (a key stored for credential
// injection, for an agent with one model provider, or the organization's AI
// gateway); the setup checklist and the New Terminal dialog say when it
// cannot (docs/audits/hosted-sandbox-key-custody-2026-11-18.md).
const CUSTODY = [
  // The default (decision SBXD-1): per launch and per agent.
  { value: "auto", label: "Stays on this machine when Observer can add it, otherwise in the box (disclosed)" },
  { value: "home_relay", label: "Stays on this machine (a stored key or your organization's gateway)" },
  { value: "in_box_api_key", label: "API key in the box (disclosed)" },
  { value: "in_box_oauth_seed", label: "Subscription login in the box (not built yet)" },
];
const MEMORY = [
  { value: "avoid", label: "Avoid (switched off at create, disclosed)" },
  { value: "refuse", label: "Refuse any provider that could take one" },
];
// DIFF_AGAINST are the choices of what a saved diff is taken against.
const DIFF_AGAINST = [
  { value: "baseline", label: "Everything the agent changed, its own commits too" },
  { value: "head", label: "Only what changed after the agent's last commit" },
];
const MINUTES = [5, 10, 15, 30, 45, 60, 90, 120, 240, 480, 1440];
const DAILY = [30, 60, 120, 240, 480, 960, 1440];
const CHECKPOINT = [1, 2, 5, 10, 15, 30, 60];

// PIN_PREFIX is how the organization's pins name these keys.
const PIN_PREFIX = "hosted.";

// hostedDriversSelected applies the daemon's opt-in rule (sandboxDriverSelected):
// a configured [components] block with a hosted driver active.
export function hostedDriversSelected(view: ComponentsView | undefined): string[] {
  if (!view || !view.configured) return [];
  return HOSTED_DRIVERS.filter((d) => view.components.some((c) => c.id === d.component && c.state === "active")).map((d) => d.id);
}

function minuteOptions(list: number[], current: number) {
  const all = list.includes(current) ? list : [...list, current].sort((a, b) => a - b);
  return all.map((n) => ({ value: String(n), label: <span>{n} min</span>, searchable: `${n} min` }));
}

function MinutesField({
  id,
  label,
  hint,
  list,
  value,
  disabled,
  pinned,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  list: number[];
  value: number;
  disabled: boolean;
  pinned: boolean;
  onChange: (n: number) => void;
}) {
  return (
    <div className="space-y-1">
      <span id={id} className="block font-medium text-fg-1">{label}</span>
      <ComboChip
        label={label}
        labelledBy={id}
        hideTriggerLabel
        fullWidth
        value={String(value)}
        disabled={disabled}
        onChange={(v) => onChange(Number(v))}
        options={minuteOptions(list, value)}
        buttonValueRender={() => <span>{value} min</span>}
      />
      <span className="block text-[11px] text-fg-3">{hint}</span>
      {pinned && <span className="block text-[11px] text-fg-3">Set by your organization (it can only lower this).</span>}
    </div>
  );
}

export function SandboxHostedPanel({
  value,
  view,
  pinned,
  writable,
  onChange,
}: {
  value: SandboxHostedConfig;
  view: ComponentsView | undefined;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxHostedConfig) => void;
}) {
  // A settings link to Hosted sandboxes (#hosted-sandboxes, the New
  // Terminal dialog's hosted tool notice) opens this panel, scrolls to it
  // and highlights it once it renders (lib/useScrollHighlight).
  const anchor = TERMINALS_HOSTED_SANDBOXES_HASH.slice(1);
  const loc = useLocation();
  const selected = hostedDriversSelected(view);
  // The panel draws nothing until a hosted driver is selected: the reveal
  // waits for it to exist.
  const highlighted = useScrollHighlight(anchor, selected.length > 0 && hashNames(loc.hash, anchor), loc.key);
  if (selected.length === 0) return null;
  const editable = (key: string) => writable && !pinned.has(PIN_PREFIX + key);
  const set = <K extends keyof SandboxHostedConfig>(key: K, v: SandboxHostedConfig[K]) => onChange({ ...value, [key]: v });
  return (
    <details
      id={anchor}
      className={`scroll-mt-6 rounded-2 border border-line-2 bg-bg-3 p-3 transition-shadow ${highlighted ? HIGHLIGHT_CLASS : ""}`}
    >
      <summary className="cursor-pointer font-medium text-fg-1">
        Hosted sandboxes <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          A hosted row runs the agent in a box on the provider&apos;s machines: your workspace files (git tracked and
          untracked-not-ignored files, or a plain folder&apos;s files as set below, never your home directory, never .git history, credential-shaped files excluded) are
          uploaded after you agree to it once per provider, and a Linux observer runs in the box so hooks still reach this
          machine. Built from each vendor&apos;s documentation; not yet proven with a real account (register REM-1 to REM-12).
          Used only when the row is in the backend list above and chosen for the launch.
        </p>
        <div className="grid gap-3 md:grid-cols-2">
          <MinutesField id="sandbox-hosted-maxrun" label="Box timeout" hint="Every box is created with this timeout (never none); the provider ends it there even if this machine is off." list={MINUTES} value={value.max_run_minutes} disabled={!editable("max_run_minutes")} pinned={pinned.has(PIN_PREFIX + "max_run_minutes")} onChange={(n) => set("max_run_minutes", n)} />
          <MinutesField id="sandbox-hosted-daily" label="Box-minutes per provider per day" hint="A launch over this refuses. The cost shown with it is an estimate from a dated list price." list={DAILY} value={value.daily_box_minutes} disabled={!editable("daily_box_minutes")} pinned={pinned.has(PIN_PREFIX + "daily_box_minutes")} onChange={(n) => set("daily_box_minutes", n)} />
          <MinutesField id="sandbox-hosted-minsession" label="Minimum session" hint="A provider whose plan caps a box below this is not offered." list={MINUTES.filter((n) => n >= 5)} value={value.min_session_minutes} disabled={!editable("min_session_minutes")} pinned={pinned.has(PIN_PREFIX + "min_session_minutes")} onChange={(n) => set("min_session_minutes", n)} />
          <MinutesField id="sandbox-hosted-checkpoint" label="Transcript checkpoint" hint="The agent's transcripts are pulled home this often, and always before the box is deleted." list={CHECKPOINT} value={value.checkpoint_minutes} disabled={!editable("checkpoint_minutes")} pinned={pinned.has(PIN_PREFIX + "checkpoint_minutes")} onChange={(n) => set("checkpoint_minutes", n)} />
          <div className="space-y-1">
            <span id="sandbox-hosted-custody" className="block font-medium text-fg-1">Model credential</span>
            <ComboChip
              label="Model credential"
              labelledBy="sandbox-hosted-custody"
              hideTriggerLabel
              fullWidth
              value={value.key_custody}
              disabled={!writable}
              onChange={(v) => set("key_custody", v)}
              options={CUSTODY.map((c) => ({ value: c.value, label: <span>{c.label}</span>, searchable: c.label }))}
              buttonValueRender={() => <span>{CUSTODY.find((c) => c.value === value.key_custody)?.label ?? value.key_custody}</span>}
            />
            <span className="block text-[11px] text-fg-3">A key in the box can be read by the agent; capture is then full only on the proxy-only network tier.</span>
          </div>
          {/* The per-agent key settings (key_custody_by_tool, tool_keys, login_seed; decisions SBXD-1, SBXD-4). */}
          <HostedKeySettings value={value} writable={writable} onChange={(next) => onChange({ ...value, ...next })} />
          <div className="space-y-1">
            <span id="sandbox-hosted-memory" className="block font-medium text-fg-1">Provider memory images</span>
            <ComboChip
              label="Provider memory images"
              labelledBy="sandbox-hosted-memory"
              hideTriggerLabel
              fullWidth
              value={value.memory_images}
              disabled={!editable("memory_images")}
              onChange={(v) => set("memory_images", v)}
              options={MEMORY.map((c) => ({ value: c.value, label: <span>{c.label}</span>, searchable: c.label }))}
              buttonValueRender={() => <span>{MEMORY.find((c) => c.value === value.memory_images)?.label ?? value.memory_images}</span>}
            />
            {pinned.has(PIN_PREFIX + "memory_images") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
          </div>
          <div className="space-y-1">
            <span id="sandbox-hosted-diff-against" className="block font-medium text-fg-1">Changes saved when the box ends</span>
            <ComboChip
              label="Changes saved when the box ends"
              labelledBy="sandbox-hosted-diff-against"
              hideTriggerLabel
              fullWidth
              value={value.diff_against ?? "baseline"}
              disabled={!editable("diff_against")}
              onChange={(v) => set("diff_against", v)}
              options={DIFF_AGAINST.map((c) => ({ value: c.value, label: <span>{c.label}</span>, searchable: c.label }))}
              buttonValueRender={() => <span>{DIFF_AGAINST.find((c) => c.value === (value.diff_against ?? "baseline"))?.label ?? value.diff_against}</span>}
            />
            <span className="block text-[11px] text-fg-3">
              The first keeps the agent&apos;s commits in the saved changes, so a run started from a clean, committed folder opens as a branch.
            </span>
            {pinned.has(PIN_PREFIX + "diff_against") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
          </div>
          <GuardHooksField value={value.guard_hooks} disabled={!editable("guard_hooks")} pinned={pinned.has(PIN_PREFIX + "guard_hooks")} onChange={(v) => set("guard_hooks", v)} />
          <HostedCloneWhereField settingKey="clone_where" value={value.clone_where ?? "auto"} disabled={!editable("clone_where")} pinned={pinned.has(PIN_PREFIX + "clone_where")} onChange={(v) => set("clone_where", v)} />
          <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-3 p-3 md:col-span-2">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={value.db_export ?? false}
              disabled={!editable("db_export")}
              onChange={(e) => set("db_export", e.target.checked)}
            />
            <span>
              <span className="font-medium text-fg-1">Copy the box&apos;s databases home at teardown</span>
              <span className="block text-[11px] text-fg-3">
                Off by default. When on, consistent copies of the agent&apos;s SQLite stores (conversation content, up to 1 GiB a
                run) are kept under sandbox-hosted/dbcopies on this machine, and removed after the workspace retention days.
                Nothing ingests them yet.
              </span>
              {pinned.has(PIN_PREFIX + "db_export") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
            </span>
          </label>
          <HostedUploadFields value={value} pinned={pinned} writable={writable} onChange={onChange} />
        </div>
        {/* allow_private_ranges (decision SBXD-7) */}
        <PrivateRangesField value={value} drivers={HOSTED_DRIVERS.filter((d) => selected.includes(d.id))} pinned={pinned} writable={writable} onChange={onChange} />
        {HOSTED_DRIVERS.filter((d) => selected.includes(d.id)).map((d) => {
          const p = value[d.table] ?? EMPTY_PROVIDER;
          const setP = (k: keyof SandboxHostedProvider, v: string) => set(d.table, { ...p, [k]: v });
          return (
            <div key={d.id} className="space-y-2 rounded-2 border border-line-2 p-3">
              <div className="font-medium text-fg-1">{d.name}</div>
              <div className="space-y-1">
                <span id={`sandbox-hosted-${d.id}-region`} className="block text-fg-2">Region</span>
                <ComboChip
                  label={`${d.name} region`}
                  labelledBy={`sandbox-hosted-${d.id}-region`}
                  hideTriggerLabel
                  fullWidth
                  value={p.region}
                  disabled={!writable}
                  onChange={(v) => setP("region", v)}
                  options={[{ value: "", label: <span>Provider default</span>, searchable: "default" }, ...d.regions.map((r) => ({ value: r, label: <span>{r}</span>, searchable: r }))]}
                  buttonValueRender={() => <span>{p.region || "Provider default"}</span>}
                />
                <span className="block text-[11px] text-fg-3">{d.regionNote}</span>
              </div>
              <div className="grid gap-2 md:grid-cols-2">
                <Input
                  label="Template"
                  mono
                  value={p.template}
                  placeholder="the vendor default (holds no agent CLI)"
                  disabled={!editable(`${d.table}.template`)}
                  error={hostedTemplateProblem(p.template) ?? undefined}
                  help="The vendor template, image or runtime that holds the agent tool. Empty: the tool installs from its vendor at first start, on the internet tier only."
                  onChange={(e) => setP("template", e.target.value)}
                />
                <Input
                  label="In-box observer"
                  mono
                  value={p.box_binary}
                  placeholder="this running Linux binary"
                  disabled={!editable(`${d.table}.box_binary`)}
                  error={absPathProblem(p.box_binary) ?? undefined}
                  help="An absolute path to a Linux observer binary of this version for the box. Empty: the running binary, when it is a Linux binary of the box's architecture."
                  onChange={(e) => setP("box_binary", e.target.value)}
                />
              </div>
              {(pinned.has(`${PIN_PREFIX}${d.table}.template`) || pinned.has(`${PIN_PREFIX}${d.table}.box_binary`)) && (
                <span className="block text-[11px] text-fg-3">Set by your organization.</span>
              )}
            </div>
          );
        })}
        <SandboxHostedStatus selected={selected} />
      </div>
    </details>
  );
}
