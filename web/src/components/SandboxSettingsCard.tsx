// SandboxSettingsCard.tsx is the Terminals > Settings "Sandbox isolation"
// card (sandbox plan v2 section 9), the dashboard editor for the complete
// [terminal.sandbox] block. It belongs to the Sandboxes and VMs module
// (component terminals.sandbox): the Terminals page renders it through the
// compgen registry (SANDBOX_SETTINGS_CARD), so a build without the module
// ships none of it and the page renders no sandbox element.

import { Suspense, useEffect, useRef, useState, type ReactNode } from "react";
import {
  ChartShell,
  ConfirmButton,
  ErrorState,
  InlineLoading,
  Pill,
  ComboChip,
  SuccessCheck,
  type ComboOption,
} from "@/components/primitives";
import { Summary } from "@/components/Summary";
import { SandboxOCIPanel, type SandboxOCIConfig } from "@/components/SandboxOCIPanel";
import { SandboxWindowsPanel, type SandboxMXCConfig } from "@/components/SandboxWindowsPanel";
import { SandboxMacPanel, type SandboxAppleContainerConfig, type SandboxSeatbeltConfig } from "@/components/SandboxMacPanel";
import { SandboxNativePanel } from "@/components/SandboxNativePanel";
import { SandboxLandlockPanel, type SandboxLandlockConfig } from "@/components/SandboxLandlockPanel";
import { SandboxOpenShellPanel, type SandboxOpenShellConfig } from "@/components/SandboxOpenShellPanel";
import { SandboxVMPanel, type SandboxVMConfig } from "@/components/SandboxVMPanel";
import { SandboxHostedPanel, type SandboxHostedConfig } from "@/components/SandboxHostedPanel";
import { SandboxOrgShellCard } from "@/components/SandboxOrgShellCard";
import { SandboxStraceSeizeCard } from "@/components/SandboxStraceSeizeToggle";
import { SandboxCredentialsPanel, type SandboxReadoptConfig } from "@/components/SandboxCredentialsPanel";
import {
  SandboxWindowsTiersPanel,
  type SandboxHCSConfig,
  type SandboxWSLCConfig,
  type SandboxWindowsConfig,
} from "@/components/SandboxWindowsTiersPanel";
import { SANDBOX_SETUP_PANEL } from "@/lib/components.gen";
import { useLaunchDock } from "@/components/LaunchDock";
import type { SandboxSetupSummary, SandboxSetupSummaryResponse } from "@/lib/sandboxSetupTypes";
import { summaryOptionLabel, summarySetUp } from "@/lib/sandboxSetup";
import { mxcTierLoosens } from "@/lib/sandboxParity";
import { useApi } from "@/lib/useApi";
import { useComponentState } from "@/lib/useComponents";
import type { ComponentsView } from "@/lib/componentState";
import { ApiError, fetchJSON } from "@/lib/api";
import { markRestartPending } from "@/lib/restartPending";
import {
  applyLoaded,
  canStartSave,
  editDraft,
  emptySave,
  isDirty,
  runSave,
  type ConfigSaveState,
  type ConfigSaved,
} from "@/lib/configSave";
import { Link } from "react-router-dom";
import { COMPONENTS_SETTINGS_PATH, backendNotes, backendState, classLabel, gatewayModeLabel } from "@/lib/sandboxIsolation";
import { TERMINALS_SANDBOX_BACKENDS_HASH } from "@/lib/nodePageTabs";
import type { SandboxAvailability, SandboxBackendAvail, SandboxOrgSettings } from "@/lib/types";

// Sandbox home / network modes: the mode name on the first line (what the
// config stores), the long explanation as the row's second line instead of
// one native <option> that overflowed narrow screens.
const SANDBOX_HOME_OPTIONS: ComboOption[] = [
  {
    value: "tmpfs",
    label: <span><span className="font-mono">tmpfs</span> <span className="text-fg-3">(recommended)</span></span>,
    detail: "Hide the real home.",
    searchable: "tmpfs hide the real home recommended",
  },
  {
    value: "readonly",
    label: <span className="font-mono">readonly</span>,
    detail: "Expose the real home read-only.",
    searchable: "readonly expose the real home read-only",
  },
];

const SANDBOX_EGRESS_OPTIONS: ComboOption[] = [
  {
    value: "internet",
    label: <span><span className="font-mono">internet</span> <span className="text-fg-3">(recommended)</span></span>,
    detail: "Own network; model API via the proxy, internet via the egress gateway.",
    searchable: "internet own network model api proxy egress gateway recommended",
  },
  {
    value: "proxy_only",
    label: <span>proxy only</span>,
    detail: "Own network; only the model API proxy.",
    searchable: "proxy_only own network only the model api proxy",
  },
  {
    value: "none",
    label: <span className="font-mono">none</span>,
    detail: "Own network; nothing reachable.",
    searchable: "none own network nothing reachable",
  },
  {
    value: "host",
    label: <span className="font-mono">host</span>,
    detail: "Share the host network (the dashboard stays reachable from inside).",
    searchable: "host share the host network dashboard reachable",
  },
];


export type TerminalSandboxConfig = {
  enabled: boolean;
  backend: string;
  home_mode: "tmpfs" | "readonly";
  default_on: boolean;
  allow_remote_clone: boolean;
  remote_allowed_hosts: string[];
  allow_worktree_source: boolean;
  workspaces_dir: string;
  workspace_retention_days: number;
  mask_paths: string[];
  extra_ro_binds: string[];
  extra_rw_binds: string[];
  prep_timeout_seconds: number;
  // How soon an update waiting for live sandboxed runs asks (lane SBX-UPD).
  // Optional so an older daemon (which omits it) still round-trips.
  live_run_update_policy?: SandboxLiveRunPolicy;
  // SR27-SBX-1 network tier + executed-state protection. Optional so an
  // older daemon (which omits them) still round-trips; the server keeps a
  // saved value when a save omits the field.
  egress?: SandboxEgress;
  allow_tool_config_writes?: boolean;
  // Private-destination allow-list for the internet tier's egress gateway
  // (SR27-SBX-2). Optional for the same round-trip reason.
  egress_allow_cidrs?: string[];
  // egress_allow_hosts: the agent-run host allow-list (lane LEFT-SBX).
  egress_allow_hosts?: string[];
  // pass_env: the extra variables a sandboxed agent may receive (WINFIX2,
  // ledger SBX-WIN-ENV-1). Optional for the same round-trip reason.
  pass_env?: string[];
  // sign_in_seed_tools: the tools whose sign-in a sandboxed run copies into
  // its box without asking (lane BOXSIGNIN, local-only). The catalog (tools
  // with a grounded sign-in file) and the org's forbid are read-only.
  sign_in_seed_tools?: string[];
  sign_in_seed_catalog?: string[];
  sign_in_seed_forbidden?: boolean;
  // allow_osc52_clipboard: a sandboxed tool's OSC 52 clipboard sequences
  // reach the terminal (ruling P-175; off by default). Optional for the same
  // round-trip reason.
  allow_osc52_clipboard?: boolean;
  // Backend preference order and the local isolation floor (sandbox plan v2
  // section 10). Optional for the same round-trip reason.
  backends?: string[];
  min_isolation?: string;
  // [terminal.sandbox.oci], the container driver (lane SBX-P3A).
  oci?: SandboxOCIConfig;
  // [terminal.sandbox.mxc], the Windows driver (lane SBX-P6).
  mxc?: SandboxMXCConfig;
  // The macOS drivers' blocks (lane SBX-P5, beta).
  seatbelt?: SandboxSeatbeltConfig;
  apple_container?: SandboxAppleContainerConfig;
  // [terminal.sandbox.landlock], the Landlock-only row (lane SBX-P3B, beta).
  landlock?: SandboxLandlockConfig;
  // [terminal.sandbox.hosted], the hosted rows (lane SBX-P7).
  hosted?: SandboxHostedConfig;
  // [terminal.sandbox.vm], the Cloud Hypervisor microVM row (lane SBX-P4, beta).
  vm?: SandboxVMConfig;
  // [terminal.sandbox.readopt], [terminal.sandbox.wslc], [terminal.sandbox.hcs]
  // and [terminal.sandbox.windows] (dashboard CLI parity lane L3: the daemon
  // serves and saves them since; optional for the same round-trip reason).
  readopt?: SandboxReadoptConfig;
  wslc?: SandboxWSLCConfig;
  hcs?: SandboxHCSConfig;
  windows?: SandboxWindowsConfig;
  // seccomp: Observer's own syscall filter for bwrap and process_lite (lane
  // N2; the toggle is lane O4's). Optional for the same round-trip reason.
  seccomp?: boolean;
  // [terminal.sandbox.openshell], the OpenShell row (lanes O1A and O2; the
  // panel is lane O4's). Optional for the same round-trip reason.
  openshell?: SandboxOpenShellConfig;
  // [terminal.sandbox.setup], the sandbox installation lifecycle
  // (allow_elevated, default off, decision P-250; the toggle is P-254's).
  // Optional for the same round-trip reason: an older daemon omits it and
  // the server keeps the saved block when a save omits it.
  setup?: SandboxSetupConfig;
};

// SandboxSetupConfig is [terminal.sandbox.setup]. Local-only: an
// organization can never turn it on.
export type SandboxSetupConfig = { allow_elevated: boolean };

// SandboxSetupElevatedToggle edits [terminal.sandbox.setup].allow_elevated
// (decision P-250, default off; the Settings control P-254 asked for).
export function SandboxSetupElevatedToggle({
  value,
  disabled,
  onChange,
}: {
  value: SandboxSetupConfig | undefined;
  disabled: boolean;
  onChange: (next: SandboxSetupConfig) => void;
}) {
  return (
    <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3" data-testid="sandbox-setup-allow-elevated">
      <input
        type="checkbox"
        className="mt-0.5"
        aria-label="Let a setup step ask for your password"
        checked={value?.allow_elevated ?? false}
        disabled={disabled}
        onChange={(e) => onChange({ ...(value ?? { allow_elevated: false }), allow_elevated: e.target.checked })}
      />
      <span>
        <span className="font-medium text-fg-1">Let a setup step ask for your password</span>
        <span className="block text-[11px] text-fg-3">
          Off: a step that needs administrator rights shows its command for you to run yourself. On: it opens in a setup terminal where you type your password. Your organization can never turn this on.
        </span>
      </span>
    </label>
  );
}

type SandboxEgress = "internet" | "proxy_only" | "none" | "host";

type SandboxLiveRunPolicy = "defer" | "ask_immediately";

// SANDBOX_LIVE_RUN_POLICY_OPTIONS is the closed live_run_update_policy
// vocabulary (sandbox plan v2 section 5.5): neither value ends a run.
const SANDBOX_LIVE_RUN_POLICY_OPTIONS: ComboOption[] = [
  { value: "defer", label: <span>Ask in the banner</span>, detail: "An update waiting for live sandboxed runs shows the question in the banner; it applies when they finish or when you end them.", searchable: "defer banner" },
  { value: "ask_immediately", label: <span>Ask at once</span>, detail: "An update waiting for live sandboxed runs opens the question as soon as it is deferred.", searchable: "ask immediately dialog" },
];

// SANDBOX_FLOOR_OPTIONS is the closed [terminal.sandbox].min_isolation
// vocabulary, weakest first (config.SandboxIsolationClasses).
const SANDBOX_FLOOR_OPTIONS: ComboOption[] = [
  { value: "", label: <span className="text-fg-3">no floor</span>, detail: "Any offered backend may run a sandboxed terminal.", searchable: "no floor none" },
  { value: "process", label: <span className="font-mono">process</span>, detail: "A process sandbox or stronger (bwrap builds this).", searchable: "process sandbox" },
  { value: "container", label: <span className="font-mono">container</span>, detail: "A container or stronger; bwrap launches are refused.", searchable: "container" },
  { value: "userspace_kernel", label: <span>user-space kernel</span>, detail: "A user-space kernel (gVisor) or a VM.", searchable: "userspace kernel gvisor" },
  { value: "hw_vm", label: <span>virtual machine</span>, detail: "A virtual machine only.", searchable: "hw_vm virtual machine" },
];

// SANDBOX_RETENTION_DAYS and SANDBOX_PREP_TIMEOUTS are the pickers for the
// two numeric keys (pickers, never free text, D-571). The saved value is
// always offered too, so a hand-edited config.toml value round-trips.
const SANDBOX_RETENTION_DAYS = [0, 7, 14, 30, 60, 90, 180, 365];
const SANDBOX_PREP_TIMEOUTS = [30, 60, 120, 300, 600, 1200, 1800, 3600];

function numberOptions(values: number[], current: number, render: (n: number) => string): ComboOption[] {
  const all = values.includes(current) ? values : [...values, current].sort((a, b) => a - b);
  return all.map((n) => ({ value: String(n), label: <span>{render(n)}</span>, searchable: render(n) }));
}

function retentionLabel(n: number): string {
  return n === 0 ? "keep forever" : `${n} days`;
}

function timeoutLabel(n: number): string {
  return n >= 60 && n % 60 === 0 ? `${n / 60} min` : `${n} s`;
}

// SandboxOrgPanel shows what the organization sets for this node's sandbox
// (sandbox plan v2 section 9, lane SBX-P1B): the isolation floors in force
// and the applied pins, read-only. The matching controls below are disabled.
function SandboxOrgPanel({ org }: { org: SandboxOrgSettings }) {
  const rows = [
    ...(org.floors ?? []).map((v) => ({ ...v, kind: "floor" })),
    ...(org.pins ?? []).map((v) => ({ ...v, kind: "pin" })),
    ...(org.managed ?? []).map((v) => ({ ...v, kind: "managed" })),
  ];
  const refused = org.managed_refused ?? [];
  if (rows.length === 0 && refused.length === 0) return null;
  return (
    <div className="space-y-1 rounded-2 border border-line-2 bg-bg-2 px-3 py-2">
      <span className="block font-medium text-fg-1">Set by your organization</span>
      <ul className="space-y-0.5">
        {rows.map((r) => (
          <li key={`${r.kind}:${r.key}`} className="flex flex-wrap gap-2">
            <span className="text-fg-2">{r.label || r.key}</span>
            <span className="font-mono text-fg-1">{r.value}</span>
            <span className="text-fg-3">{ORG_KIND_LABEL[r.kind] ?? r.kind}</span>
          </li>
        ))}
      </ul>
      {refused.length > 0 && (
        <div>
          <span className="block font-medium text-fg-1">Not applied on this machine</span>
          <ul className="space-y-0.5">
            {refused.map((r) => (
              <li key={`refused:${r.key}`} className="flex flex-wrap gap-2">
                <span className="text-fg-2">{r.label || r.key}</span>
                <span className="font-mono text-fg-3">{r.value}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <span className="block text-[11px] text-fg-3">
        A floor or pin only ever makes this machine stricter; it is applied on every launch and cannot be changed here.
        {(org.managed ?? []).length > 0 &&
          " A managed value is what launches use while your organization's managed policy is in force; your own value below is kept and applies again when the policy is withdrawn."}
      </span>
    </div>
  );
}

// ORG_KIND_LABEL names where an organization value comes from.
const ORG_KIND_LABEL: Record<string, string> = {
  floor: "floor",
  pin: "pinned",
  managed: "managed (effective value)",
};

// OrgSetNote marks one control the organization pinned; note says how the
// pin composes with the developer's own value when it does.
function OrgSetNote({ show, note }: { show: boolean; note?: string }) {
  if (!show) return null;
  return <span className="block text-[11px] text-fg-3">{note ?? "Set by your organization."}</span>;
}

// PIN_COMPOSES lists the keys whose own value still counts under an
// organization pin (the pin composes with it instead of replacing it), so
// the control stays editable, with the note saying how they combine. Every
// other pinned key is read-only.
const PIN_COMPOSES: Record<string, string> = {
  mask_paths: "Your organization adds its paths to yours; you can add more.",
  remote_allowed_hosts:
    "Your organization's hosts are intersected with yours: only hosts on both lists are used, and if none are, remote clone is off.",
  backends:
    "Your organization limits the backends: your order applies within its list, and if none of yours remain no sandbox can run.",
};

// SandboxBackendsList is the Card's backend list (sandbox plan v2 section 9):
// every registry row from the probe with its status on this host (or the
// selection rule that dropped it), a beta badge, the capture on the
// configured network, an Enabled checkbox that adds the row to or removes
// it from the backends key, and up/down buttons for the enabled rows'
// preference order. Planned rows are listed, never offered. A row the
// daemon left out only for not being enabled says whether it would run here
// once it is (when_enabled_*), so a checkbox is never offered as a fix for a
// backend this host cannot run; one whose module is not installed links to
// Settings > Components. When the setup routes answer (onSetup given), each
// row also gets "Set up" (not ready) or "Manage" (ready), which opens the
// sandbox setup panel under that row (sandbox installation lifecycle plan
// section 3.7); the Enabled checkboxes stay as they are.
export function SandboxBackendsList({
  backends,
  order,
  egress,
  writable,
  orgNote,
  onOrder,
  onSetup,
  setupRows,
  setupOpen,
  setupPanel,
}: {
  backends: SandboxBackendAvail[];
  /** The enabled backends in preference order (the draft's backends key). */
  order: string[];
  egress: string;
  writable: boolean;
  orgNote?: string;
  onOrder: (next: string[]) => void;
  /** Opens (or closes) the setup panel for a row; absent, no Set up or
   *  Manage button shows. */
  onSetup?: (id: string) => void;
  /** The setup summaries by backend id. Only a row they list (one that
   *  runs on this host) gets "Set up" or "Manage"; a row whose setup is
   *  beta reads "(beta)" on that button. */
  setupRows?: Record<string, SandboxSetupSummary>;
  /** The row whose setup panel is open. */
  setupOpen?: string | null;
  /** The open row's setup panel, rendered under it. */
  setupPanel?: ReactNode;
}) {
  const offered = backends.filter((b) => b.maturity !== "planned");
  const planned = backends.filter((b) => b.maturity === "planned");
  const enabledIds = order.filter((id) => offered.some((b) => b.id === id));
  // Enabled rows first in preference order, then the rest in registry order.
  const ranked = [
    ...enabledIds.map((id) => offered.find((b) => b.id === id) as SandboxBackendAvail),
    ...offered.filter((b) => !enabledIds.includes(b.id)),
  ];
  const move = (id: string, dir: -1 | 1) => {
    const i = enabledIds.indexOf(id);
    const j = i + dir;
    if (i < 0 || j < 0 || j >= enabledIds.length) return;
    const a = enabledIds[i];
    const b = enabledIds[j];
    // Swap the two in place, so ids the probe does not list keep their spot.
    onOrder(order.map((x) => (x === a ? b : x === b ? a : x)));
  };
  const toggle = (id: string, on: boolean) => {
    onOrder(on ? (order.includes(id) ? order : [...order, id]) : order.filter((x) => x !== id));
  };
  // The page scrolls to #sandbox-backends before this lazily loaded card
  // exists, so the list scrolls itself into view once it renders.
  useEffect(() => {
    if (typeof window === "undefined" || window.location.hash !== TERMINALS_SANDBOX_BACKENDS_HASH) return;
    document.getElementById(TERMINALS_SANDBOX_BACKENDS_HASH.slice(1))?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, []);
  return (
    <div id={TERMINALS_SANDBOX_BACKENDS_HASH.slice(1)} className="scroll-mt-6 space-y-1">
      <span className="block font-medium text-fg-1">Backends</span>
      <span className="block text-[11px] text-fg-3">
        Tick a backend to offer it in the New Terminal Isolation picker. Automatic uses the first enabled backend that runs
        here, in this order.
      </span>
      <ul className="space-y-1">
        {ranked.map((b) => {
          const checked = enabledIds.includes(b.id);
          const last = checked && enabledIds.length === 1;
          const st = backendState(b);
          const i = enabledIds.indexOf(b.id);
          let status: string;
          let tone = "text-fg-3";
          if (st.state === "available") {
            status = checked ? "available" : "available; runs here once saved";
            tone = "text-ok";
          } else if (st.state === "not_enabled") {
            status = checked ? "runs here once saved" : "not enabled; runs here once enabled";
            tone = checked ? "text-ok" : "text-fg-2";
          } else {
            status = st.reason;
          }
          return (
            <li key={b.id} className="flex flex-wrap items-center gap-2 rounded-2 border border-line-2 px-2 py-1">
              <label className="flex items-center gap-2" title={last ? "At least one backend stays enabled. To turn sandboxing off, clear Enable sandbox support." : undefined}>
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={!writable || last}
                  onChange={(e) => toggle(b.id, e.target.checked)}
                  aria-label={`Enable ${b.label}`}
                />
                <span className="font-mono text-fg-1">{b.id}</span>
              </label>
              <span className="text-fg-3">{b.label} - {classLabel(b.class)}</span>
              {b.beta && <Pill variant="warn">beta</Pill>}
              <span className={tone}>{status}</span>
              {st.state === "needs_module" && (
                <Link to={COMPONENTS_SETTINGS_PATH} className="text-accent hover:underline">
                  Install its module
                </Link>
              )}
              {b.capture_by_tier?.[egress] && <span className="text-fg-3">capture {b.capture_by_tier[egress]}</span>}
              {b.gateway_mode && <span className="text-fg-3">gateway: {gatewayModeLabel(b.gateway_mode)}</span>}
              {backendNotes(b).map((n) => (
                <span key={n} className="basis-full text-fg-3">
                  note: {n}
                </span>
              ))}
              {onSetup && setupRows?.[b.id] && (
                <SetupButton
                  label={b.label}
                  manage={summarySetUp(setupRows[b.id])}
                  beta={!!setupRows[b.id].beta}
                  open={setupOpen === b.id}
                  onClick={() => onSetup(b.id)}
                />
              )}
              {checked && enabledIds.length > 1 && (
                <span className="ml-auto flex gap-1">
                  <button type="button" disabled={!writable || i === 0} onClick={() => move(b.id, -1)} aria-label={`Prefer ${b.id}`}>
                    up
                  </button>
                  <button type="button" disabled={!writable || i === enabledIds.length - 1} onClick={() => move(b.id, 1)} aria-label={`Prefer ${b.id} less`}>
                    down
                  </button>
                </span>
              )}
              {onSetup && setupOpen === b.id && setupPanel && <div className="basis-full">{setupPanel}</div>}
            </li>
          );
        })}
      </ul>
      {planned.length > 0 && (
        <span className="block text-[11px] text-fg-3">
          Not offered yet: {planned.map((b) => `${b.label}${b.phase ? ` (${b.phase})` : ""}`).join(", ")}.
        </span>
      )}
      <OrgSetNote show={!!orgNote} note={orgNote} />
    </div>
  );
}

// SetupButton is a backend row's "Set up" (not set up) or "Manage" (set up)
// button, opening the setup panel under the row. A row whose setup is beta
// reads "(beta)" after the verb (operator ruling P-256).
function SetupButton({
  label,
  manage,
  beta,
  open,
  onClick,
}: {
  label: string;
  manage: boolean;
  beta?: boolean;
  open: boolean;
  onClick: () => void;
}) {
  const verb = manage ? "Manage" : "Set up";
  return (
    <button type="button" onClick={onClick} aria-expanded={open} aria-label={`${verb} ${label}`} className="text-accent hover:underline">
      {verb + (beta ? " (beta)" : "")}
    </button>
  );
}

// SandboxSetupRowsList is the backend list drawn from the setup summaries
// alone, for a node whose sandbox probe lists no backend (the master switch
// is off, so the probe answers disabled_by_config): each row that runs on
// this host still gets "Set up" or "Manage", which is exactly how a fresh
// node turns a backend on.
export function SandboxSetupRowsList({
  rows,
  onSetup,
  setupOpen,
  setupPanel,
}: {
  rows: SandboxSetupSummary[];
  onSetup: (id: string) => void;
  setupOpen?: string | null;
  setupPanel?: ReactNode;
}) {
  return (
    <div id={TERMINALS_SANDBOX_BACKENDS_HASH.slice(1)} className="scroll-mt-6 space-y-1" data-testid="sandbox-setup-rows">
      <span className="block font-medium text-fg-1">Backends</span>
      <span className="block text-[11px] text-fg-3">
        The sandbox is off, so no backend runs yet. Set one up here; its last step turns the sandbox on.
      </span>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.backend} className="flex flex-wrap items-center gap-2 rounded-2 border border-line-2 px-2 py-1">
            <span className="font-mono text-fg-1">{r.backend}</span>
            <span className="text-fg-3">{summaryOptionLabel(r)}</span>
            <SetupButton
              label={r.label || r.backend}
              manage={summarySetUp(r)}
              beta={!!r.beta}
              open={setupOpen === r.backend}
              onClick={() => onSetup(r.backend)}
            />
            {setupOpen === r.backend && setupPanel && <div className="basis-full">{setupPanel}</div>}
          </li>
        ))}
      </ul>
    </div>
  );
}

type TerminalSandboxConfigResponse = {
  // The etag of the config.toml this card was read from; the save sends it
  // back as base_etag (T-639).
  config_etag?: string;
  confirm_token: ConfirmToken;
  config_writable: boolean;
  restart_required_on_save: boolean;
  sandbox: TerminalSandboxConfig;
};

type ConfirmToken = string;

function splitConfigList(value: string): string[] {
  // Preserve a trailing empty row while the operator types; the server trims
  // and de-duplicates on save. Filtering here would eat each newly-entered
  // newline and make multi-line editing impossible in a controlled textarea.
  return value.replace(/\r/g, "").split("\n");
}

// sandboxConfigEqual compares a draft against the last-loaded server config.
// The block is a flat record of scalars plus four string lists, so a
// field-order-independent JSON compare over a normalized shape is enough -
// and it is what lets the card show an "Unsaved changes" marker.
//
// Why that marker is load-bearing here rather than a nicety: this card has
// TWO checkbox-shaped things on it, and only one of them saves. Toggling
// "Enable sandbox support" edits a local draft and nothing else; the write
// happens on the separate "Save sandbox configuration" button further down,
// past a collapsed <details> block. An operator who flipped the switch and
// walked away had, from the UI's point of view, done nothing at all - which
// is exactly how "I enabled the sandbox and it is still greyed out" happens.
export function sandboxConfigEqual(
  a: TerminalSandboxConfig | null,
  b: TerminalSandboxConfig | null | undefined,
): boolean {
  if (!a || !b) return a === b;
  const norm = (c: TerminalSandboxConfig) => ({
    ...c,
    // The list editors keep a trailing empty row while the operator types
    // (splitConfigList); the server trims on save. Ignore that difference so
    // an untouched textarea never reads as "unsaved".
    remote_allowed_hosts: c.remote_allowed_hosts.filter((s) => s.trim() !== ""),
    mask_paths: c.mask_paths.filter((s) => s.trim() !== ""),
    extra_ro_binds: c.extra_ro_binds.filter((s) => s.trim() !== ""),
    extra_rw_binds: c.extra_rw_binds.filter((s) => s.trim() !== ""),
    egress_allow_cidrs: (c.egress_allow_cidrs ?? []).filter((s) => s.trim() !== ""),
    egress_allow_hosts: (c.egress_allow_hosts ?? []).filter((s) => s.trim() !== ""),
    pass_env: (c.pass_env ?? []).filter((s) => s.trim() !== ""),
    sign_in_seed_tools: c.sign_in_seed_tools ?? [],
    allow_osc52_clipboard: c.allow_osc52_clipboard ?? false,
    backends: c.backends ?? [],
    min_isolation: c.min_isolation ?? "",
    seccomp: c.seccomp ?? false,
    setup: { allow_elevated: c.setup?.allow_elevated ?? false },
  });
  return JSON.stringify(norm(a)) === JSON.stringify(norm(b));
}

/** SandboxConfigPutReply is what the sandbox config PUT answers with. */
export type SandboxConfigPutReply = {
  restart_required?: boolean;
  sandbox?: TerminalSandboxConfig;
  config_etag?: string;
};

/**
 * putSandboxConfig sends one save of the [terminal.sandbox] draft and
 * returns the server's reply in the save model's shape (the saved block and
 * the new etag), which the card adopts as its baseline.
 */
export async function putSandboxConfig(
  draft: TerminalSandboxConfig,
  baseEtag: string,
  confirmToken: string,
  fetcher: typeof fetchJSON = fetchJSON,
): Promise<ConfigSaved<TerminalSandboxConfig> & { restart_required?: boolean }> {
  const res = await fetcher<SandboxConfigPutReply>(
    "/api/terminal/sandbox/config",
    { base_etag: baseEtag },
    {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Observer-Confirm": confirmToken,
      },
      body: JSON.stringify(draft),
    },
  );
  return { block: res.sandbox, etag: res.config_etag, restart_required: res.restart_required };
}

// LOCAL_ONLY_HINT recognizes the CapabilityLocal refusal
// (internal/intelligence/dashboard/remote.go: "forbidden: route is reachable
// only from the local dashboard", audited as local_route_refused). The
// sandbox config route is owner-loopback-only, so a dashboard served over the
// tailnet 403s on the GET - and the card, which keyed its whole body off
// `draft`, used to sit on "Loading sandbox configuration…" forever with every
// control disabled and nothing saying why.
const LOCAL_ONLY_HINT = /local dashboard|local_route_refused/i;

function isLocalRouteRefusal(err: Error | null): boolean {
  if (!err) return false;
  return LOCAL_ONLY_HINT.test(err.message) || / 403 /.test(err.message);
}

// localDashboardURL is the loopback address of THIS daemon's dashboard. The
// remote view is the same daemon on the same port, reached over the tailnet,
// so the port in the current location is the right one to hand back.
function localDashboardURL(): string {
  const port =
    typeof window !== "undefined" && window.location.port
      ? window.location.port
      : "8081";
  return `http://127.0.0.1:${port}`;
}

// SandboxSettingsCard is the missing dashboard editor for the complete
// [terminal.sandbox] block. The live probe is intentionally shown alongside
// the saved config, so the UI never implies that a newly-enabled sandbox is
// already protecting launches: the master switch binds on the next launch
// (the daemon re-resolves the seam when config.toml changes), while moving
// the workspaces directory still needs a restart.
/**
 * SANDBOX_MASTER_SWITCH_HELP is the enable switch's help line. A save of the
 * switch applies live (D-R4-1): it binds on the next launch, no restart.
 */
export const SANDBOX_MASTER_SWITCH_HELP =
  "Master switch. A saved change binds on the next launch, with no daemon restart.";

export function SandboxSettingsCard() {
  const settings = useApi<TerminalSandboxConfigResponse>(
    "/api/terminal/sandbox/config",
  );
  const probe = useApi<SandboxAvailability>("/api/terminal/sandbox");
  // The container driver's panel shows only where a [components] block
  // selects terminals.sandbox.oci (the driver is opt-in and inactive in
  // every distro; SBX-P3A merge finding F7). Until the state is known the
  // panel stays hidden.
  const componentState = useComponentState();
  const ociSelected = ociDriverSelected(componentState.data?.view);
  // The sandbox setup rows (lane sbxinstall-ui): a 404 or 501 (no setup in
  // this build or module) leaves data null, so no Set up or Manage button
  // shows. A setup step's terminal opens in the dock.
  const setupRows = useApi<SandboxSetupSummaryResponse>("/api/terminal/sandbox/setup");
  const [setupFor, setSetupFor] = useState<string | null>(null);
  const dock = useLaunchDock();
  const setupByID: Record<string, SandboxSetupSummary> = Object.fromEntries((setupRows.data?.backends ?? []).map((r) => [r.backend, r]));
  const toggleSetup = (id: string) => setSetupFor((cur) => (cur === id ? null : id));
  // The draft and the saved baseline it is compared to (lib/configSave.ts):
  // a save adopts the PUT's own reply as the baseline, so "Unsaved changes"
  // clears on the save itself, and a stale read after it is ignored (D-5).
  const [save, setSave] = useState<ConfigSaveState<TerminalSandboxConfig>>(emptySave);
  // The state a click on Save reads (never a render's stale closure).
  const saveRef = useRef(save);
  saveRef.current = save;
  const busyRef = useRef(false);
  const draft = save.draft;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const data = settings.data;
    if (data?.sandbox) {
      setSave((cur) => applyLoaded(cur, { block: data.sandbox, etag: data.config_etag ?? "" }, sandboxConfigEqual));
    }
  }, [settings.data]);

  // The dock (above) also shows a terminal a sub-panel opens (the
  // re-adoption re-attach).
  const localOnly = isLocalRouteRefusal(settings.error);
  const dirty = isDirty(save, sandboxConfigEqual);
  // A move of the MXC tier floor off ProcessContainer loosens isolation
  // (dashboard CLI parity B-G6): the Save asks first, the way it does for
  // the authority-expanding keys. An organization pin overrides it anyway.
  // The saved tier is the save model's baseline, the block "Unsaved
  // changes" compares against.
  const loosensMXCTier =
    !!draft &&
    !(probe.data?.org?.pins ?? []).some((p) => p.key === "windows.mxc_tier") &&
    mxcTierLoosens(save.base?.windows?.mxc_tier, draft.windows?.mxc_tier);
  const expandsAuthority =
    !!draft &&
    (draft.allow_remote_clone ||
      draft.extra_rw_binds.some((p) => p.trim() !== "") ||
      (draft.egress_allow_cidrs ?? []).some((p) => p.trim() !== "") ||
      loosensMXCTier);

  function update<K extends keyof TerminalSandboxConfig>(
    key: K,
    value: TerminalSandboxConfig[K],
  ) {
    setSaved(false);
    setSave((cur) => editDraft(cur, (d) => ({ ...d, [key]: value })));
  }

  async function saveSandbox() {
    const token = settings.data?.confirm_token;
    const start = canStartSave(saveRef.current, busyRef.current, token);
    if (!start.ok) {
      setErr(start.why);
      return;
    }
    // An authority-expanding config is confirmed in place by the Save
    // ConfirmButton (requireConfirm={expandsAuthority}), never window.confirm.
    busyRef.current = true;
    setBusy(true);
    setErr(null);
    setSaved(false);
    try {
      const { state, reply } = await runSave(saveRef.current, (body, baseEtag) => putSandboxConfig(body, baseEtag, token ?? ""));
      setSave(state);
      if (reply.restart_required) markRestartPending("terminal-sandbox");
      setSaved(true);
      settings.reload();
      // Re-probe: the daemon re-resolves its sandbox seam when config.toml
      // changes, so the live verdict moves on THIS save, not on a restart.
      // Without this the card would keep showing the pre-save verdict until
      // the page was reloaded, which is how "I enabled it and nothing
      // happened" reads from the operator's side.
      probe.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  const writable = !!settings.data?.config_writable;
  const live = probe.data;
  // The open row's setup panel (one node, under whichever list draws the
  // rows).
  const setupPanelNode = setupFor && SANDBOX_SETUP_PANEL && (
    <Suspense fallback={null}>
      <SANDBOX_SETUP_PANEL
        backend={setupFor}
        onTerminal={(handle, label) => dock.launch({ token: handle, tool: label, sessionId: "", hasProjectRoot: false })}
        onReady={() => {
          probe.reload();
          setupRows.reload();
        }}
      />
    </Suspense>
  );
  // Keys the organization pinned are shown read-only (lane SBX-P1B), except
  // the ones the pin composes with (PIN_COMPOSES), which stay editable.
  const pinned = new Set((live?.org?.pins ?? []).map((p) => p.key));
  const editable = (key: string) => writable && (!pinned.has(key) || key in PIN_COMPOSES);
  const composeNote = (key: string) => (pinned.has(key) ? PIN_COMPOSES[key] : undefined);
  // The module is installed but not active here: its routes answer 404
  // component_not_installed, and the page shows no sandbox element at all
  // (sandbox plan v2 section 11.2, "skipped at setup means not there").
  if (moduleNotInstalled(settings.error) || moduleNotInstalled(probe.error)) return null;

  return (
    <ChartShell
      title="Sandbox isolation"
      sub="Run supported agents inside an isolation backend (bubblewrap on Linux and WSL2 today) with an isolated home and an explicit workspace. The enable switch binds on the next launch; moving the workspaces directory needs a daemon restart."
      right={
        <div className="flex items-center gap-2">
          {dirty && <Pill variant="warn">unsaved changes</Pill>}
          <Pill variant={live?.available ? "success" : "neutral"}>
            {live?.available ? "available now" : "not active"}
          </Pill>
        </div>
      }
    >
      <div className="space-y-4 p-1 text-[12px]">
        {localOnly && (
          <div className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-warn">
            This editor is local-only. Open the dashboard at{" "}
            <code className="text-fg-1">{localDashboardURL()}</code> to change it.
            <span className="ml-1 text-fg-3">
              The sandbox settings route is owner-loopback-only, so it is refused
              over a remote or tailnet view. The live probe below still reports
              honestly.
            </span>
          </div>
        )}
        {!writable && settings.data && (
          <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-fg-3">
            This dashboard has no writable config path. Edit the sandbox section of the config file instead.
          </div>
        )}

        <div
          className={`rounded-2 border px-3 py-2 ${
            live?.available
              ? "border-ok/40 bg-ok/10 text-ok"
              : "border-line-2 bg-bg-2 text-fg-3"
          }`}
        >
          <span className="font-medium">Running daemon: </span>
          {live?.available
            ? `${live.backend ?? "bwrap"} ${live.backend_version ?? ""} available; home is ${live.home_mode ?? "isolated"}; network is ${live.egress ?? "internet"}.`
            : live?.reason ?? "Sandbox probe has not returned yet."}
          {/* Three different "not available" stories, three different next
              steps. A saved enable switch rebinds the daemon's sandbox seam
              on the next launch, so the old blanket "restart the daemon"
              line was wrong for the most common case. */}
          {live && !live.available && dirty && draft?.enabled && (
            <span className="ml-1 text-warn">
              Save below to apply the enable switch; it takes effect on the next
              launch.
            </span>
          )}
          {live?.verdict === "runtime_init_failed" && (
            <span className="ml-1 text-warn">
              The sandbox is enabled but the daemon could not start it - fix the
              setting named above and save again.
            </span>
          )}
        </div>

        {live?.org && <SandboxOrgPanel org={live.org} />}

        {!draft ? (
          // Never an eternal "Loading": a refused local-only route and a
          // genuinely failed load are different facts, and neither is
          // "still fetching".
          localOnly ? null : settings.error ? (
            <ErrorState
              className="py-4"
              title="Could not load the sandbox configuration"
              error={settings.error}
              onRetry={settings.reload}
            />
          ) : (
            <InlineLoading label="Loading sandbox configuration" />
          )
        ) : (
          <>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-3 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.enabled}
                  disabled={!writable}
                  onChange={(e) => update("enabled", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Enable sandbox support</span>
                  <span className="block text-[11px] text-fg-3">
                    {SANDBOX_MASTER_SWITCH_HELP}
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-3 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.default_on}
                  disabled={!editable("default_on")}
                  onChange={(e) => update("default_on", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Default sandbox on</span>
                  <span className="block text-[11px] text-fg-3">
                    Preselect the sandbox in the New Terminal Isolation picker; it remains overridable.
                  </span>
                  <OrgSetNote show={pinned.has("default_on")} />
                </span>
              </label>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1">
                <span id="sandbox-home-label" className="block font-medium text-fg-1">Home isolation</span>
                <ComboChip
                  label="Home isolation"
                  labelledBy="sandbox-home-label"
                  hideTriggerLabel
                  fullWidth
                  value={draft.home_mode}
                  disabled={!editable("home_mode")}
                  onChange={(v) => update("home_mode", v as "tmpfs" | "readonly")}
                  options={SANDBOX_HOME_OPTIONS}
                  buttonValueRender={(o) => <span className="font-mono">{o?.value ?? draft.home_mode}</span>}
                />
                <OrgSetNote show={pinned.has("home_mode")} />
              </div>
              <div className="space-y-1">
                <span id="sandbox-floor-label" className="block font-medium text-fg-1">Minimum isolation</span>
                <ComboChip
                  label="Minimum isolation"
                  labelledBy="sandbox-floor-label"
                  hideTriggerLabel
                  fullWidth
                  value={draft.min_isolation ?? ""}
                  disabled={!writable}
                  onChange={(v) => update("min_isolation", v)}
                  options={SANDBOX_FLOOR_OPTIONS}
                  buttonValueRender={(o) => <span className="font-mono">{o?.value || "no floor"}</span>}
                />
                <span className="block text-[11px] text-fg-3">
                  A sandboxed launch on a backend that builds a weaker class is refused, never run weaker.
                </span>
              </div>
            </div>

            {(live?.backends?.length ?? 0) === 0 && (setupRows.data?.backends?.length ?? 0) > 0 && SANDBOX_SETUP_PANEL && (
              <SandboxSetupRowsList rows={setupRows.data?.backends ?? []} onSetup={toggleSetup} setupOpen={setupFor} setupPanel={setupPanelNode} />
            )}
            {(live?.backends?.length ?? 0) > 0 && (
              <SandboxBackendsList
                backends={live?.backends ?? []}
                order={(draft.backends?.length ?? 0) > 0 ? draft.backends ?? [] : [draft.backend || "bwrap"]}
                egress={draft.egress ?? "internet"}
                writable={editable("backends")}
                orgNote={composeNote("backends")}
                onOrder={(next) => update("backends", next)}
                onSetup={setupRows.data && SANDBOX_SETUP_PANEL ? toggleSetup : undefined}
                setupRows={setupByID}
                setupOpen={setupFor}
                setupPanel={setupPanelNode}
              />
            )}

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1">
                <span id="sandbox-network-label" className="block font-medium text-fg-1">Network</span>
                <ComboChip
                  label="Network"
                  labelledBy="sandbox-network-label"
                  hideTriggerLabel
                  fullWidth
                  value={draft.egress ?? "internet"}
                  disabled={!writable}
                  onChange={(v) => update("egress", v as SandboxEgress)}
                  options={SANDBOX_EGRESS_OPTIONS}
                  buttonValueRender={(o) => <span className="font-mono">{o?.value ?? draft.egress ?? "internet"}</span>}
                />
                <span className="block text-[11px] text-fg-3">
                  Every mode except host keeps a sandboxed agent away from this dashboard and other local services. The internet mode also refuses private addresses (your LAN, the Windows host on WSL2, Docker containers) unless you list them below.
                </span>
              </div>
              <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.allow_tool_config_writes ?? false}
                  disabled={!editable("allow_tool_config_writes")}
                  onChange={(e) => update("allow_tool_config_writes", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Allow tool config writes</span>
                  <span className="block text-[11px] text-fg-3">
                    Off: the daemon config, guard policy, tool hook and MCP config, and the workspace git config and hooks are read-only inside the sandbox, so an agent cannot plant a command a later unsandboxed session runs.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-3 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.seccomp ?? false}
                  disabled={!editable("seccomp")}
                  onChange={(e) => update("seccomp", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Syscall filter (seccomp)</span>
                  <span className="block text-[11px] text-fg-3">
                    Observer&apos;s own syscall filter for the bubblewrap and Landlock-only sandboxes. On: a launch on either is refused if the filter cannot be built, applied or read back; it never runs unfiltered. Container rows keep their engine&apos;s own filter; on other rows Observer&apos;s filter does not run, and a launch on one says so. Off by default until it is checked live across the tools. Each run records what it got.
                  </span>
                  <OrgSetNote show={pinned.has("seccomp")} />
                </span>
              </label>
              <SandboxStraceSeizeCard writable={writable} />
            </div>

            {draft.oci && ociSelected && <SandboxOCIPanel value={draft.oci} pinned={pinned} writable={writable} onChange={(v) => update("oci", v)} />}
            {draft.mxc && <SandboxWindowsPanel value={draft.mxc} view={componentState.data?.view} pinned={pinned} writable={writable} onChange={(v) => update("mxc", v)} />}
            {draft.vm && <SandboxVMPanel value={draft.vm} view={componentState.data?.view} writable={writable} onChange={(v) => update("vm", v)} confirmToken={settings.data?.confirm_token} />}
            {draft.landlock && <SandboxLandlockPanel value={draft.landlock} view={componentState.data?.view} pinned={pinned} writable={writable} onChange={(v) => update("landlock", v)} />}
            {draft.openshell && (
              <SandboxOpenShellPanel
                value={draft.openshell}
                row={live?.backends?.find((b) => b.id === "openshell")}
                view={componentState.data?.view}
                writable={writable}
                onChange={(v) => update("openshell", v)}
              />
            )}
            {draft.seatbelt && draft.apple_container && <SandboxMacPanel seatbelt={draft.seatbelt} appleContainer={draft.apple_container} view={componentState.data?.view} pinned={pinned} writable={writable} onChange={(k, v) => update(k, v as never)} />}
            <SandboxNativePanel value={(draft as { vendor_forced_native?: string }).vendor_forced_native} pinned={pinned} writable={writable} onChange={(v) => update("vendor_forced_native" as never, v as never)} />
            {draft.hosted && <SandboxHostedPanel value={draft.hosted} view={componentState.data?.view} pinned={pinned} writable={writable} onChange={(v) => update("hosted", v)} />}
            <SandboxOrgShellCard />
            <SandboxCredentialsPanel
              value={draft.readopt}
              view={componentState.data?.view}
              pinned={pinned}
              writable={writable}
              onChange={(v) => update("readopt", v)}
              onOpenTerminal={(handle, label) => dock.launch({ token: handle, tool: label, sessionId: "", hasProjectRoot: false })}
            />
            <SandboxWindowsTiersPanel
              wslc={draft.wslc}
              hcs={draft.hcs}
              windows={draft.windows}
              savedTier={save.base?.windows?.mxc_tier}
              view={componentState.data?.view}
              pinned={pinned}
              writable={writable}
              onChange={(k, v) => update(k, v as never)}
            />

            <SandboxListField
              label="Allowed private networks (internet mode)"
              hint="Authority-expanding: CIDRs inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7 the egress gateway may reach, one per line (for example a registry at 10.20.0.0/16). Loopback, link-local and this machine's own addresses can never be listed."
              value={draft.egress_allow_cidrs ?? []}
              disabled={!editable("egress_allow_cidrs")}
              orgSet={pinned.has("egress_allow_cidrs")}
              warn
              onChange={(v) => update("egress_allow_cidrs", v)}
            />

            <SandboxListField
              label="Hosts a sandboxed agent may reach (internet mode)"
              hint="Restrictive: when set, the egress gateway lets a sandboxed agent reach only these hosts (one per line; *.example.com for every name below it), on ports 443 and 80, beside the model proxy. Empty keeps the internet mode as it is. Your organization's list, when it pins one, narrows yours."
              value={draft.egress_allow_hosts ?? []}
              disabled={!editable("egress_allow_hosts")}
              orgSet={pinned.has("egress_allow_hosts")}
              onChange={(v) => update("egress_allow_hosts", v)}
            />

            <SandboxListField
              label="Extra variables a sandboxed agent may receive"
              hint="Authority-expanding: a sandboxed agent gets only this computer's own variables (PATH, HOME, the locale and the system folders), its tool's provider variables and Observer's own; name any other variable here, one per line (for example GITHUB_TOKEN). This setting is yours alone; your organization cannot set it. Each run shows the names it passed."
              value={draft.pass_env ?? []}
              disabled={!editable("pass_env")}
              orgSet={pinned.has("pass_env")}
              warn
              onChange={(v) => update("pass_env", v)}
            />

            <fieldset className="rounded-2 border border-warn/30 bg-warn/5 p-3" data-testid="sign-in-seed-tools">
              <legend className="px-1 text-[12px] font-medium text-fg-1">Copy a tool's sign-in into a sandboxed run without asking</legend>
              <p className="text-[11px] text-fg-2">
                Off by default: a container run that starts from its own empty tool state (gVisor, or the image's own copy of the tool) asks at
                launch before it copies the tool's sign-in file. A tool ticked here is copied without asking. The tool inside the box can read and
                use the copy, the box's allowed network can carry it, and it is removed when the run ends. Never for a hosted sandbox. This setting
                is yours alone; your organization can only forbid it.
              </p>
              <p className="mt-1 text-[11px] text-fg-2" data-testid="sign-in-shared-note">
                A sandbox that shares the tool's own state (bubblewrap, Landlock, Seatbelt, mxc-process, Apple container, or oci-runc running this
                computer's own tool) always shares the tool's sign-in with the box, and each such run says so: the sandbox limits files and network,
                not the tool's own login.
              </p>
              {draft.sign_in_seed_forbidden && (
                <p className="mt-1 text-[11px] text-danger">
                  Your organization forbids copying a sign-in into a clean-copy container run. A sandbox that shares the tool's own state still
                  shares its sign-in.
                </p>
              )}
              <div className="mt-1.5 flex flex-wrap gap-3">
                {(draft.sign_in_seed_catalog ?? []).map((t) => {
                  const on = (draft.sign_in_seed_tools ?? []).includes(t);
                  return (
                    <label key={t} className="flex items-center gap-1.5 text-[12px]">
                      <input
                        type="checkbox"
                        checked={on}
                        disabled={!editable("sign_in_seed_tools") || !!draft.sign_in_seed_forbidden}
                        onChange={() =>
                          update(
                            "sign_in_seed_tools",
                            on ? (draft.sign_in_seed_tools ?? []).filter((x) => x !== t) : [...(draft.sign_in_seed_tools ?? []), t],
                          )
                        }
                      />
                      <span className="font-mono">{t}</span>
                    </label>
                  );
                })}
              </div>
            </fieldset>

            <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={draft.allow_osc52_clipboard ?? false}
                disabled={!editable("allow_osc52_clipboard")}
                onChange={(e) => update("allow_osc52_clipboard", e.target.checked)}
              />
              <span>
                <span className="font-medium text-fg-1">Let a sandboxed agent use the clipboard through the terminal (OSC 52)</span>
                <span className="block text-[11px] text-fg-3">
                  Off: Observer removes the terminal clipboard sequences a sandboxed agent prints, so it cannot set or read your clipboard through this terminal or the console it was started from. This setting is yours alone; your organization cannot set it. A run that allows it says so on its terminal.
                </span>
              </span>
            </label>

            <SandboxSetupElevatedToggle
              value={draft.setup}
              disabled={!writable}
              onChange={(v) => update("setup", v)}
            />

            <div className="grid gap-3 md:grid-cols-2">
              <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.allow_remote_clone}
                  disabled={!editable("allow_remote_clone")}
                  onChange={(e) => update("allow_remote_clone", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Allow remote clone</span>
                  <span className="block text-[11px] text-fg-3">
                    The daemon may run git clone over the network with your ambient credentials.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.allow_worktree_source}
                  disabled={!editable("allow_worktree_source")}
                  onChange={(e) => update("allow_worktree_source", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Allow git worktree source (off by default)</span>
                  <span className="block text-[11px] text-fg-3">
                    Mounts the main repository&apos;s .git folder writable inside the box. The agent can then add
                    objects to the shared object store (and so also delete or replace stored ones) and commit on
                    the run&apos;s own new branch. The repository&apos;s hooks, config, the main checkout&apos;s
                    HEAD and index, every other branch and tag, and the other worktrees stay read-only. At the end
                    of the run a clean worktree is removed and a branch holding commits is kept for you.
                  </span>
                </span>
              </label>
            </div>

            <SandboxListField
              label="Remote allowed hosts"
              hint="One hostname per line. Empty means any host once remote clone is enabled."
              value={draft.remote_allowed_hosts}
              disabled={!editable("remote_allowed_hosts")}
              orgSet={pinned.has("remote_allowed_hosts")}
              orgNote={composeNote("remote_allowed_hosts")}
              onChange={(v) => update("remote_allowed_hosts", v)}
            />

            <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
              <Summary className="font-medium text-fg-1">
                Workspace lifecycle and advanced binds
              </Summary>
              <div className="mt-3 space-y-3">
                <label className="block space-y-1">
                  <span className="font-medium text-fg-2">Workspaces directory</span>
                  <input
                    value={draft.workspaces_dir}
                    disabled={!writable}
                    placeholder="default: &lt;observer dir&gt;/workspaces"
                    onChange={(e) => update("workspaces_dir", e.target.value)}
                    className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
                  />
                  <span className="block text-[11px] text-fg-3">Must be an absolute path when set.</span>
                </label>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <span id="sandbox-retention-label" className="block font-medium text-fg-2">Workspace retention</span>
                    <ComboChip
                      label="Workspace retention"
                      labelledBy="sandbox-retention-label"
                      hideTriggerLabel
                      fullWidth
                      value={String(draft.workspace_retention_days)}
                      disabled={!editable("workspace_retention_days")}
                      onChange={(v) => update("workspace_retention_days", Number(v))}
                      options={numberOptions(SANDBOX_RETENTION_DAYS, draft.workspace_retention_days, retentionLabel)}
                      buttonValueRender={() => <span>{retentionLabel(draft.workspace_retention_days)}</span>}
                    />
                    <span className="block text-[11px] text-fg-3">How long prepared workspaces are kept; forever is the default.</span>
                    <OrgSetNote show={pinned.has("workspace_retention_days")} />
                  </div>
                  <div className="space-y-1">
                    <span id="sandbox-timeout-label" className="block font-medium text-fg-2">Preparation timeout</span>
                    <ComboChip
                      label="Preparation timeout"
                      labelledBy="sandbox-timeout-label"
                      hideTriggerLabel
                      fullWidth
                      value={String(draft.prep_timeout_seconds)}
                      disabled={!editable("prep_timeout_seconds")}
                      onChange={(v) => update("prep_timeout_seconds", Number(v))}
                      options={numberOptions(SANDBOX_PREP_TIMEOUTS, draft.prep_timeout_seconds, timeoutLabel)}
                      buttonValueRender={() => <span>{timeoutLabel(draft.prep_timeout_seconds)}</span>}
                    />
                    <OrgSetNote show={pinned.has("prep_timeout_seconds")} />
                  </div>
                  <div className="space-y-1">
                    <span id="sandbox-liverun-label" className="block font-medium text-fg-2">Updates while runs are live</span>
                    <ComboChip
                      label="Updates while runs are live"
                      labelledBy="sandbox-liverun-label"
                      hideTriggerLabel
                      fullWidth
                      value={draft.live_run_update_policy ?? "defer"}
                      disabled={!editable("live_run_update_policy")}
                      onChange={(v) => update("live_run_update_policy", v as SandboxLiveRunPolicy)}
                      options={SANDBOX_LIVE_RUN_POLICY_OPTIONS}
                    />
                    <span className="block text-[11px] text-fg-3">An update never ends a live sandboxed run on its own; this says when it asks.</span>
                    <OrgSetNote show={pinned.has("live_run_update_policy")} />
                  </div>
                </div>
                <SandboxListField
                  label="Mask paths"
                  hint="Absolute host paths to hide with tmpfs, one per line."
                  value={draft.mask_paths}
                  disabled={!editable("mask_paths")}
                  orgSet={pinned.has("mask_paths")}
                  orgNote={composeNote("mask_paths")}
                  onChange={(v) => update("mask_paths", v)}
                />
                <SandboxListField
                  label="Extra read-only binds"
                  hint="Absolute paths exposed read-only inside the sandbox."
                  value={draft.extra_ro_binds}
                  disabled={!editable("extra_ro_binds")}
                  orgSet={pinned.has("extra_ro_binds")}
                  onChange={(v) => update("extra_ro_binds", v)}
                />
                <SandboxListField
                  label="Extra read-write binds"
                  hint="Authority-expanding: these host paths become writable inside the sandbox."
                  value={draft.extra_rw_binds}
                  disabled={!editable("extra_rw_binds")}
                  orgSet={pinned.has("extra_rw_binds")}
                  warn
                  onChange={(v) => update("extra_rw_binds", v)}
                />
              </div>
            </details>

            {err && (
              <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-danger">
                {err}
              </div>
            )}
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <ConfirmButton
                variant="soft"
                armedVariant="danger"
                disabled={busy || !writable}
                requireConfirm={expandsAuthority}
                onConfirm={() => void saveSandbox()}
                confirmLabel="Save anyway?"
                armedNote={
                  loosensMXCTier
                    ? "This configuration loosens isolation: it lets launches use MXC's weaker AppContainer tier, which sees every folder granted to ALL APPLICATION PACKAGES." +
                      (draft.allow_remote_clone || draft.extra_rw_binds.some((p) => p.trim() !== "") || (draft.egress_allow_cidrs ?? []).some((p) => p.trim() !== "")
                        ? " It also expands authority: remote clone, read-write binds or private networks are set."
                        : "")
                    : "This configuration expands authority: remote clone lets the daemon make a network git request with your ambient credentials, and read-write binds expose host paths inside the sandbox."
                }
              >
                {busy ? "saving…" : "Save sandbox configuration"}
              </ConfirmButton>
              {dirty && (
                <span className="text-[11px] text-warn">
                  Unsaved changes - nothing above is in effect until you save.
                </span>
              )}
              {saved && !dirty && <SuccessCheck label="Saved" className="!text-[11px]" />}
              <span className="text-[11px] text-fg-3">
                A saved enable switch binds on the next launch; a changed workspaces
                directory needs a daemon restart. Active terminals are never
                retroactively sandboxed.
              </span>
            </div>
          </>
        )}
      </div>
    </ChartShell>
  );
}

function SandboxListField({
  label,
  hint,
  value,
  disabled,
  warn = false,
  orgSet = false,
  orgNote,
  onChange,
}: {
  label: string;
  hint: string;
  value: string[];
  disabled: boolean;
  warn?: boolean;
  orgSet?: boolean;
  orgNote?: string;
  onChange: (value: string[]) => void;
}) {
  return (
    <label className="block space-y-1">
      <span className={`font-medium ${warn ? "text-warn" : "text-fg-2"}`}>{label}</span>
      <textarea
        rows={Math.max(2, Math.min(5, value.length + 1))}
        value={value.join("\n")}
        disabled={disabled}
        onChange={(e) => onChange(splitConfigList(e.target.value))}
        className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
      />
      <span className="block text-[11px] text-fg-3">{hint}</span>
      <OrgSetNote show={orgSet} note={orgNote} />
    </label>
  );
}

// ociDriverSelected reports whether the container driver is selected: a
// configured [components] block with terminals.sandbox.oci active (the same
// opt-in rule the daemon applies, sandboxDriverSelected). An unconfigured
// install, or a view not yet loaded, has no container driver.
function ociDriverSelected(view: ComponentsView | undefined): boolean {
  if (!view || !view.configured) return false;
  return view.components.some((c) => c.id === "terminals.sandbox.oci" && c.state === "active");
}

// moduleNotInstalled reports whether err is the route guard's 404
// component_not_installed answer.
function moduleNotInstalled(err: Error | null): boolean {
  return err instanceof ApiError && err.status === 404 && err.body.includes("component_not_installed");
}
