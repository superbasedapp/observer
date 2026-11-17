// sandboxSetupTypes.ts mirrors the sandbox setup wire contract in
// internal/dashapi/sandboxsetup.go (sandbox installation lifecycle plan,
// docs/plans/sandbox-installation-lifecycle-plan-2026-11-06.md section 3.6).
// Field names are the Go JSON tags, snake_case; the Go side pins them in
// internal/dashapi/sandboxsetup_test.go. Types only: the panel's copy lives in
// sandboxSetup.ts (lane ui).

import type { ToolInstallRecord } from "./types.ts";

/** sandboxsetup.StepState. */
export type SandboxSetupStepState =
  | "done"
  | "missing"
  | "unknown"
  | "blocked"
  | "not_applicable"
  | "in_flight"
  | "not_allowed";

/** sandboxsetup.Class, after the switches in force. */
export type SandboxSetupClass = "auto" | "terminal" | "elevated" | "guide" | "never";

/** sandboxsetup.Channel: how a step is carried out. */
export type SandboxSetupChannel =
  | "component_select"
  | "sandbox_enable"
  | "config_key"
  | "pm"
  | "pinned_download"
  | "content"
  | "oci_pull"
  | "terminal_cmd"
  | "hosted_connect"
  | "hosted_consent"
  | "orgshell_login"
  | "none";

/** sandboxsetup.Kind. */
export type SandboxSetupKind =
  | "component"
  | "program"
  | "kernel_feature"
  | "os_feature"
  | "os_version"
  | "group"
  | "service"
  | "content"
  | "image"
  | "account"
  | "credential"
  | "consent"
  | "config"
  | "enable";

/** What the person must do once a step ran ("" for nothing). */
export type SandboxSetupAfter = "" | "relogin" | "reboot" | "engine_restart" | "daemon_restart";

/** A tool_installs record of a sandbox setup step (subject_kind "sandbox"). */
export type SandboxSetupRecord = ToolInstallRecord & {
  /** "tool" or "sandbox"; absent reads as "tool". */
  subject_kind?: string;
  backend?: string;
  /** vendor_release, org_mirror or from_file. */
  source?: string;
  digest?: string;
  placed_path?: string;
  elevated?: boolean;
};

/** dashapi.SandboxSetupConsent: shown before a pinned download, echoed on run. */
export type SandboxSetupConsent = {
  pin: string;
  version: string;
  sha256: string;
  bytes: number;
  /** vendor_release or org_mirror. */
  source: string;
  url?: string;
};

/** dashapi.SandboxSetupStep. */
export type SandboxSetupStep = {
  prereq: string;
  kind: SandboxSetupKind | string;
  label: string;
  state: SandboxSetupStepState | string;
  class: SandboxSetupClass | string;
  channel: SandboxSetupChannel | string;
  display?: string;
  /** display is a command line to paste into a terminal, not a sentence. */
  display_is_command?: boolean;
  /** A credential step's field names (the provider's own variable names), never a value. */
  fields?: string[];
  /** A credential step's CLI form, which asks for the same fields. */
  command?: string;
  reason?: string;
  disclosure?: string;
  after?: SandboxSetupAfter | string;
  docs?: string;
  can_run: boolean;
  can_undo: boolean;
  /** What keeps an undo Observer would otherwise offer (live_runs, live_runs_unknown, kill_switch, elevation_off); the reason holds the sentence. */
  undo_refused?: string;
  record?: SandboxSetupRecord;
  consent?: SandboxSetupConsent;
};

/** dashapi.SandboxSetupPlan. */
export type SandboxSetupPlan = {
  backend: string;
  label: string;
  steps: SandboxSetupStep[];
  /** Index of the first step not done (-1: none). */
  next: number;
  ready: boolean;
  /** A passive plan with nothing left Observer can see to do: set up, and
   *  only "Check this machine" can say it runs here. */
  unconfirmed?: boolean;
  blocked?: string;
  /** Why the backend's setup is beta (a label only, never a gate). */
  beta?: string;
  /** The plan follows an active check. */
  checked: boolean;
  fingerprint: string;
};

/** dashapi.SandboxSetupSummary: one offered row on this host. */
export type SandboxSetupSummary = {
  backend: string;
  label: string;
  ready: boolean;
  /** Set up as far as Observer can see without running anything. */
  unconfirmed?: boolean;
  blocked?: string;
  /** Why the backend's setup is beta (a label only, never a gate). */
  beta?: string;
  /** The next step's label. */
  next?: string;
};

/** GET /api/terminal/sandbox/setup. */
export type SandboxSetupSummaryResponse = {
  backends: SandboxSetupSummary[];
};

/** dashapi.SandboxSetupRunRequest.Action. */
export type SandboxSetupAction = "run" | "undo" | "update" | "repair";

/** dashapi.SandboxSetupRunRequest: POST /api/terminal/sandbox/setup/{backend}/run. */
export type SandboxSetupRunRequest = {
  step: string;
  action: SandboxSetupAction;
  fingerprint: string;
  consent?: SandboxSetupConsent;
  /** A pinned download's offline file. */
  from_file?: string;
  /** hosted_connect only; never logged. */
  key?: string;
  /** hosted_connect only: each typed credential field by name; never logged. */
  fields?: Record<string, string>;
};

/** dashapi.SandboxSetupStarted. */
export type SandboxSetupStarted = {
  kind: "terminal" | "op" | "done";
  handle?: string;
  label?: string;
  op_id?: string;
  plan?: SandboxSetupPlan;
};

/** dashapi.SandboxSetupOp: GET /api/terminal/sandbox/setup/op/{id}. */
export type SandboxSetupOp = {
  id: string;
  /** internal/toolinstall status vocabulary. */
  status: string;
  done_bytes: number;
  total_bytes: number;
  error?: string;
};

/** The closed error codes of the setup routes ({"error", "code"}). */
export type SandboxSetupErrorCode =
  | "plan_changed"
  | "not_allowed_by_org"
  | "install_disabled"
  | "elevation_disabled"
  | "consent_required"
  | "live_runs"
  | "step_not_runnable"
  | "unknown_step"
  | "not_in_build"
  | "terminal_unavailable";

/** The setup routes' error body. */
export type SandboxSetupError = {
  error: string;
  code: SandboxSetupErrorCode | string;
};

/** The props of SandboxSetupPanel (compgen SANDBOX_SETUP_PANEL). */
export type SandboxSetupPanelProps = {
  /** Preselected row. */
  backend?: string;
  /** Open a setup terminal in the dock. */
  onTerminal: (handle: string, label: string) => void;
  /** The row became ready. */
  onReady?: (backend: string) => void;
  /** A docs or settings link was followed. */
  onNavigate?: () => void;
  /** The dialog's inline form. */
  compact?: boolean;
};
