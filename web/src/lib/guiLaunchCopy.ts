// guiLaunchCopy is the USER-FACING copy for an IDE / desktop-app (GUI) row in
// the New terminal dialog, derived from STRUCTURED fields only — never from
// free text.
//
// Why: gui_launchables rows also carry `note` and `wrap_reason`, and launch /
// preflight replies carry `wrap_note` / `notes`. Those are engineering records
// (install-layout provenance with dates and paths, base-URL research, WSLENV
// mechanics). They stay on the wire for `observer adapters` / doctor; the
// dialog shows only the short sentences below.
//
// The routing sentence is honest by construction: it is phrased from the
// daemon's own routing verdict (`routing_reaches_app` + `routing_reason`, the
// launcher's guilaunch.Compose result dry-run in the preflight, and the real
// one on the launch reply). Without a verdict, a sentence is shown ONLY for a
// wrap kind whose outcome does not depend on the machine — the dialog never
// claims routing it cannot deliver (a WSL daemon launching a Windows app is
// exactly the case where a child-env wrap silently does nothing).
//
// Table-driven (CLAUDE.md #5). Unknown kinds / reasons say nothing rather than
// echoing server text. No imports besides `import type`, so it runs under the
// node test runner.

/** The fields of a gui_launchables row this copy is derived from. */
export type GUICopyRow = {
  label: string;
  wrap_kind: string;
  project_dir_argv: boolean;
  grounded: boolean;
};

/** The daemon's routing verdict for the row (preflight or launch reply). */
export type GUIRoutingVerdict = {
  routing_reaches_app?: boolean;
  routing_reason?: string;
};

/** Shared phrase for "the proxy route will not reach this app". */
const NOT_ROUTED = "It can't be routed through the superbased proxy.";

// ROUTED_COPY: what to say when the verdict is that routing DOES reach the
// app, per wrap kind (only child_env can be delivered at launch).
export const ROUTED_COPY: Readonly<Record<string, string>> = {
  child_env: "The proxy address is set when the app starts, so quit it first if it's already open.",
};

// NOT_ROUTED_COPY: what to say when the verdict is that routing does NOT reach
// the app, per closed guilaunch.WrapReason.
export const NOT_ROUTED_COPY: Readonly<Record<string, string>> = {
  interop_env_not_propagated:
    "Launched from WSL, it can't be routed through the superbased proxy. Start it on Windows with the proxy address set, or set the proxy in the app's own settings.",
  packaged_app_no_env: "Opened as a Windows Store app, it can't be routed through the superbased proxy.",
  handoff_launcher: "It opens in a copy that's already running, so it won't be routed through the superbased proxy.",
  no_proxy_url: "superbased couldn't find its proxy address, so this launch won't be routed through it.",
  no_routing_vars: NOT_ROUTED,
  config_write: "It reaches the proxy through the settings superbased writes during setup, not through this launch.",
  no_wrap_mechanism: NOT_ROUTED,
};

// MACHINE_INDEPENDENT_COPY: the only sentences safe WITHOUT a verdict (an older
// daemon, or a row nothing can launch yet), because their outcome does not
// depend on how the app is launched. child_env is deliberately absent.
export const MACHINE_INDEPENDENT_COPY: Readonly<Record<string, string>> = {
  config_write: NOT_ROUTED_COPY.config_write,
  none: NOT_ROUTED,
};

/** Sentence for an app that takes no project-folder argument. */
export const NO_PROJECT_FOLDER_COPY = "Opens without a project folder.";

// guiRoutingSentence phrases the routing fact for one row, or "" when there is
// nothing honest to say.
export function guiRoutingSentence(row: GUICopyRow, verdict?: GUIRoutingVerdict | null): string {
  const reaches = verdict?.routing_reaches_app;
  if (reaches === true) return ROUTED_COPY[row.wrap_kind] ?? "";
  if (reaches === false) return NOT_ROUTED_COPY[verdict?.routing_reason ?? ""] ?? "";
  return MACHINE_INDEPENDENT_COPY[row.wrap_kind] ?? "";
}

// guiLaunchSummary is the ONE calm line shown under a selected GUI row: the
// project-folder fact (only when the app takes none — otherwise the folder
// picker itself says it) followed by the routing fact. "" when there is
// nothing to say.
export function guiLaunchSummary(row: GUICopyRow, verdict?: GUIRoutingVerdict | null): string {
  return [row.project_dir_argv ? "" : NO_PROJECT_FOLDER_COPY, guiRoutingSentence(row, verdict)]
    .filter((s) => s !== "")
    .join(" ");
}

// guiLaunchedToast is the success toast after a GUI launch. "routed through
// the superbased proxy" comes ONLY from the launch's own verdict
// (routing_reaches_app, falling back to wrap_applied on an older daemon).
export function guiLaunchedToast(r: {
  label: string;
  pid: number;
  wrap_applied: boolean;
  routing_reaches_app?: boolean;
}): string {
  const routed = r.routing_reaches_app ?? r.wrap_applied;
  return `Launched ${r.label} (pid ${r.pid})${routed ? " - routed through the superbased proxy" : ""}`;
}

// guiNotGroundedReason replaces the registry `note` for a row with no known
// executable layout (Grounded=false): the user-facing consequence, not the
// provenance record.
export function guiNotGroundedReason(row: Pick<GUICopyRow, "label">): string {
  return `superbased doesn't know where ${row.label} is installed yet, so it can't launch it from here.`;
}

// guiAvailabilityName is the name the dialog's availability copy ("X is not
// installed.", "Couldn't check whether X is installed") uses for the selected
// tool: a GUI row's label ("Zed"), never its launch id ("zed-ide", T-333);
// a terminal tool keeps its id, which is also the command it runs.
export function guiAvailabilityName(
  tool: string,
  guiRows: ReadonlyArray<{ id: string; label: string }>,
): string {
  const row = guiRows.find((r) => r.id === tool);
  return row && row.label.trim() ? row.label : tool;
}
