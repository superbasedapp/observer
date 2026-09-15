import { ApiError, apiReason } from "@/lib/api";
import {
  PROJECT_ROOT_DENIED_MSG,
  REMOTE_TERMINAL_OFF_MSG,
  isProjectRootDeniedError,
  isTerminalCapabilityError,
} from "@/lib/remoteTerminal";
import { preflightStripCopy, toolNotAllowedReason } from "@/lib/toolInstall";
import type { GUILaunchable, ToolPreflight } from "@/lib/types";

// Pure copy + decision helpers for the New-Terminal dialog's IDE/desktop-app
// (GUI) launch half (T2.3, docs/plans/ide-desktop-launch-plan-2026-09-03.md
// §2.4). Mirrors toolInstall.ts's discipline: everything here is a PURE
// function over plain data, and the honesty convention is the same — never a
// generic "unavailable", name the exact blocker verbatim.
//
// The operator's scope for a GUI row is install + launch ONLY (plan §0): no
// resume, no continue, no attach, no model picker, no sandbox. The dialog
// derives ONE predicate — isGUISelection — and hides every one of those
// controls behind it, so a terminal-tool selection stays byte-identical to
// before this ticket.

// ---------------------------------------------------------------------------
// The one derived predicate every GUI-specific branch in the dialog reads.
// ---------------------------------------------------------------------------

// isGUISelection reports whether the currently-selected tool id names one of
// the advertised GUI rows from GET /api/terminal/sessions' `gui_launchables`
// (both adapter-owned rows and host rows carry a distinct `id`). A tool id
// can never be both an AI-tool launchable and a GUI launchable — the two
// come from disjoint registry carriers (plan §2.1) — so this is a plain
// membership check, not a priority rule.
export function isGUISelection(tool: string, guiRows: GUILaunchable[]): boolean {
  return guiRows.some((r) => r.id === tool);
}

// ---------------------------------------------------------------------------
// Wrap-kind honesty copy (plan §2.2 WrapKind vocabulary).
// ---------------------------------------------------------------------------

// wrapSummary renders the ONE sentence explaining whether/how this GUI
// launch's routing gets wrapped, per the row's closed `wrap_kind`
// vocabulary. This is the value proposition of a wrapped launch (plan §0.2)
// — the dialog shows it under the picker for every GUI row, not just the
// blocked ones, so "no wrap" is never silently omitted.
export function wrapSummary(row: GUILaunchable): string {
  switch (row.wrap_kind) {
    case "none":
      return `No routing wrap: ${row.wrap_reason}`;
    case "child_env":
      return "Routing wrap: the proxy base URL is exported into the app's environment (cold start only)";
    case "config_write":
      return `Routing is written by the ${row.adapter || row.id} config writer (\`observer init\`), not at launch`;
    default:
      // An unrecognised wrap_kind from a newer daemon: fall back to the
      // server's own reason rather than inventing wording for a value this
      // build has never seen (the same "don't fabricate" rule as an
      // unrecognised preflight verdict in toolInstall.ts).
      return row.wrap_reason || `Routing wrap: ${row.wrap_kind || "unknown"}.`;
  }
}

// ---------------------------------------------------------------------------
// Launch gating — mirrors the terminal path's launchBlockedFor /
// launchBlockedReason (toolInstall.ts), reusing the SAME allow-list and
// preflight-verdict copy so the two surfaces can never say different things
// about the same blocker.
// ---------------------------------------------------------------------------

// guiLaunchDisabledReason is the honest reason a GUI row's Start would be
// refused, or null when there is nothing blocking it. Precedence mirrors
// launchBlockedReason: the LAUNCH allow-list first (it names the exact
// config key + the fact that installing doesn't need it), then "no grounded
// executable at all" (the row's own honest zero — plan §2.4's `Grounded`),
// then a preflight verdict that means the daemon can't resolve a runnable
// binary (not_found / foreign_only) — reusing preflightStripCopy so this
// sentence is identical to the availability strip shown just below the
// picker, never a second hand-rolled copy of it.
export function guiLaunchDisabledReason(
  row: GUILaunchable,
  preflight: ToolPreflight | null,
  allowed: boolean,
): string | null {
  if (!allowed) return toolNotAllowedReason(row.id);
  if (!row.grounded) {
    return row.note || `${row.label} has no grounded install on this daemon — see the vendor's docs.`;
  }
  const verdict = preflight?.verdict ?? "";
  if (verdict === "not_found" || verdict === "foreign_only") {
    const strip = preflightStripCopy(row.id, preflight);
    return strip?.headline ?? `${row.label} is not installed.`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// POST /api/terminal/launch { kind: "gui" } error mapping.
// ---------------------------------------------------------------------------

// GUI_LAUNCH_UNSUPPORTED_MSG maps the launch route's 501 for a GUI request —
// this daemon runs without the terminal/PTY stack the GUI spawn+record path
// (termsvc.LaunchGUI) depends on for its allowed_tools/run-bookkeeping seam.
export const GUI_LAUNCH_UNSUPPORTED_MSG =
  "This daemon cannot launch GUI apps — it runs without the terminal stack (needs ConPTY on Windows 10 1809+ / a PTY backend).";

// guiLaunchErrorMessage turns a thrown POST /api/terminal/launch { kind:
// "gui" } failure into actionable copy. The 403/400 gates a GUI launch can
// hit — fresh-launch disabled, tool not in allowed_tools, the [remote]
// terminal gate, project-root denial — are the SAME gates a terminal launch
// hits on the SAME route (plan §2.4: "resolve through the SAME seams"), so
// this reuses the terminal path's classifiers (remoteTerminal.ts) instead of
// re-deriving the same message text. Anything else (unknown/unadvertised id,
// not-applicable field, 500 spawn failure) falls through to apiReason, which
// shows the server's own sentence — the same default the install path uses.
export function guiLaunchErrorMessage(e: unknown): string {
  const status = e instanceof ApiError ? e.status : 0;
  if (status === 501) return GUI_LAUNCH_UNSUPPORTED_MSG;
  if (isTerminalCapabilityError(e)) return REMOTE_TERMINAL_OFF_MSG;
  if (isProjectRootDeniedError(e)) return PROJECT_ROOT_DENIED_MSG;
  return apiReason(e);
}
