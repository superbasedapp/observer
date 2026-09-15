import { ApiError, apiReason } from "@/lib/api";
import type { ToolPreflight } from "@/lib/types";

// Pure copy + decision helpers for the New-Terminal dialog's tool-availability
// half (audit DI-03 / DI-05 / DI-17). Everything here is a PURE function over
// plain data so a future vitest can cover it without a DOM: the dialog owns the
// React state, this module owns the wording and the verdicts' meaning.
//
// The honesty convention these follow is the one already used by
// sandboxDisabledReason / sshSystemDisabledReason in NewTerminalDialog.tsx and
// by REMOTE_TERMINAL_OFF_MSG in remoteTerminal.ts: never a generic
// "unavailable" — name the exact blocker, the exact config key, and where the
// switch lives.

// ---------------------------------------------------------------------------
// DI-05 — POST /api/terminal/install failures
// ---------------------------------------------------------------------------

// INSTALL_UNAVAILABLE_MSG maps the install route's 503. Mirrors the server's
// ONE honest sentence for a nil LaunchManager
// (internal/intelligence/dashboard/launch.go::errTerminalUnavailable): the
// embedded terminal is either switched off or has no PTY backend on this OS.
export const INSTALL_UNAVAILABLE_MSG =
  "The in-dashboard terminal is unavailable on this daemon, so there is nowhere to run the installer. Either [handoff].allow_dashboard_launch is false in ~/.observer/config.toml, or this OS has no PTY backend (Windows before 10 version 1809 has no ConPTY).";

// INSTALL_DISABLED_MSG maps the install route's 403 — the guided-install kill
// switch. Distinct from every other 403 in the dialog (the remote
// allow_terminal gate, the project-root denial) because this route is
// Local-only and its own opt-in owns the refusal.
export const INSTALL_DISABLED_MSG =
  "Guided install is switched off. Set [terminal.launch].allow_install = true in ~/.observer/config.toml and restart SuperBased, or run the install command above yourself in a terminal.";

// INSTALL_NO_COMMAND_MSG maps the install route's 400. The server reaches it
// when the capability registry carries no grounded install argv for the tool on
// this OS — the same honest zero toolresolve.NoGroundedInstallMsg states for
// the launcher and `observer doctor`.
export const INSTALL_NO_COMMAND_MSG =
  "SuperBased has no grounded install command for this tool on this OS — see the vendor's docs and install it by hand, then re-check.";

// NO_GROUNDED_INSTALL_MSG is the SPA mirror of
// internal/toolresolve.NoGroundedInstallMsg ("no grounded install command —
// see the vendor's docs"). It is the last-resort fallback for the dialog's
// not-installed branch when the server sends neither an install_command nor an
// install_note (an older daemon predating DI-03's wire field), so the branch
// can never dead-end with only "X is not installed."
export const NO_GROUNDED_INSTALL_MSG =
  "No grounded install command — see the vendor's docs.";

// installErrorMessage turns a thrown POST /api/terminal/install failure into
// actionable copy. Dispatch is on HTTP STATUS, which is correct HERE and only
// here: this route's statuses are unambiguous — 503 is the terminal-stack gate,
// 403 is [terminal.launch].allow_install, 400 is "no grounded install command"
// — so the status alone identifies the blocker.
//
// That is the OPPOSITE of the launch path (remoteTerminal.ts's
// isTerminalCapabilityError / isProjectRootDeniedError), which must classify by
// MESSAGE because POST /api/terminal/launch and the resume route overload 403
// across two unrelated gates ([remote].allow_terminal and
// allowed_project_roots). Do not "unify" the two approaches: they are different
// because the routes are different.
//
// Any other status (notably the 500 spawn failure, whose body carries the real
// exec error) falls through to apiReason, which strips fetchJSON's
// "api <status> <path>: " prefix and shows the SERVER's own sentence.
// INSTALL_TOKEN_STALE_MSG maps the install route's OTHER 403 — the panel's
// confirm token is missing or no longer matches (the dashboard was restarted or
// the panel outlived its token). The fix is a reload, not a config change.
export const INSTALL_TOKEN_STALE_MSG =
  "The dashboard's confirm token for this panel is stale — reload the page and try the install again.";

// isConfirmTokenReason recognises requireConfirmToken's plain-text 403 body
// ("forbidden: missing or mismatched confirm token — reload the panel").
export function isConfirmTokenReason(reason: string): boolean {
  return /confirm token/i.test(reason);
}

export function installErrorMessage(e: unknown): string {
  const status = e instanceof ApiError ? e.status : 0;
  switch (status) {
    case 503:
      return INSTALL_UNAVAILABLE_MSG;
    case 403:
      // 403 is overloaded on this route: requireConfirmToken answers a
      // stale/missing panel token with a PLAIN-TEXT body, while the
      // [terminal.launch].allow_install gate answers with JSON {"error"}.
      // Classify by body so a stale token does not tell the operator to flip
      // a config key that is already on (review F3, 2026-09-03).
      return isConfirmTokenReason(apiReason(e)) ? INSTALL_TOKEN_STALE_MSG : INSTALL_DISABLED_MSG;
    case 400:
      return INSTALL_NO_COMMAND_MSG;
    default:
      return apiReason(e);
  }
}

// ---------------------------------------------------------------------------
// DI-03 — the honest zero on the not-installed branch
// ---------------------------------------------------------------------------

// installGuidanceFor returns the sentence the not-installed branch shows when
// there is NO runnable install command — the `install_note` the server sends
// (audit DI-03: the grounded REASON this tool has no guided install on this OS,
// e.g. "muse is WSL-only"), falling back to the shared no-grounded-install
// sentence for an older daemon that predates the field.
//
// Returns null when an install_command IS present: the command itself is the
// guidance, and the server fills install_note only in the absent case, so
// rendering both would be redundant. Follows sandboxDisabledReason's shape —
// null means "nothing to say here".
export function installGuidanceFor(preflight: ToolPreflight | null): string | null {
  if (!preflight) return null;
  if (preflight.install_command) return null;
  const note = preflight.install_note?.trim();
  if (note) return note;
  return NO_GROUNDED_INSTALL_MSG;
}

// ---------------------------------------------------------------------------
// DI-17 — preflight state, verdict copy, Start gating
// ---------------------------------------------------------------------------

// PreflightState is what the dialog knows about GET
// /api/terminal/launch/preflight for the CURRENTLY selected tool:
//   "unknown" — not asked yet, or the tool has no verdict to give (the plain
//               shell pseudo-tool, or no tool selected);
//   "ok"      — the route answered; `preflight` carries the verdict;
//   "error"   — the route failed (501 seam disabled, 400, network). BEFORE
//               DI-17 this was indistinguishable from "unknown": the strip
//               rendered nothing and Start stayed enabled, so a daemon that
//               could not check silently looked like a healthy tool.
export type PreflightState = "unknown" | "ok" | "error";

// PreflightTone selects the strip's colour. "warn" is reserved for a verdict
// that genuinely blocks the launch; an informational verdict (a shim note, an
// off-PATH resolution, an unrecognised verdict) must not shout.
export type PreflightTone = "info" | "warn";

// PreflightStrip is the fully-resolved copy for the availability strip: one
// headline sentence, the server's notes, and whether to render at all.
export type PreflightStrip = {
  /**
   * False only for the calm case — a plain "ok" verdict carrying no notes.
   * Every other verdict (including an unrecognised one) renders, so the dialog
   * can never show an empty div where an explanation belongs.
   */
  render: boolean;
  tone: PreflightTone;
  /** One verdict-specific sentence. Never empty. */
  headline: string;
  /** The server's notes, verbatim and in order (never truncated here). */
  notes: string[];
  /** True when this verdict means the daemon cannot launch the tool. */
  blocking: boolean;
};

// VERDICT_COPY is the closed verdict vocabulary of
// internal/toolresolve.FormatVerdict, as a TABLE (CLAUDE.md #5: ordered rule
// sets are data, not an if/else ladder). The wording deliberately stays in the
// same family as FormatVerdict so the launcher's stderr, `observer doctor` and
// this dialog say one thing about the same machine state.
const VERDICT_COPY: Record<
  string,
  { tone: PreflightTone; blocking: boolean; headline: (tool: string, bin: string) => string }
> = {
  ok: {
    tone: "info",
    blocking: false,
    headline: (tool, bin) => (bin ? `${tool}: found at ${bin}.` : `${tool}: found.`),
  },
  ok_off_path: {
    tone: "info",
    blocking: false,
    headline: (tool, bin) =>
      bin
        ? `${tool}: not on PATH — the daemon will use ${bin}.`
        : `${tool}: not on PATH — the daemon resolved it elsewhere.`,
  },
  shadowed: {
    tone: "info",
    blocking: false,
    headline: (tool, bin) =>
      bin
        ? `${tool}: a Windows interop shim shadows the native install on PATH — the daemon will use the native ${bin} instead.`
        : `${tool}: a Windows interop shim shadows the native install on PATH — the daemon will use the native install instead.`,
  },
  foreign_only: {
    tone: "warn",
    blocking: true,
    headline: (tool) =>
      `${tool} is installed on Windows, not in WSL — the daemon can't launch it.`,
  },
  not_found: {
    tone: "warn",
    blocking: true,
    headline: (tool) => `${tool} is not installed.`,
  },
};

// preflightStripCopy resolves the availability strip for one preflight reply.
// It is the SINGLE owner of this wording: before DI-17 the same two sentences
// were hand-rolled in two drifting places (the strip and the Start button's
// tooltip), and three of the five verdicts rendered nothing at all.
//
// Notes are returned for EVERY verdict, not just ok_off_path/shadowed — the
// PATH-shim explanation (DI-04b) arrives on a plain "ok" and must stay visible.
// An unrecognised verdict gets a default arm that NAMES it (mirroring
// FormatVerdict's default) rather than an empty div.
export function preflightStripCopy(
  tool: string,
  preflight: ToolPreflight | null,
): PreflightStrip | null {
  if (!preflight) return null;
  const verdict = preflight.verdict ?? "";
  const notes = preflight.notes ?? [];
  const row = VERDICT_COPY[verdict];
  if (!row) {
    return {
      // Always render: an unknown verdict is exactly the case where silence is
      // most misleading.
      render: true,
      tone: "info",
      blocking: false,
      headline: `${tool}: ${verdict || "no verdict"} — SuperBased doesn't recognise this availability verdict, so it is not blocking the launch. The launch itself stays the authority.`,
      notes,
    };
  }
  return {
    render: verdict !== "ok" || notes.length > 0,
    tone: row.tone,
    blocking: row.blocking,
    headline: row.headline(tool, preflight.bin ?? ""),
    notes,
  };
}

// PREFLIGHT_NOTE_CAP is how many notes render before the "+N more" expander.
// The server sends them in priority order, so the first few are the ones that
// matter; the expander exists because DI-17 found the old hard cap of 4 SILENTLY
// dropped the rest.
export const PREFLIGHT_NOTE_CAP = 4;

// preflightErrorCopy is the strip shown when the preflight ROUTE itself failed
// — a 501 (the daemon runs without the tool-resolution seam), a 400, or a
// network error. `reason` is the server's own sentence via apiReason.
export function preflightErrorCopy(tool: string, reason: string): string {
  const who = tool || "this tool";
  const detail = reason.trim();
  const head = detail
    ? `Couldn't check whether ${who} is installed: ${detail}`
    : `Couldn't check whether ${who} is installed`;
  const dot = /[.!?]$/.test(head) ? "" : ".";
  return `${head}${dot} Start is disabled until the check succeeds — use Re-check, or install and launch this tool from a normal terminal.`;
}

// launchBlockedFor is the ONE predicate for "the Start button must be disabled
// because of this tool". Three independent causes:
//   - a verdict that means the daemon cannot resolve a runnable binary
//     (foreign_only / not_found);
//   - a preflight that could not be performed at all (DI-17: previously this
//     left Start enabled, so the dialog offered a launch it had no basis for);
//   - the LAUNCH allow-list refusing the tool (DI-06). This one blocks START
//     ONLY. It deliberately does NOT disable the picker option, the preflight
//     strip, or the "Install in terminal" button: [terminal.launch].allowed_tools
//     defaults to EMPTY (deny-all) and the install route is ungated by it on
//     purpose (audit DI-21), so gating selection on the allow-list would make
//     the guided install unreachable on exactly the fresh install that needs
//     it most.
// Every OTHER Start gate (no tool chosen, the remote allow_terminal tier, the
// sandbox workspace) stays where it is. The server re-checks all of this at
// launch and stays the authority — this is the honest up-front signal.
export function launchBlockedFor(
  state: PreflightState,
  verdict: string,
  allowed = true,
): boolean {
  if (state === "error") return true;
  if (!allowed) return true;
  const row = VERDICT_COPY[verdict];
  return row ? row.blocking : false;
}

// launchBlockedReason is the Start button's tooltip for a tool-side block — the
// same sentences the strip and the picker annotation show, so the surfaces can
// never drift apart again. Returns null when the tool is not what is blocking
// Start.
//
// Precedence is most-actionable-first: an unanswerable check beats a verdict
// (there is nothing trustworthy to say yet), and a verdict beats the allow-list
// (installing the binary is the step the operator can take right now, and it
// needs no allow-list entry).
export function launchBlockedReason(
  tool: string,
  state: PreflightState,
  preflight: ToolPreflight | null,
  errorReason: string,
  allowed = true,
): string | null {
  if (state === "error") return preflightErrorCopy(tool, errorReason);
  const strip = preflightStripCopy(tool, preflight);
  if (strip && strip.blocking) return strip.headline;
  if (!allowed) return toolNotAllowedReason(tool);
  return null;
}

// ---------------------------------------------------------------------------
// DI-06 / DI-07 — the two independent allow-lists behind the tool picker
// ---------------------------------------------------------------------------

// TOOL_NOT_ALLOWED_MSG is the honest copy for a tool the LAUNCH gate refuses
// ([terminal.launch].allowed_tools, default empty = deny-all). Before DI-06
// this was learned only from the POST's raw 403.
//
// It annotates the option; it does NOT disable it. See launchBlockedFor for why
// selection must stay open (the guided install is ungated by this allow-list on
// purpose, so a deny-all fresh install must still be able to reach it).
export const TOOL_NOT_ALLOWED_MSG =
  "not in [terminal.launch].allowed_tools — enable it under Terminals › Fresh-agent launch policy";

// toolNotAllowedReason is the Start-button / warn-line sentence for a tool the
// launch allow-list refuses. It names the key, the fix, AND the fact that
// installing does not require the allow-list — otherwise a fresh-install
// operator reads a disabled Start as "I can't do anything with this tool".
export function toolNotAllowedReason(tool: string): string {
  return `${tool} is ${TOOL_NOT_ALLOWED_MSG}. A fresh launch will be refused until then — installing it from here does not need the allow-list.`;
}

// TOOL_NOT_WATCHED_MSG is the honest copy for a tool the CAPTURE gate omits
// ([observer.watch].enabled_adapters). It is deliberately NOT disabling: the
// launch works perfectly, it simply records nothing — a completely different
// failure from "you may not launch this".
export const TOOL_NOT_WATCHED_MSG =
  "not watched — [observer.watch].enabled_adapters omits it; sessions will not be captured";

// ToolAnnotation is the resolved per-option state for one entry of the picker.
// `known` is false when the daemon sent no launchable_tool_info for this tool
// (an older build): absence is UNKNOWN, never "not allowed" — the honesty rule
// forbids inventing a gate the server never reported.
//
// EVERY option stays SELECTABLE — there is deliberately no "disabled" field
// here. Both gates are annotations, not selection barriers: a disallowed tool
// still needs its preflight verdict and its "Install in terminal" button
// (install is ungated by the launch allow-list by design, audit DI-21), and an
// unwatched tool launches perfectly well. The allow-list is enforced on START
// (launchBlockedFor) and, authoritatively, by the server.
export type ToolAnnotation = {
  tool: string;
  known: boolean;
  allowed: boolean;
  watched: boolean;
  /** Honest hover reason for the option, or null when there is nothing to say. */
  title: string | null;
  /** Inline suffix appended to the option label, or "". */
  labelSuffix: string;
};

// LaunchableToolInfo mirrors ONE element of GET /api/terminal/sessions'
// launchable_tool_info (Go: dashboard.LaunchableTool). Re-declared here rather
// than imported from types.ts so this pure module stays importable on its own.
export type LaunchableToolInfo = { tool: string; allowed: boolean; watched: boolean };

// annotateTool resolves one picker option against the two allow-lists. It
// branches on the CAPABILITY the server reported (allowed / watched), never on
// the tool's name (CLAUDE.md #3) — a new adapter needs no change here.
export function annotateTool(
  tool: string,
  info: LaunchableToolInfo | undefined,
): ToolAnnotation {
  if (!info) {
    return {
      tool,
      known: false,
      allowed: true,
      watched: true,
      title: null,
      labelSuffix: "",
    };
  }
  // The launch gate is reported first because it is the one that stops Start;
  // an unwatched-AND-disallowed tool leads with the blocker.
  if (!info.allowed) {
    return {
      tool,
      known: true,
      allowed: false,
      watched: info.watched,
      title: TOOL_NOT_ALLOWED_MSG,
      labelSuffix: " · not allow-listed",
    };
  }
  if (!info.watched) {
    return {
      tool,
      known: true,
      allowed: true,
      watched: false,
      title: TOOL_NOT_WATCHED_MSG,
      labelSuffix: " · not watched",
    };
  }
  return {
    tool,
    known: true,
    allowed: true,
    watched: true,
    title: null,
    labelSuffix: "",
  };
}

// pickerLegend summarises the annotated picker in one line, or null when every
// listed tool is both allow-listed and watched (nothing to explain). Counts,
// not names, so the line stays one line no matter how many adapters ship; the
// per-option title carries the specific reason.
export function pickerLegend(annotations: ToolAnnotation[]): string | null {
  const blocked = annotations.filter((a) => a.known && !a.allowed).length;
  const unwatched = annotations.filter((a) => a.known && a.allowed && !a.watched).length;
  if (blocked === 0 && unwatched === 0) return null;
  const parts: string[] = [];
  if (blocked > 0) {
    parts.push(
      `${blocked} ${blocked === 1 ? "tool is" : "tools are"} not in [terminal.launch].allowed_tools, so a launch is refused (you can still select ${blocked === 1 ? "it" : "them"} and install)`,
    );
  }
  if (unwatched > 0) {
    parts.push(
      `${unwatched} ${unwatched === 1 ? "tool launches" : "tools launch"} but [observer.watch].enabled_adapters omits ${unwatched === 1 ? "it" : "them"}, so ${unwatched === 1 ? "its" : "their"} sessions are not captured`,
    );
  }
  return `${parts.join("; ")}.`;
}

// unwatchedAllowedToolsMsg renders the DI-07 cross-check the server derives
// (GET /api/terminal/policy's unwatched_allowed_tools): tools the operator
// allow-listed for launch that an EXPLICIT [observer.watch].enabled_adapters
// list omits. They launch happily and record nothing, which is the silent
// failure the pill exists to make loud. Returns null when the gap is empty.
export function unwatchedAllowedToolsMsg(tools: string[] | undefined): string | null {
  const list = (tools ?? []).filter((t) => t.trim() !== "");
  if (list.length === 0) return null;
  return `${list.length} allow-listed ${list.length === 1 ? "tool is" : "tools are"} not watched: ${list.join(", ")} — add ${list.length === 1 ? "it" : "them"} to [observer.watch].enabled_adapters or delete the key to watch every adapter.`;
}
