import type { VocabEntry, VocabTable } from "@shared/lib/vocabEntry";
import type { ProjectCaptureInfo } from "@/lib/types";

// vocabTones - the node dashboard's presentation tables for the closed
// vocabularies that more than one web page renders and that have no other
// metadata owner module (the sibling of shared/lib/vocabIcons.ts, which owns
// every glyph). Each table is commented with the owner of its values. A
// vocabulary shared with the org dashboard lives in shared/lib instead
// (guardCatalog.ts for guard decision / severity, cacheVocab.ts,
// sessionVocab.ts); a vocabulary one page owns stays in that page.

// POLICY_MODE - the mode of a guard, admission, egress or routing policy
// (Security, Egress, Policies, Routing). Recording-only modes (observe,
// advise) are info; enforce, which actively blocks or reroutes, is warn; a
// policy that is off is neutral. Before 2026-09-28 enforce was danger on
// Security and warn elsewhere, and observe was accent / neutral / info.
// Glyphs: VOCAB_ICONS.guardMode.
export const POLICY_MODE: VocabTable = {
  observe: { tone: "info" },
  advise: { tone: "info" },
  enforce: { tone: "warn" },
  off: { tone: "neutral" },
  disabled: { tone: "neutral" },
};

// PROMPT_GUARD_OUTCOME - the prompt-submit guard's outcome
// (GET /api/guard/prompt/events, internal/guard prompt lane), rendered by the
// Security page's Prompt guard card and the session Overview's
// PromptGuardLine. Any "degraded:<why>" outcome is folded onto the one
// "degraded" row by promptGuardOutcomeKey. Glyphs:
// VOCAB_ICONS.promptGuardOutcome.
export const PROMPT_GUARD_OUTCOME: VocabTable = {
  blocked: { tone: "danger" },
  confirmed: { tone: "info" },
  warned: { tone: "warn" },
  redacted: { tone: "accent" },
  allowed: { tone: "neutral" },
  degraded: { tone: "warn" },
  // detected: the POST-HOC capture lane found it in a prompt that was
  // already sent (no pre-send seam judged it) - nothing was stopped.
  detected: { tone: "danger" },
};

/** promptGuardOutcomeKey folds a "degraded:<why>" outcome onto its table row. */
export function promptGuardOutcomeKey(outcome: string): string {
  return outcome.startsWith("degraded:") ? "degraded" : outcome;
}

// EGRESS_OUTCOME - the proxy's realized egress routing outcome (Egress page
// and the Policies Activity tab). applied is success; a fail-closed,
// breaker-open or upstream error stopped the request (danger); a fail-open
// fallback or a failed splice let it through unrouted (warn). Before
// 2026-09-28 the Activity tab tested substrings and rendered fallback_open
// as danger. Glyphs: VOCAB_ICONS.egressOutcome.
export const EGRESS_OUTCOME: VocabTable = {
  applied: { tone: "success" },
  fail_closed: { tone: "danger" },
  breaker_open: { tone: "danger" },
  upstream_error: { tone: "danger" },
  fallback_open: { tone: "warn" },
  splice_failed: { tone: "warn" },
};

// CHECK_STATUS - a doctor / probe check status (GET /api/health/doctor,
// the prompt-guard probe). Glyphs: VOCAB_ICONS.healthCheck.
export const CHECK_STATUS: VocabTable = {
  ok: { tone: "success" },
  warn: { tone: "warn" },
  fail: { tone: "danger" },
};

// COMMIT_CAPTURE - a project's commit-capture state (ProjectCaptureInfo in
// lib/types.ts; the Go owner is internal/store commitCaptureStates). Each
// state names its cause: `tip` is the one-line reason (the Projects table
// tooltip), `banner` the Project detail heading, `todo` what to do about it.
// Only "error" is generic, and it is refined by COMMIT_SCAN_FAILURE below.
// Glyphs: VOCAB_ICONS.commitCapture.
export type CommitCaptureState = ProjectCaptureInfo["commits"];
export const COMMIT_CAPTURE: Readonly<
  Record<CommitCaptureState, VocabEntry & { tip: string; banner: string; todo: string; rescan: boolean }>
> = {
  ok: { tone: "success", tip: "Commit capture is live for this project.", banner: "", todo: "", rescan: true },
  catching_up: {
    tone: "info",
    label: "catching up",
    tip: "Reading this project's full git history in the background. Recent commits are already in.",
    banner: "Reading this project's full git history",
    todo: "A large history is read in steps of about 45 seconds per scan. Recent commits are in already, so the figures below use them. Nothing to do.",
    rescan: true,
  },
  never_scanned: {
    tone: "warn",
    label: "not scanned",
    tip: "The commit scanner hasn't scanned this project yet.",
    banner: "Not scanned yet",
    todo: "The scanner reads every project with a session in the last few days, every 2 minutes. Rescan now to read it immediately.",
    rescan: true,
  },
  no_git: {
    tone: "warn",
    label: "no git",
    tip: "git is not installed (or not on PATH) for the Observer daemon.",
    banner: "git is not installed",
    todo: "Install git and make sure it is on the PATH of the user that runs Observer, then restart the daemon.",
    rescan: false,
  },
  no_folder: {
    tone: "warn",
    label: "no folder",
    tip: "This project has no folder on disk: the tool did not report one, so there is no repository to read.",
    banner: "This project has no folder on disk",
    todo: "The AI tool filed these sessions under a placeholder name instead of a folder. Nothing to fix here: commits for this work show on the project for its real folder.",
    rescan: false,
  },
  root_missing: {
    tone: "warn",
    label: "folder gone",
    tip: "The project folder was deleted, moved or is not mounted. Commits captured before are kept.",
    banner: "The project folder was not found",
    todo: "It was deleted, moved, or is on a drive that is not mounted right now. Commits captured before are kept. If you moved it, the next session in the new place starts a new project; if it comes back, scanning resumes on its own.",
    rescan: true,
  },
  not_repo: {
    tone: "warn",
    label: "not a repo",
    tip: "The folder exists but is not a git repository.",
    banner: "This folder is not a git repository",
    todo: "Commit tracking needs git. Run git init (or clone the project) in this folder; the scanner re-checks every 30 minutes, or rescan now.",
    rescan: true,
  },
  error: {
    tone: "warn",
    label: "scan error",
    tip: "The last commit scan failed. Open the project for the reason.",
    banner: "The last commit scan failed",
    todo: "",
    rescan: true,
  },
};

// COMMIT_SCAN_FAILURE - the failure kind behind an "error" capture state
// (internal/commitscan failure.go's FailureKind vocabulary). `what` is the
// one-line cause, `todo` the plain fix.
export const COMMIT_SCAN_FAILURE: Readonly<Record<string, { what: string; todo: string }>> = {
  timeout: {
    what: "git took too long, even when asked for a few commits at a time",
    todo: "Usually a very large repository on a slow drive (for example /mnt/c from WSL). Rescan now to try again; moving the repository to the Linux file system makes it much faster.",
  },
  dubious_ownership: {
    what: "git refused the folder because another user owns it",
    todo: "Common for /mnt/c folders seen from WSL. If you trust the folder, run: git config --global --add safe.directory <folder>, then rescan.",
  },
  permission_denied: {
    what: "the folder or its .git directory is not readable by the user Observer runs as",
    todo: "Fix the folder permissions, then rescan.",
  },
  repo_unreadable: {
    what: "git reports a missing or damaged object in this repository",
    todo: "Run git fsck in the folder. A shallow or partial clone can also cause this; fetching the full history fixes it.",
  },
  output_too_large: {
    what: "a single commit's change summary is larger than the scanner's 8 MB limit",
    todo: "This is rare (usually a huge generated file committed once). Recent commits around it are still captured.",
  },
  other: {
    what: "git failed for a reason the scanner does not recognise",
    todo: "The message from git is below. Rescan to retry; it also retries on its own with a growing delay.",
  },
};

// SUGGESTION_SEVERITY / _CATEGORY / _SCOPE - the advisor's closed
// vocabularies (AdvisorSuggestion in lib/types.ts, internal/intelligence/
// advisor). Glyphs: VOCAB_ICONS.suggestionSeverity / .suggestionCategory /
// .suggestionScope.
export const SUGGESTION_SEVERITY: VocabTable = {
  info: { tone: "info" },
  advice: { tone: "accent" },
  warning: { tone: "warn" },
};

export const SUGGESTION_CATEGORY: VocabTable = {
  cost: { tone: "neutral" },
  latency: { tone: "neutral" },
  quality: { tone: "neutral" },
  hygiene: { tone: "neutral" },
};

export const SUGGESTION_SCOPE: VocabTable = {
  session: { tone: "neutral" },
  project: { tone: "neutral" },
  global: { tone: "neutral" },
};

// AUDIT_CHAIN - a hash-chained audit log's verification state (admission /
// egress audit chains on the Policies page). Glyphs: VOCAB_ICONS.auditChain.
export const AUDIT_CHAIN: VocabTable = {
  intact: { tone: "success", label: "ok" },
  broken: { tone: "danger" },
};

// commitCaptureTip is the one-line Projects-table tooltip for a capture
// state: the state's own tip, or for a plain error the specific cause
// (COMMIT_SCAN_FAILURE) the list row now carries as commits_kind.
export function commitCaptureTip(c: ProjectCaptureInfo): string {
  if (c.commits === "error") {
    const f = COMMIT_SCAN_FAILURE[c.commits_kind ?? "other"] ?? COMMIT_SCAN_FAILURE.other;
    return `The last commit scan failed: ${f.what}. Open the project to see what to do.`;
  }
  return (COMMIT_CAPTURE[c.commits] ?? COMMIT_CAPTURE.error).tip;
}
