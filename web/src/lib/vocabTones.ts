import type { VocabEntry, VocabTable } from "@shared/lib/vocabEntry";

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
// lib/types.ts, internal/commitscan). Every state but ok is warn (commit and
// prompt-to-commit data is missing or stale). `tip` is the one-line reason
// (the Projects table tooltip); `banner` is the longer Project detail
// wording. Glyphs: VOCAB_ICONS.commitCapture.
export const COMMIT_CAPTURE: Readonly<
  Record<"ok" | "no_git" | "never_scanned" | "error", VocabEntry & { tip: string; banner: string }>
> = {
  ok: { tone: "success", tip: "Commit capture is live for this project.", banner: "" },
  no_git: {
    tone: "warn",
    label: "no git",
    tip: "This project isn't a git repository (or git isn't installed).",
    banner:
      "this project isn't a git repository (or git isn't installed) - commit and prompt-to-commit data is unavailable.",
  },
  never_scanned: {
    tone: "warn",
    label: "not scanned",
    tip: "The commit scanner hasn't scanned this project yet.",
    banner:
      "the commit scanner hasn't scanned this project yet - commit and prompt-to-commit data will appear once it has.",
  },
  error: {
    tone: "warn",
    label: "scan error",
    tip: "The last commit scan failed (timeout, unreadable or deleted root); the ledger may be stale.",
    banner:
      "the last commit scan failed (a timeout, or an unreadable or deleted root) - the ledger below may be stale until a scan succeeds.",
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
