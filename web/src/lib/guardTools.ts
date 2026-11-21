// Guard tools (T-154): the copy for the Security page's twins of
// `observer guard test`, `guard rescan`, `guard compile [--diff]` and
// `guard mcp scan | report`. The daemon runs the CLI's own code; this module
// only turns its answers into sentences.

/** POST /api/guard/test (the `observer guard test --json` document + mode). */
export type GuardTestResponse = {
  mode: string;
  mode_changes_verdict: boolean;
  report: {
    advice: string;
    decision: string;
    enforce_decision: string;
    kind: string;
    project_root: string;
    reason: string;
    rule_id: string;
    severity: string;
    source: string;
    target: string;
  };
};

/** GET on /api/guard/jobs/{policy,mcp,chain}. */
export type GuardJobsView = {
  confirm_token: string;
  kinds: { kind: string; label: string; writes: boolean }[];
  compile_enabled?: boolean;
};

/** One job in the shared registry (/api/backfill/jobs/<id>). */
export type GuardJob = { id: string; mode: string; status: string; output: string; error?: string };

// DECISION_WORDS: a decision as the start of a sentence, and as the end of
// "this would be ...". Unknown decisions fall back to the raw word.
const DECISION_WORDS: Record<string, { head: string; tail: string }> = {
  allow: { head: "Allowed", tail: "allowed" },
  flag: { head: "Flagged", tail: "flagged" },
  ask: { head: "Needs approval", tail: "held for approval" },
  deny: { head: "Blocked", tail: "blocked" },
};

/** guardTestHeadline is the verdict in one sentence. */
export function guardTestHeadline(r: GuardTestResponse["report"]): string {
  if (!r.rule_id) return "Allowed: no rule matched.";
  const head = DECISION_WORDS[r.decision]?.head ?? r.decision;
  return `${head} by ${r.rule_id} (${r.severity} severity).`;
}

/** guardTestEnforceLine answers "would enforce change this?". */
export function guardTestEnforceLine(res: GuardTestResponse): string {
  const mode = `Current mode is ${res.mode}.`;
  if (!res.mode_changes_verdict) return `${mode} Enforce mode decides the same.`;
  const tail = DECISION_WORDS[res.report.enforce_decision]?.tail ?? res.report.enforce_decision;
  return `${mode} In enforce mode this would be ${tail}.`;
}

const JOB_LABELS: Record<string, string> = {
  rescan: "Re-judge history",
  "compile-diff": "Check native rules",
  compile: "Write native rules",
  "mcp-scan": "Scan MCP configs",
  "mcp-report": "MCP report",
  // B-G8: the audit chain repairs (/api/guard/jobs/chain).
  "repair-anchors": "Restore pruned action ids (dry run)",
  "repair-anchors-apply": "Restore pruned action ids",
  "dedup-events": "Remove repeated rows (dry run)",
  "dedup-events-apply": "Remove repeated rows",
  "relink-gaps": "Re-link over deleted rows (dry run)",
  "relink-gaps-apply": "Re-link over deleted rows",
};

/** guardJobLabel names a job kind (or a "guard:<kind>" job mode). */
export function guardJobLabel(kindOrMode: string): string {
  const kind = kindOrMode.startsWith("guard:") ? kindOrMode.slice("guard:".length) : kindOrMode;
  return JOB_LABELS[kind] ?? kind;
}
