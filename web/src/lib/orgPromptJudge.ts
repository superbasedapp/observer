// orgPromptJudge.ts - the view model of the Security page's "Organization
// prompt judge" card (lane adm-p2). The body comes from GET
// /api/guard/prompt/judge, the same facts `observer guard status` prints
// (cmd/observer/planeb_admission_dashboard.go). Pure: no React, no fetch.
// Read-only: there is no switch here, a managed machine discloses, it does
// not opt in.

/** OrgPromptJudgeStatus is the daemon's body; `available: false` (with a
 *  reason) when this process cannot read it. */
export type OrgPromptJudgeStatus = {
  available: boolean;
  reason?: string;
  active?: boolean;
  off_reason?: string;
  managed?: boolean;
  version?: number;
  scope?: string;
  mode?: string;
  strict?: boolean;
  node_lane?: boolean;
  enforced?: boolean;
  judge_route?: string;
  engine_linked?: boolean;
  fail_closed?: boolean;
  unreachable?: string;
  budget_ms?: number;
  counts?: Record<string, number> | null;
  lines?: string[] | null;
  disclosure?: string;
  residuals?: string[] | null;
};

export type Tone = "neutral" | "success" | "warn" | "danger" | "info";

/** One tile of the card. */
export type JudgeTile = { label: string; value: string; tone: Tone; sub?: string };

const SCOPE_LABEL: Readonly<Record<string, string>> = {
  user_prompts: "Your prompts",
  all_calls: "Every model call",
};

/** judgeHeadline is the card's one-line state. */
export function judgeHeadline(s: OrgPromptJudgeStatus): { text: string; tone: Tone } {
  if (!s.available) return { text: s.reason ?? "Not available in this process.", tone: "neutral" };
  if (!s.active) {
    if (!s.managed) return { text: "Off: this is not an organization-managed machine, so the organization cannot turn it on here.", tone: "neutral" };
    return { text: `Off on this machine: ${s.off_reason ?? "no reason given"}.`, tone: "neutral" };
  }
  const how = s.enforced ? "refuses prompts its policy rules out" : "records its verdicts and refuses nothing";
  return { text: `On: the organization's judge reads the prompts you type here and ${how}.`, tone: s.enforced ? "warn" : "info" };
}

/** judgeTiles are the status tiles of an active judge (none when off). */
export function judgeTiles(s: OrgPromptJudgeStatus): JudgeTile[] {
  if (!s.available || !s.active) return [];
  const counts = s.counts ?? {};
  const deny = counts.deny ?? 0;
  const flagged = Object.entries(counts)
    .filter(([k]) => k !== "deny")
    .reduce((n, [, v]) => n + v, 0);
  return [
    { label: "Policy", value: `v${s.version ?? "?"}`, tone: "neutral", sub: s.mode ? `mode ${s.mode}` : undefined },
    { label: "Reads", value: SCOPE_LABEL[s.scope ?? ""] ?? s.scope ?? "?", tone: s.scope === "all_calls" ? "warn" : "neutral" },
    { label: "Strict", value: s.strict ? "yes" : "no", tone: s.strict ? "warn" : "neutral" },
    {
      label: "If the daemon cannot answer",
      value: s.fail_closed ? "Prompt refused" : "Prompt goes through",
      tone: s.fail_closed ? "danger" : "neutral",
      sub: s.unreachable,
    },
    { label: "Refused (24h)", value: String(deny), tone: deny > 0 ? "danger" : "neutral" },
    { label: "Flagged (24h)", value: String(flagged), tone: flagged > 0 ? "warn" : "neutral" },
  ];
}
