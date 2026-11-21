import type { ProjectCommitOwnerReason, ProjectCommitShareBasis } from "@/lib/types";

// commitOwner.ts - the display vocabulary for commit ownership
// (docs/projects-page.md "Commit ownership"), shared by the Projects
// CommitsTab and the session-detail SessionCommitsCard so the two can never
// word the same reason differently. The reasons themselves are decided
// server-side by internal/projectroi's ordered rule table; this file only
// names them. The four "none" reasons never name a session: a commit no AI
// edit reached is human (or un-captured) work, never a guessed owner.

// OwnerReasonMeta names one reason. cloud marks a cloud-agent credit: the
// owner is a cloud session whose vendor-reported PR or branch produced the
// commit, and no line of it was measured, so the UI says so instead of
// showing zero lines.
export type OwnerReasonMeta = { label: string; tip: string; none: boolean; cloud?: boolean };

export const OWNER_REASON: Readonly<Record<ProjectCommitOwnerReason, OwnerReasonMeta>> = {
  merge: {
    label: "merge",
    tip: "Merge commits never carry attribution, so no session owns one.",
    none: true,
  },
  unreachable: {
    label: "not on branch",
    tip: "This commit fell out of the checked-out branch's history on a later scan, so it carries no attribution and has no owner.",
    none: true,
  },
  foreign_author: {
    label: "another author",
    tip: "This commit's author is not your configured git identity (user.name) for this repository, e.g. a teammate's commit you pulled. It carries no attribution, so none of your sessions owns it.",
    none: true,
  },
  no_ai_edits: {
    label: "none (human)",
    tip: "No AI edit captured by Observer reached this commit. It is treated as human (or uncaptured) work; no owner is guessed.",
    none: true,
  },
  sole_contributor: {
    label: "only contributing session",
    tip: "The only session whose prompts' AI edits reached this commit.",
    none: false,
  },
  most_code_lines: {
    label: "most AI code lines",
    tip: "Several sessions reached this commit; this one carried the most AI code lines into it.",
    none: false,
  },
  most_files: {
    label: "most files",
    tip: "Tied on AI code lines; this session carried the most files into the commit.",
    none: false,
  },
  earliest_prompt: {
    label: "earliest prompt",
    tip: "Tied on AI code lines and files; this session's first contributing prompt came earliest.",
    none: false,
  },
  session_id: {
    label: "tie broken by session id",
    tip: "Tied on every measure; the lowest session id is chosen so the answer is deterministic.",
    none: false,
  },
  cloud_pr_commit: {
    label: "cloud agent (in its PR)",
    tip: "A cloud agent session produced this commit: it is in the commit list of the pull request the agent's vendor reported for that session. File-level credit; the agent's lines were not measured.",
    none: false,
    cloud: true,
  },
  cloud_pr_landing: {
    label: "cloud agent (its PR landed)",
    tip: "This commit is how the pull request a cloud agent session opened landed (its squash or rebase commit, from the code host). File-level credit; the agent's lines were not measured.",
    none: false,
    cloud: true,
  },
  cloud_pr_subject: {
    label: "cloud agent (PR in subject)",
    tip: "This commit's squash subject names the pull request a cloud agent session opened on this repository, committed after that session started. Read from local git only. File-level credit; the agent's lines were not measured.",
    none: false,
    cloud: true,
  },
};

export const SHARE_BASIS_TIP: Readonly<Record<ProjectCommitShareBasis, string>> = {
  code_lines: "Shares are each session's AI code lines carried into this commit, over all contributors' code lines.",
  files:
    "No AI code lines reached this commit (only docs/config files), so shares are by files carried instead.",
  cloud_claim:
    "A cloud agent session's pull request or branch produced this commit. No line of it was measured, so every claiming session shares it equally.",
};

// ownerReasonMeta tolerates a reason string a newer server may add: it
// renders the raw value rather than crashing or inventing a label.
export function ownerReasonMeta(reason: string): OwnerReasonMeta {
  return (
    (OWNER_REASON as Record<string, OwnerReasonMeta>)[reason] ?? {
      label: reason,
      tip: reason,
      none: false,
    }
  );
}
