import type { ProjectCommitOwnerReason, ProjectCommitShareBasis } from "@/lib/types";

// commitOwner.ts - the display vocabulary for commit ownership
// (docs/projects-page.md "Commit ownership"), shared by the Projects
// CommitsTab and the session-detail SessionCommitsCard so the two can never
// word the same reason differently. The reasons themselves are decided
// server-side by internal/projectroi's ordered rule table; this file only
// names them. The four "none" reasons never name a session: a commit no AI
// edit reached is human (or un-captured) work, never a guessed owner.

export const OWNER_REASON: Readonly<
  Record<ProjectCommitOwnerReason, { label: string; tip: string; none: boolean }>
> = {
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
};

export const SHARE_BASIS_TIP: Readonly<Record<ProjectCommitShareBasis, string>> = {
  code_lines: "Shares are each session's AI code lines carried into this commit, over all contributors' code lines.",
  files:
    "No AI code lines reached this commit (only docs/config files), so shares are by files carried instead.",
};

// ownerReasonMeta tolerates a reason string a newer server may add: it
// renders the raw value rather than crashing or inventing a label.
export function ownerReasonMeta(reason: string): { label: string; tip: string; none: boolean } {
  return (
    (OWNER_REASON as Record<string, { label: string; tip: string; none: boolean }>)[reason] ?? {
      label: reason,
      tip: reason,
      none: false,
    }
  );
}
