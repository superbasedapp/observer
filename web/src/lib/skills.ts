// skills.ts — pure formatting + table-driven label maps for the Skills tab
// (docs/app-design-system.md conventions: tone maps to the caller's Pill
// variant, never a new color). No imports besides `import type` from
// ./types.ts, so this file has zero runtime dependencies and can be
// exercised with plain node:test.
//
// Three facts about a skill are kept structurally separate everywhere in
// this file and never merged into one label: "observed" (a hook snapshot
// hashed on disk at session start), "head" (the committed content at the
// commit the reflog says HEAD was on at that time - NOT the working
// copy), and "invoked" (Skill-tool invocations). See the wire-shape
// comment on ProjectSkillsResponse in ./types.ts.

import type {
  ProjectSkill,
  SkillCommitStatus,
  SkillCurrentInGit,
  SkillHead,
  SkillHeadState,
  SkillInvokedEvent,
  SkillInvokedState,
  SkillObserved,
  SkillObservedState,
  SkillSpan,
  SkillCell,
  ProjectSkillsResponse,
} from "./types.ts";

export type SkillTone = "ok" | "muted" | "warn";

export type SkillLabel = {
  text: string;
  tone: SkillTone;
  tip?: string;
};

// A version id is an 8-hex git blob id prefix. SkillObserved.changed can
// interleave version ids with non-version state words ("absent",
// "unknown") - this is how the two are told apart, since the wire carries
// no parallel discriminator.
const VERSION_ID_RE = /^[0-9a-f]{8}$/i;

// versionLabel renders a version id as "#<ordinal> <id>", looking up the
// ordinal on the skill's own version list. Falls back to the bare id when
// the id isn't found there (e.g. a dangling reference in `changed`), and
// to "" for an empty id.
export function versionLabel(skill: ProjectSkill, id: string): string {
  if (!id) return "";
  const v = skill.versions.find((entry) => entry.id === id);
  if (!v) return id;
  return `#${v.ordinal} ${v.id}`;
}

// CHANGED_WORDS renders the non-version state words a changed chain can
// carry, so no raw token reaches the page.
const CHANGED_WORDS: Record<string, string> = {
  absent: "not present",
  unknown: "unknown",
  unreadable: "unreadable",
  home_unresolved: "unknown (home not resolved)",
};

// changedEntryLabel renders one entry of SkillObserved.changed: a version
// id resolves through versionLabel, a state word through CHANGED_WORDS.
function changedEntryLabel(skill: ProjectSkill, entry: string): string {
  if (VERSION_ID_RE.test(entry)) return versionLabel(skill, entry);
  return CHANGED_WORDS[entry] ?? entry;
}

const OBSERVED_TIP_NOT_CAPTURED =
  "No hook snapshot for this session: it predates skills capture, or hooks were not registered. Unknown, not absent.";
const OBSERVED_TIP_NA = "This tool does not read this skill directory.";
const OBSERVED_TIP_SUBAGENT =
  "Sub-agent sessions never fire SessionStart, so nothing is captured for them; see the parent session.";

// OBSERVED_STATIC covers every SkillObservedState whose label doesn't
// depend on the row's other fields. "observed" and "changed_during_session"
// are handled dynamically in observedLabel below (they need the skill's
// version list / the changed list).
const OBSERVED_STATIC: Partial<Record<SkillObservedState, SkillLabel>> = {
  not_captured: { text: "not captured", tone: "muted", tip: OBSERVED_TIP_NOT_CAPTURED },
  unknown: { text: "unknown", tone: "muted" },
  absent: { text: "not present", tone: "muted" },
  home_unresolved: { text: "unknown (home not resolved)", tone: "muted" },
  not_measurable: { text: "not measurable", tone: "muted" },
  "n/a": { text: "-", tone: "muted", tip: OBSERVED_TIP_NA },
};

// observedLabel renders the "Available at start (observed)" fact.
export function observedLabel(skill: ProjectSkill, obs: SkillObserved): SkillLabel {
  if (obs.state === "not_captured" && obs.reason === "subagent") {
    return { text: "not captured (sub-agent)", tone: "muted", tip: OBSERVED_TIP_SUBAGENT };
  }
  if (obs.state === "observed_after_start") {
    // The first snapshot came from a later re-fire (resume/compact): what
    // was on disk then, never "available at start".
    const seen = obs.version ? versionLabel(skill, obs.version) : "not present";
    const when = obs.source || "a later event";
    return {
      text: "not captured at start",
      tone: "muted",
      tip: `First seen at ${when}: ${seen}. That is what was on disk then, not at the start.`,
    };
  }
  if (obs.state === "observed") {
    return {
      text: versionLabel(skill, obs.version),
      tone: "ok",
      tip: obs.line_endings
        ? "CRLF: matches the committed content except line endings."
        : undefined,
    };
  }
  if (obs.state === "changed_during_session") {
    const chain = obs.changed.map((entry) => changedEntryLabel(skill, entry));
    return { text: `changed: ${chain.join(" -> ")}`, tone: "warn" };
  }
  return OBSERVED_STATIC[obs.state] ?? { text: obs.state, tone: "muted" };
}

// HEAD_STATIC covers every SkillHeadState whose label doesn't depend on
// the row's other fields. "committed" and "head_moved_near_start" are
// handled dynamically in headLabel below.
const HEAD_STATIC: Partial<Record<SkillHeadState, SkillLabel>> = {
  absent_in_commit: { text: "not in that commit", tone: "muted" },
  reflog_unavailable: { text: "unknown (no reflog for that time)", tone: "muted" },
  pending: { text: "pending", tone: "muted" },
  commit_unavailable: { text: "commit gone", tone: "muted" },
  git_unavailable: { text: "git history unavailable", tone: "muted" },
  not_in_project_git: { text: "not in this project's git", tone: "muted" },
  "n/a": { text: "-", tone: "muted" },
};

// HEAD_REASON_TIP explains a head reason token; no raw token reaches the
// page.
const HEAD_REASON_TIP: Record<string, string> = {
  skew: "HEAD moved within the clock-skew margin of the session start, so which commit the session started on is not certain.",
  same_second:
    "HEAD moved to more than one commit within one second (a rebase or pull); the reflog has one-second resolution, so the last one is not certain.",
  not_scanned: "The git history step has not run for this project yet.",
};

// headLabel renders the "HEAD at start" fact - the committed content at
// the commit the reflog says HEAD was on, never the working copy.
export function headLabel(skill: ProjectSkill, head: SkillHead): SkillLabel {
  if (head.state === "committed") {
    return { text: versionLabel(skill, head.version), tone: "ok" };
  }
  if (head.state === "head_moved_near_start") {
    const candidates = head.candidates.length > 0 ? ` (${head.candidates.join(", ")})` : "";
    const lead = head.reason === "same_second" ? "HEAD moved several times in one second" : "HEAD moved near start";
    return {
      text: `${lead}${candidates}`,
      tone: "warn",
      tip: HEAD_REASON_TIP[head.reason] ?? undefined,
    };
  }
  if (head.state === "git_unavailable" && head.reason) {
    return { text: "git history unavailable", tone: "muted", tip: HEAD_REASON_TIP[head.reason] ?? undefined };
  }
  return HEAD_STATIC[head.state] ?? { text: head.state, tone: "muted" };
}

// WORKTREE_UNCOMMITTED is the set of worktree states that mean "the
// committed version isn't what's on disk right now" for an otherwise
// `in_git: "committed"` skill.
const WORKTREE_UNCOMMITTED = new Set(["modified", "deleted", "renamed_away", "unmerged"]);

const CURRENT_STATIC: Partial<Record<SkillCurrentInGit, SkillLabel>> = {
  removed: { text: "removed", tone: "muted" },
  not_in_project_git: { text: "home directory (not in project git)", tone: "muted" },
  unknown: { text: "unknown", tone: "muted" },
};

// currentLabel renders the skill's present-day git status (distinct from
// both the observed and head facts, which are point-in-time-at-a-session).
export function currentLabel(skill: ProjectSkill): SkillLabel {
  const c = skill.current;
  if (c.in_git === "committed") {
    const uncommitted = WORKTREE_UNCOMMITTED.has(c.worktree);
    return {
      text: uncommitted ? "committed (uncommitted changes)" : "committed",
      tone: uncommitted ? "warn" : "ok",
    };
  }
  if (c.in_git === "not_committed") {
    if (c.worktree === "untracked") return { text: "not in git (untracked)", tone: "warn" };
    if (c.worktree === "ignored") return { text: "not in git (ignored)", tone: "muted" };
    if (c.worktree === "added" || c.worktree === "renamed") {
      return { text: "staged, not committed", tone: "warn" };
    }
    return { text: "not in git", tone: "muted" };
  }
  return CURRENT_STATIC[c.in_git] ?? { text: c.in_git, tone: "muted" };
}

// currentCaveat names why versions can't be matched to commits for this
// skill's directory, or null when matching is possible.
export function currentCaveat(skill: ProjectSkill): string | null {
  if (!skill.current.cannot_match) return null;
  return "versions cannot be matched to commits";
}

const INVOCATION_TIP = "Only Skill-tool invocations are captured, not typed /skill commands.";

// invocationLabel renders the "Invoked" summary count. measurable=false
// must never render as "0" - it means the tool's invocations aren't
// captured at all, a different fact than "captured, and there were none".
export function invocationLabel(skill: ProjectSkill): SkillLabel {
  if (!skill.invocations.measurable) {
    return { text: "not measurable", tone: "muted", tip: INVOCATION_TIP };
  }
  if (skill.invocations.count === 0) {
    return { text: "none captured", tone: "muted", tip: INVOCATION_TIP };
  }
  return { text: String(skill.invocations.count), tone: "ok", tip: INVOCATION_TIP };
}

// INVOKED_STATIC covers every SkillInvokedState except "version", which is
// handled dynamically in invokedEventLabel below (it needs the skill's
// version list to render an ordinal).
const INVOKED_STATIC: Partial<Record<SkillInvokedState, SkillLabel>> = {
  version_not_captured: { text: "invoked (version not captured)", tone: "muted" },
  not_measurable: { text: "invoked (not measurable)", tone: "muted" },
  unknown: { text: "invoked (unknown version)", tone: "muted" },
};

// invokedEventLabel renders one Skill-tool invocation event on a notable
// cell.
export function invokedEventLabel(skill: ProjectSkill, invoked: SkillInvokedEvent): SkillLabel {
  if (invoked.state === "version") {
    return { text: versionLabel(skill, invoked.version), tone: "ok" };
  }
  return INVOKED_STATIC[invoked.state] ?? { text: invoked.state, tone: "muted" };
}

const COMMIT_STATUS_LABEL: Record<SkillCommitStatus, string> = {
  A: "added",
  M: "modified",
  D: "deleted",
  "": "",
  "?": "not certain",
};

// commitStatusLabel spells out a SkillCommit.status letter for a chip.
export function commitStatusLabel(status: SkillCommitStatus): string {
  return COMMIT_STATUS_LABEL[status] ?? status;
}

// sessionsForSkill returns one skill's spans, newest-first. The wire
// array is oldest-to-newest across every skill combined.
export function sessionsForSkill(resp: ProjectSkillsResponse, key: string): SkillSpan[] {
  return resp.spans.filter((s) => s.skill_key === key).slice().reverse();
}

// cellsForSkill returns the sparse notable cells for one skill.
export function cellsForSkill(resp: ProjectSkillsResponse, key: string): SkillCell[] {
  return resp.cells.filter((c) => c.skill_key === key);
}

export const UNMATCHED_INVOCATIONS_NOTE =
  "Invoked but not a project or home skill (e.g. plugin skills).";
export const AMBIGUOUS_INVOCATIONS_NOTE = "Name matches more than one skill; not attributed.";
