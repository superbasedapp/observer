// deliveryModel.ts - the PURE half of the node dashboard's delivery surfaces
// (commit to PR to merge, D-689; docs/projects-page.md "Delivery"): the
// Projects "Delivery" tab, the session Commits card's delivery lines and the
// Settings "Code hosts" card. Closed vocabularies mapped to labels and tones
// (glyphs live in shared/lib/vocabIcons.ts), plus the few derivations the
// three surfaces must agree on.
//
// HONESTY RULES this file owns:
//   - A rate or count the server marks unknown is never drawn as 0: the
//     text helpers return null and the caller shows the reason.
//   - PR merge rate and mergeable counts need a code host; without one the
//     page says "connect a code host", never "0%".
//   - Chips carry state, not judgement: the accepted-work rate is never
//     coloured red or green.
//
// No React, no fetch: importable under `node --test`.

import type { VocabEntry } from "../../../shared/lib/vocabEntry.ts";
import type {
  DeliveryFunnel,
  DeliveryLanding,
  DeliveryPR,
  DeliveryRate,
  DeliverySource,
  DeliverySummary,
  SessionDeliveryRow,
} from "./types.ts";

/** CODE_HOSTS_HREF opens Settings > Connected tools at the Code hosts card,
 *  the one place a code host is connected (every "connect" button links here). */
export const CODE_HOSTS_HREF = "/settings?section=tools&open=code-hosts";

/** A vocabulary row with the sentence its tooltip says. */
export type DeliveryEntry = VocabEntry & { tip: string };

/** PR_CHIP: a PR's one chip, keyed by prChipKey (state, or for an open PR
 *  its readiness). Labels match the org dashboard's People > Delivery tab. */
export const PR_CHIP: Readonly<Record<string, DeliveryEntry>> = {
  merged: { tone: "accent", label: "merged", tip: "Merged into the base branch." },
  closed_unmerged: {
    tone: "neutral",
    label: "closed unmerged",
    tip: "Closed without merging. A PR replaced by another PR also reads this way.",
  },
  draft: { tone: "neutral", label: "draft", tip: "A draft PR is never mergeable." },
  ready: { tone: "success", label: "mergeable", tip: "Open, and the code host would allow merging now." },
  conflicts: { tone: "danger", label: "conflicts", tip: "Merge conflicts with the base branch." },
  checks_failing: { tone: "danger", label: "checks failing", tip: "At least one required check failed." },
  checks_pending: { tone: "info", label: "checks running", tip: "Required checks are still running." },
  changes_requested: { tone: "warn", label: "changes requested", tip: "A reviewer requested changes." },
  review_required: {
    tone: "warn",
    label: "needs review",
    tip: "Required approvals look missing. Inferred from the code host saying the PR is blocked with no other reason.",
  },
  behind: { tone: "warn", label: "behind base", tip: "The base branch moved and the branch must be brought up to date." },
  blocked_other: { tone: "warn", label: "blocked", tip: "Blocked by something else (a policy, a hook or a lock)." },
  unknown: { tone: "neutral", label: "open", tip: "Open. The code host has not said whether it can merge yet." },
};

/** prChipKey is the PR_CHIP key for a PR. */
export function prChipKey(pr: Pick<DeliveryPR, "state" | "readiness">): string {
  if (pr.state === "open") return pr.readiness && PR_CHIP[pr.readiness] ? pr.readiness : "unknown";
  return PR_CHIP[pr.state] ? pr.state : "unknown";
}

/** prChipLabel adds the merge method to a merged PR's label. */
export function prChipLabel(pr: Pick<DeliveryPR, "state" | "readiness" | "merge_method">): string {
  const key = prChipKey(pr);
  const label = PR_CHIP[key]?.label ?? key;
  return key === "merged" && pr.merge_method ? `${label} (${pr.merge_method})` : label;
}

/** LANDING_STATUS: one AI-touched commit's delivery outcome. */
export const LANDING_STATUS: Readonly<Record<string, DeliveryEntry>> = {
  in_flight: { tone: "neutral", label: "in flight", tip: "Committed recently and not pushed yet; still within the abandon window." },
  local_only: { tone: "neutral", label: "local only", tip: "Exists only on this machine: not on any remote branch you have fetched." },
  pushed: { tone: "info", label: "pushed, no PR", tip: "On a remote branch, not in a pull request the code host knows of (or no code host connected)." },
  in_pr: { tone: "info", label: "in a PR", tip: "In an open or draft pull request." },
  landed: { tone: "success", label: "landed", tip: "On the default branch, as of the last fetch or sync." },
  likely_landed: {
    tone: "neutral",
    label: "likely landed",
    tip: "Most of its added lines are on the default branch, but nothing proves it landed. Low confidence; not counted in the rate by default.",
  },
  abandoned: { tone: "warn", label: "abandoned", tip: "Its PR was closed without merging, or it was reset or rebased away and never landed." },
  landing_lost: {
    tone: "warn",
    label: "landing lost",
    tip: "It had landed, then the default branch was rewritten and it is no longer there. Kept, never deleted.",
  },
};

/** LANDING_KIND: how a landed commit landed. */
export const LANDING_KIND: Readonly<Record<string, DeliveryEntry>> = {
  exact_sha: { tone: "neutral", label: "exact sha", tip: "This exact commit is on the default branch (merge commit or fast-forward)." },
  merge: { tone: "neutral", label: "merge", tip: "Landed through a merge commit." },
  squash: { tone: "neutral", label: "squash", tip: "Landed inside a squash commit." },
  rebase: { tone: "neutral", label: "rebase", tip: "Landed through a rebase merge: a new sha with the same change." },
  patch_id: { tone: "neutral", label: "patch-id", tip: "A default-branch commit carries the same patch under a new sha (rebase or cherry-pick)." },
  squash_files: {
    tone: "neutral",
    label: "squash, files match",
    tip: "A squash commit touched every file this commit touched, but the patch differs (a conflict fixed during the merge).",
  },
  content: { tone: "neutral", label: "content overlap", tip: "Matched by added-line overlap only. Low confidence." },
};

/** CodeHostEntry is a code host state row with the action it suggests. */
export type CodeHostEntry = DeliveryEntry & { action: "none" | "test" | "reconnect" | "wait" };

/** CODE_HOST_STATUS: a code host link's state, with what to do about it. */
export const CODE_HOST_STATUS: Readonly<Record<string, CodeHostEntry>> = {
  ok: { tone: "success", label: "ok", tip: "Connected and syncing.", action: "none" },
  never_checked: { tone: "neutral", label: "not checked yet", tip: "Connected; the first sync runs within a minute.", action: "test" },
  auth_failed: {
    tone: "danger",
    label: "auth failed",
    tip: "The code host refused the credential (revoked or expired). Polling stopped; the last good data is kept.",
    action: "reconnect",
  },
  rate_limited: {
    tone: "warn",
    label: "rate limited",
    tip: "The code host is rate limiting this account. Observer waits for the reset and retries.",
    action: "wait",
  },
  unreachable: { tone: "warn", label: "unreachable", tip: "The code host could not be reached. Retrying with a growing delay.", action: "test" },
  repo_moved: {
    tone: "warn",
    label: "repo moved",
    tip: "A repository was renamed or moved. Update the remote URL in your clone (git remote set-url).",
    action: "test",
  },
  wrong_shape: { tone: "warn", label: "unexpected answer", tip: "The code host answered in a shape Observer does not read. Retrying.", action: "test" },
  disabled: { tone: "danger", label: "stopped", tip: "Stopped: the host is not on the allowed list.", action: "reconnect" },
  needs_noninteractive_credentials: {
    tone: "warn",
    label: "needs non-interactive credentials",
    tip: "git asked for a password or a key passphrase, which Observer never answers. Set up a credential helper or an SSH agent.",
    action: "test",
  },
};

/** MIRROR_STATUS: an Observer-owned mirror's state. */
export const MIRROR_STATUS: Readonly<Record<string, DeliveryEntry>> = {
  ok: { tone: "success", label: "ok", tip: "Cloned and refreshed." },
  cloning: { tone: "info", label: "cloning", tip: "The first copy is being made.", spin: true },
  failed: { tone: "danger", label: "failed", tip: "The last clone or refresh failed; see the message." },
  over_cap: { tone: "warn", label: "over cap", tip: "Not cloned: it would exceed the mirror disk cap. Delete a mirror or raise the mirror disk cap." },
  never: { tone: "neutral", label: "not cloned", tip: "Created on the next Check now or scheduled refresh." },
  needs_noninteractive_credentials: {
    tone: "warn",
    label: "needs non-interactive credentials",
    tip: "git asked for a password or a key passphrase, which Observer never answers. Set up a credential helper or an SSH agent for this remote.",
  },
};

/** DELIVERY_SOURCE: where the evidence behind a project's numbers comes from. */
export const DELIVERY_SOURCE: Readonly<Record<string, DeliveryEntry>> = {
  provider: { tone: "info", label: "code host", tip: "Pull request state comes from the code host's API; landing is also checked against your own refs." },
  mirror: { tone: "info", label: "Observer mirror", tip: "An Observer-owned copy in Observer's own data folder, refreshed by Check now or on a schedule. Your repository is never touched." },
  user_refs: { tone: "neutral", label: "local git", tip: "Your own remote-tracking refs, as fresh as your last fetch. Nothing is sent anywhere." },
  none: { tone: "neutral", label: "no remote", tip: "This repository has no remote, so there is no default branch to land on." },
};

/** entry looks a value up in a table, falling back to an honest neutral row. */
export function entry(table: Readonly<Record<string, DeliveryEntry>>, value: string | undefined | null): DeliveryEntry {
  if (value && table[value]) return table[value];
  return { tone: "neutral", label: value ?? "unknown", tip: "A state this version of the dashboard does not know." };
}

/** codeHostEntry is entry() for CODE_HOST_STATUS, keeping the action (an
 *  unknown state offers Test). */
export function codeHostEntry(value: string | undefined | null): CodeHostEntry {
  if (value && CODE_HOST_STATUS[value]) return CODE_HOST_STATUS[value];
  return { ...entry(CODE_HOST_STATUS, value), action: "test" };
}

/** SCHEDULE_OPTIONS: the mirror refresh picker (0 = Check now only; the
 *  server refuses anything under 30 minutes). `short` is the segment text
 *  on the picker; `label` is the sentence used everywhere else. */
export const SCHEDULE_OPTIONS: readonly { value: number; label: string; short?: string }[] = [
  { value: 0, label: "Only when I press Check now", short: "Check now only" },
  { value: 30, label: "Every 30 minutes", short: "30 min" },
  { value: 60, label: "Every hour", short: "1 hour" },
  { value: 120, label: "Every 2 hours", short: "2 hours" },
  { value: 360, label: "Every 6 hours", short: "6 hours" },
  { value: 720, label: "Every 12 hours", short: "12 hours" },
  { value: 1440, label: "Every day", short: "1 day" },
];

/** scheduleLabel names a stored schedule, including one set from the CLI
 *  that is not on the picker. */
export function scheduleLabel(minutes: number): string {
  const hit = SCHEDULE_OPTIONS.find((o) => o.value === minutes);
  if (hit) return hit.label;
  return minutes % 60 === 0 ? `Every ${minutes / 60} hours` : `Every ${minutes} minutes`;
}

/** rateText renders a known rate as a percentage, or null when unknown. */
export function rateText(r: DeliveryRate | undefined | null, digits = 1): string | null {
  if (!r || !r.known || !Number.isFinite(r.value)) return null;
  return `${(r.value * 100).toFixed(digits)}%`;
}

/** fmtSpan renders seconds as a short span: "45m", "19h", "1d 4h". */
export function fmtSpan(seconds: number | null | undefined): string | null {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return null;
  const m = Math.round(seconds / 60);
  if (m < 60) return `${Math.max(m, 1)}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh ? `${d}d ${rh}h` : `${d}d`;
}

/** One bar of the prompt funnel. value null means unknown: the step cannot be
 *  seen from the evidence at hand, so it is never drawn as 0. */
export type FunnelStep = { key: string; label: string; value: number | null; ofPrev: number | null; ofFirst: number };

/** funnelSteps lays out the prompt funnel with step-over-step conversion.
 *  defaultBranch names the last step ("Landed on main"). codeHost says
 *  whether a code host answered for the project: without one, "In a pull
 *  request" is unknown unless a merge subject proved a PR (in_pr > 0). */
export function funnelSteps(f: DeliveryFunnel, defaultBranch?: string, codeHost = true): FunnelStep[] {
  const prUnknown = !codeHost && f.in_pr === 0;
  const rows: [string, string, number][] = [
    ["edited", "AI-edited prompts", f.edited_prompts],
    ["committed", "Committed", f.committed],
    ["pushed", "Pushed", f.pushed],
    ["in_pr", "In a pull request", f.in_pr],
    ["landed", defaultBranch ? `Landed on ${defaultBranch}` : "Landed", f.landed],
  ];
  const first = rows[0][2];
  return rows.map(([key, label, raw], i) => {
    const unknown = prUnknown && key === "in_pr";
    const value = unknown ? null : raw;
    const prevUnknown = prUnknown && i > 0 && rows[i - 1][0] === "in_pr";
    const prev = i === 0 || unknown || prevUnknown ? null : rows[i - 1][2];
    return {
      key,
      label,
      value,
      // A step larger than the one before it (a commit that landed by an
      // exact sha or a merge subject without a known PR) is not a subset of
      // it, so it has no step-over-step rate: null, never "200%".
      ofPrev: prev == null || value == null ? null : prev > 0 && value <= prev ? value / prev : null,
      ofFirst: first > 0 && value != null ? value / first : 0,
    };
  });
}

/** One segment of the landing-mix bar. */
export type MixSegment = { key: string; label: string; value: number; tone: VocabEntry["tone"] };

/** landingMix splits the landed commits by how they landed, plus the
 *  likely-landed count shown separately (not counted unless opted in). */
export function landingMix(s: DeliverySummary): MixSegment[] {
  const likely = s.by_status["likely_landed"] ?? 0;
  const out: MixSegment[] = [
    { key: "exact", label: "Exact sha (merge commit or fast-forward)", value: s.landed_exact, tone: "accent" },
    { key: "patch", label: "Same patch, new sha (rebase merge)", value: s.landed_patch, tone: "info" },
    { key: "squash", label: "Squash merge", value: s.landed_squash, tone: "success" },
  ];
  if (likely > 0) out.push({ key: "likely", label: "Likely, content overlap (not counted)", value: likely, tone: "neutral" });
  return out;
}

/** notLandedSentence summarises the commits that have not landed. */
export function notLandedSentence(s: DeliverySummary): string | null {
  const b = s.by_status;
  const parts: string[] = [];
  const add = (n: number | undefined, text: string) => {
    if (n && n > 0) parts.push(`${n} ${text}`);
  };
  add(b["in_pr"], "in an open PR");
  add(b["pushed"], "pushed without a PR");
  add(b["local_only"], "local only");
  add(b["in_flight"], "in flight");
  add(b["abandoned"], "abandoned");
  add(b["landing_lost"], "landing lost");
  return parts.length ? `Not landed yet: ${parts.join(", ")}.` : null;
}

/** sourceSummary is the source line's plain parts, in order. */
export function sourceSummary(src: DeliverySource, rel: (iso?: string) => string): string[] {
  const parts: string[] = [];
  if (src.kind === "provider") {
    const via = src.auth_mode === "gh_cli" ? "via your gh login" : "via token";
    const who = src.repo_slug ? `${src.repo_slug} ` : "";
    parts.push(`${who}${via}${src.synced_at ? `, synced ${rel(src.synced_at)}` : ", not synced yet"}`);
  } else if (src.kind === "mirror") {
    parts.push(`Observer mirror${src.mirror_refresh_at ? `, refreshed ${rel(src.mirror_refresh_at)}` : ""}`);
  } else if (src.kind === "user_refs") {
    parts.push("Local git only");
  }
  if (src.kind !== "none") {
    parts.push(src.last_fetch_at ? `your last fetch ${rel(src.last_fetch_at)}` : "no fetch recorded yet");
  }
  if (src.default_branch) parts.push(`landed means on ${src.default_branch}`);
  return parts;
}

/** firstBlockingReason is the chip label of an open PR's readiness, or null
 *  when the PR is not blocked. */
export function firstBlockingReason(pr: Pick<DeliveryPR, "bucket" | "state" | "readiness">): string | null {
  if (pr.bucket !== "open_blocked") return null;
  return PR_CHIP[prChipKey(pr)]?.label ?? null;
}

/** facetSentence lists every readiness facet for the expanded row. */
export function facetSentence(pr: Pick<DeliveryPR, "facets">): string | null {
  const f = pr.facets ?? {};
  const parts: string[] = [];
  const checks: Record<string, string> = {
    passing: "checks passed",
    failing: "checks failing",
    pending: "checks running",
    none: "no checks",
    nonrequired_failing: "a non-required check failing",
  };
  const review: Record<string, string> = {
    approved: "approved",
    changes_requested: "changes requested",
    review_required_inferred: "review looks required (inferred)",
    none: "no reviews",
  };
  if (f.checks && checks[f.checks]) parts.push(checks[f.checks]);
  if (f.review && review[f.review]) parts.push(review[f.review]);
  if (f.conflicts === "conflicts") parts.push("merge conflicts");
  if (f.behind) parts.push("behind base");
  return parts.length ? parts.join(", ") : null;
}

/** The session card's headline. */
export type SessionHeadline = {
  kind:
    | "landed_pr"
    | "landed_local"
    | "in_review"
    | "blocked"
    | "pushed"
    | "local"
    | "closed"
    | "abandoned"
    | "mixed"
    | "pending";
  tone: "success" | "info" | "warn" | "danger" | "neutral";
  title: string;
  body: string;
  pr?: DeliveryPR;
};

/** sessionHeadline folds a session's commits into the one sentence at the
 *  top of the Commits card. Ordered rules, first match wins. */
export function sessionHeadline(
  rows: SessionDeliveryRow[],
  opts: { defaultBranch?: string; providerLinked: boolean; rel: (iso?: string) => string },
): SessionHeadline | null {
  if (rows.length === 0) return null;
  const branch = opts.defaultBranch || "the default branch";
  const evaluated = rows.filter((r) => r.evaluated && r.landing);
  if (evaluated.length === 0) {
    return {
      kind: "pending",
      tone: "neutral",
      title: "Not evaluated yet.",
      body: "Delivery is worked out after the next commit scan. Nothing to do.",
    };
  }
  const status = (r: SessionDeliveryRow) => r.landing!.status;
  const all = (s: string) => evaluated.every((r) => status(r) === s);
  const n = evaluated.length;
  const commitWord = n === 1 ? "commit" : "commits";
  const prs = new Map<number, DeliveryPR>();
  for (const r of evaluated) if (r.pr) prs.set(r.pr.id, r.pr);
  const onePR = prs.size === 1 ? [...prs.values()][0] : undefined;

  if (all("landed")) {
    if (onePR && onePR.state === "merged") {
      const how = onePR.merge_method ? ` (${onePR.merge_method})` : "";
      return {
        kind: "landed_pr",
        tone: "success",
        title: "This session's work landed.",
        body: `${n === 1 ? "Its commit is" : `All ${n} commits are`} in PR #${onePR.number}, merged ${opts.rel(onePR.merged_at)} into ${branch}${how}.`,
        pr: onePR,
      };
    }
    // Several merged PRs, each known from the code host: name them all
    // instead of picking one and calling it "read from the merge commit".
    const merged = [...prs.values()].filter((p) => p.state === "merged");
    if (prs.size > 1 && merged.length === prs.size && evaluated.every((r) => r.pr)) {
      const nums = merged.map((p) => p.number).sort((a, b) => a - b).map((x) => `#${x}`);
      const list = `${nums.slice(0, -1).join(", ")} and ${nums[nums.length - 1]}`;
      return {
        kind: "landed_pr",
        tone: "success",
        title: "This session's work landed.",
        body: `All ${n} commits reached ${branch} through ${prs.size} merged PRs: ${list}.`,
      };
    }
    const prNum = evaluated.find((r) => r.landing!.pr_number)?.landing!.pr_number;
    return {
      kind: "landed_local",
      tone: "success",
      title: `${n === 1 ? "Its commit" : `All ${n} commits`} landed on ${branch}.`,
      body: prNum
        ? `Via PR #${prNum}, read from the merge commit.`
        : opts.providerLinked
          ? "The pull request is not known."
          : "As of your last fetch. The PR number, review and checks need a code host connection.",
    };
  }
  if (onePR && (onePR.state === "open" || onePR.state === "draft") && evaluated.every((r) => r.pr?.id === onePR.id)) {
    const reason = firstBlockingReason(onePR);
    if (reason) {
      return {
        kind: "blocked",
        tone: "danger",
        title: "In review, blocked.",
        body: `PR #${onePR.number} is open and blocked: ${reason}. Opened ${opts.rel(onePR.created_at)}.`,
        pr: onePR,
      };
    }
    return {
      kind: "in_review",
      tone: "info",
      title: onePR.state === "draft" ? "In a draft PR." : "In review.",
      body: `PR #${onePR.number} is ${prChipLabel(onePR)}. Opened ${opts.rel(onePR.created_at)}.`,
      pr: onePR,
    };
  }
  if (onePR && onePR.state === "closed_unmerged" && all("abandoned")) {
    return {
      kind: "closed",
      tone: "warn",
      title: "Did not land.",
      body: `PR #${onePR.number} was closed without merging ${opts.rel(onePR.closed_at)}. None of its ${n} AI-touched ${commitWord} reached ${branch}.`,
      pr: onePR,
    };
  }
  if (all("abandoned")) {
    return { kind: "abandoned", tone: "warn", title: "Did not land.", body: `The ${commitWord} were reset or rebased away and never reached ${branch}.` };
  }
  if (all("pushed")) {
    return {
      kind: "pushed",
      tone: "info",
      title: "Pushed, no pull request.",
      body: opts.providerLinked
        ? `${n === 1 ? "The commit is" : `All ${n} commits are`} on a remote branch, not in a pull request yet.`
        : `${n === 1 ? "The commit is" : `All ${n} commits are`} on a remote branch. PR state needs a code host connection.`,
    };
  }
  if (evaluated.every((r) => status(r) === "local_only" || status(r) === "in_flight")) {
    return { kind: "local", tone: "neutral", title: "Not pushed yet.", body: `${n === 1 ? "The commit exists" : `${n} commits exist`} only on this machine.` };
  }
  const landed = evaluated.filter((r) => status(r) === "landed").length;
  return {
    kind: "mixed",
    tone: "info",
    title: `${landed} of ${n} ${commitWord} landed on ${branch}.`,
    body: "The rest are listed below with where each one is.",
  };
}

/** landingDetail is the small text after a landing's chips: the PR it came
 *  through, or why the PR is unknown. */
export function landingDetail(l: DeliveryLanding, hasPR: boolean): string | null {
  if (l.status === "landed" && !hasPR) {
    if (l.pr_number) return `via #${l.pr_number} (merge subject)`;
    if (l.kind === "patch_id" || l.kind === "rebase") return "PR unknown (rebase merge)";
    return "PR unknown";
  }
  if (l.status === "abandoned" && l.abandon_reason === "dropped") return "reset or rebased away";
  if (l.status === "likely_landed") return "low confidence";
  return null;
}
