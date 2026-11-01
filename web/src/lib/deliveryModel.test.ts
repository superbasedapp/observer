// Pins the delivery surfaces' pure model (lib/deliveryModel.ts): every
// vocabulary value has a glyph, the PR chip key and label rules, the honesty
// rules (unknown is never 0), the funnel conversion, and one case per row of
// the session headline's ordered rules.
import assert from "node:assert/strict";
import test from "node:test";

import { VOCAB_ICONS } from "../../../shared/lib/vocabIcons.ts";
import {
  CODE_HOST_STATUS,
  DELIVERY_SOURCE,
  LANDING_KIND,
  LANDING_STATUS,
  MIRROR_STATUS,
  PR_CHIP,
  SCHEDULE_OPTIONS,
  entry,
  facetSentence,
  firstBlockingReason,
  fmtSpan,
  funnelSteps,
  landingDetail,
  landingMix,
  notLandedSentence,
  prChipKey,
  prChipLabel,
  rateText,
  scheduleLabel,
  sessionHeadline,
  sourceSummary,
} from "./deliveryModel.ts";
import type { DeliveryLanding, DeliveryPR, DeliverySummary, SessionDeliveryRow } from "./types.ts";

const TABLES: [string, keyof typeof VOCAB_ICONS, Record<string, unknown>][] = [
  ["PR_CHIP", "deliveryPR", PR_CHIP],
  ["LANDING_STATUS", "landingStatus", LANDING_STATUS],
  ["LANDING_KIND", "landingKind", LANDING_KIND],
  ["CODE_HOST_STATUS", "codeHostStatus", CODE_HOST_STATUS],
  ["MIRROR_STATUS", "mirrorStatus", MIRROR_STATUS],
  ["DELIVERY_SOURCE", "deliverySource", DELIVERY_SOURCE],
];
for (const [name, vocab, table] of TABLES) {
  test(`${name}: every value has a ${vocab} glyph and no dash in its copy`, () => {
    const glyphs = VOCAB_ICONS[vocab] as Record<string, unknown>;
    assert.deepEqual(Object.keys(table).filter((v) => !(v in glyphs)), []);
    assert.doesNotMatch(JSON.stringify(table), new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`));
  });
}

const pr = (over: Partial<DeliveryPR>): DeliveryPR => ({
  id: 1,
  link_id: 1,
  provider: "github",
  host: "github.com",
  repo_slug: "acme/app",
  number: 7,
  title: "t",
  url: "https://github.com/acme/app/pull/7",
  state: "open",
  bucket: "open_unknown",
  facets: {},
  stale: false,
  ai_commits: [],
  sessions: [],
  ...over,
});

test("prChipKey and prChipLabel: state first, readiness only for an open PR", () => {
  const cases: [Partial<DeliveryPR>, string, string][] = [
    [{ state: "merged", merge_method: "squash" }, "merged", "merged (squash)"],
    [{ state: "merged" }, "merged", "merged"],
    [{ state: "closed_unmerged" }, "closed_unmerged", "closed unmerged"],
    [{ state: "draft", readiness: "ready" }, "draft", "draft"],
    [{ state: "open", readiness: "ready" }, "ready", "mergeable"],
    [{ state: "open", readiness: "conflicts" }, "conflicts", "conflicts"],
    [{ state: "open" }, "unknown", "open"],
    [{ state: "open", readiness: "something_new" }, "unknown", "open"],
  ];
  for (const [over, key, label] of cases) {
    assert.equal(prChipKey(pr(over)), key);
    assert.equal(prChipLabel(pr(over)), label);
  }
});

test("firstBlockingReason follows the server's bucket, never re-derives it", () => {
  assert.equal(firstBlockingReason(pr({ bucket: "open_blocked", readiness: "checks_failing" })), "checks failing");
  assert.equal(firstBlockingReason(pr({ bucket: "open_ready", readiness: "ready" })), null);
  assert.equal(firstBlockingReason(pr({ bucket: "open_unknown", readiness: "unknown" })), null);
});

test("rateText: unknown is null, never 0%", () => {
  assert.equal(rateText({ known: false, value: 0, num: 0, den: 0, unknown_reason: "x" }), null);
  assert.equal(rateText(null), null);
  assert.equal(rateText({ known: true, value: 0.897, num: 52, den: 58 }), "89.7%");
  assert.equal(rateText({ known: true, value: 0, num: 0, den: 3 }), "0.0%");
});

test("fmtSpan", () => {
  const cases: [number | null, string | null][] = [
    [null, null],
    [-1, null],
    [10, "1m"],
    [45 * 60, "45m"],
    [19 * 3600, "19h"],
    [28 * 3600, "1d 4h"],
    [48 * 3600, "2d"],
  ];
  for (const [s, want] of cases) assert.equal(fmtSpan(s), want);
});

test("funnelSteps: step-over-step conversion, null when the previous step is empty", () => {
  const steps = funnelSteps({ known: true, edited_prompts: 142, committed: 96, pushed: 90, in_pr: 81, landed: 64 }, "main");
  assert.deepEqual(
    steps.map((s) => s.label),
    ["AI-edited prompts", "Committed", "Pushed", "In a pull request", "Landed on main"],
  );
  assert.equal(steps[0].ofPrev, null);
  assert.equal(Math.round((steps[1].ofPrev ?? 0) * 100), 68);
  const empty = funnelSteps({ known: true, edited_prompts: 0, committed: 0, pushed: 0, in_pr: 0, landed: 0 });
  assert.equal(empty[1].ofPrev, null);
  assert.equal(empty[4].label, "Landed");
  // Local landings without a known PR: landed exceeds "in a PR", no rate.
  const local = funnelSteps({ known: true, edited_prompts: 4, committed: 4, pushed: 3, in_pr: 1, landed: 2 }, "main");
  assert.equal(local[4].ofPrev, null);
  assert.equal(Math.round((local[2].ofPrev ?? 0) * 100), 75);
});

test("funnelSteps: without a code host and no merge-subject PR, 'In a pull request' is unknown, never 0 (0%)", () => {
  const f = { known: true, edited_prompts: 4, committed: 4, pushed: 3, in_pr: 0, landed: 2 };
  const steps = funnelSteps(f, "main", false);
  assert.equal(steps[3].key, "in_pr");
  assert.equal(steps[3].value, null);
  assert.equal(steps[3].ofPrev, null);
  assert.equal(steps[3].ofFirst, 0);
  assert.equal(steps[4].value, 2);
  assert.equal(steps[4].ofPrev, null);
  // A merge subject proved a PR: the count is real even without a code host.
  assert.equal(funnelSteps({ ...f, in_pr: 1 }, "main", false)[3].value, 1);
  // With a code host a real zero stays a zero.
  const linked = funnelSteps(f, "main", true);
  assert.equal(linked[3].value, 0);
  assert.equal(linked[3].ofPrev, 0);
});

const summary = (over: Partial<DeliverySummary> = {}): DeliverySummary => ({
  ai_commits: 10,
  by_status: { landed: 5, in_pr: 2, pushed: 1, abandoned: 2 },
  landed_exact: 2,
  landed_patch: 1,
  landed_squash: 2,
  accepted_work_rate: { known: true, value: 5 / 7, num: 5, den: 7 },
  landed_share: { known: true, value: 0.5, num: 5, den: 10 },
  pr_merge_rate: { known: false, value: 0, num: 0, den: 0, unknown_reason: "connect a provider to see this" },
  open_mergeable: { known: false, value: 0 },
  blocked_backlog: {},
  blocked_known: false,
  time_to_merge: { known: false, p50_seconds: 0, p75_seconds: 0, samples: 0 },
  funnel: { known: true, edited_prompts: 0, committed: 0, pushed: 0, in_pr: 0, landed: 0 },
  fetch_age: "<1h",
  ...over,
});

test("landingMix and notLandedSentence", () => {
  assert.deepEqual(
    landingMix(summary()).map((m) => m.value),
    [2, 1, 2],
  );
  assert.equal(landingMix(summary({ by_status: { likely_landed: 2 } })).length, 4);
  assert.equal(notLandedSentence(summary()), "Not landed yet: 2 in an open PR, 1 pushed without a PR, 2 abandoned.");
  assert.equal(notLandedSentence(summary({ by_status: { landed: 3 } })), null);
});

test("sourceSummary names the source, the fetch age and what landed means", () => {
  const rel = (iso?: string) => (iso ? "2 hours ago" : "never");
  assert.deepEqual(
    sourceSummary({ kind: "provider", auth_mode: "token", repo_slug: "acme/app", synced_at: "x", last_fetch_at: "y", default_branch: "main" }, rel),
    ["acme/app via token, synced 2 hours ago", "your last fetch 2 hours ago", "landed means on main"],
  );
  assert.deepEqual(sourceSummary({ kind: "user_refs" }, rel), ["Local git only", "no fetch recorded yet"]);
  assert.deepEqual(sourceSummary({ kind: "none" }, rel), []);
});

test("facetSentence lists every facet", () => {
  assert.equal(facetSentence(pr({ facets: { checks: "passing", review: "approved" } })), "checks passed, approved");
  assert.equal(facetSentence(pr({ facets: {} })), null);
});

test("schedule picker: 0 means Check now only; an off-picker CLI value still reads", () => {
  assert.equal(SCHEDULE_OPTIONS[0].value, 0);
  assert.ok(SCHEDULE_OPTIONS.slice(1).every((o) => o.value >= 30));
  assert.equal(scheduleLabel(60), "Every hour");
  assert.equal(scheduleLabel(45), "Every 45 minutes");
  assert.equal(scheduleLabel(180), "Every 3 hours");
});

test("entry: an unknown value is honest, neutral and raw-labelled", () => {
  assert.deepEqual(entry(LANDING_STATUS, "landed").label, "landed");
  const u = entry(MIRROR_STATUS, "brand_new");
  assert.equal(u.tone, "neutral");
  assert.equal(u.label, "brand_new");
});

const landing = (over: Partial<DeliveryLanding>): DeliveryLanding => ({
  commit_id: 1,
  sha: "abc",
  subject: "s",
  committed_at: "2026-10-15T10:00:00Z",
  reachable: true,
  status: "landed",
  session_ids: [],
  ...over,
});

test("landingDetail", () => {
  assert.equal(landingDetail(landing({ pr_number: 4118, kind: "exact_sha" }), false), "via #4118 (merge subject)");
  assert.equal(landingDetail(landing({ kind: "patch_id" }), false), "PR unknown (rebase merge)");
  assert.equal(landingDetail(landing({ kind: "squash" }), true), null);
  assert.equal(landingDetail(landing({ status: "abandoned", abandon_reason: "dropped" }), false), "reset or rebased away");
});

const row = (status: string | null, prOver?: Partial<DeliveryPR>, lOver: Partial<DeliveryLanding> = {}): SessionDeliveryRow => ({
  commit_id: Math.random(),
  sha: "abc",
  subject: "s",
  committed_at: "2026-10-15T10:00:00Z",
  reachable: true,
  owner: true,
  evaluated: status != null,
  landing: status ? landing({ status, ...lOver }) : undefined,
  pr: prOver ? pr(prOver) : undefined,
});

test("sessionHeadline: one case per ordered rule", () => {
  const opts = { defaultBranch: "main", providerLinked: true, rel: () => "2 hours ago" };
  const cases: [SessionDeliveryRow[], string][] = [
    [[row(null)], "pending"],
    [[row("landed", { state: "merged", merge_method: "squash", bucket: "merged" }), row("landed", { state: "merged", bucket: "merged" })], "landed_pr"],
    [[row("landed", undefined, { pr_number: 4118 })], "landed_local"],
    [[row("in_pr", { state: "open", readiness: "conflicts", bucket: "open_blocked" })], "blocked"],
    [[row("in_pr", { state: "open", readiness: "ready", bucket: "open_ready" })], "in_review"],
    [[row("abandoned", { state: "closed_unmerged", bucket: "closed_unmerged" })], "closed"],
    [[row("abandoned", undefined, { abandon_reason: "dropped" })], "abandoned"],
    [[row("pushed")], "pushed"],
    [[row("local_only"), row("in_flight")], "local"],
    [[row("landed"), row("pushed")], "mixed"],
  ];
  for (const [rows, kind] of cases) assert.equal(sessionHeadline(rows, opts)?.kind, kind, kind);
  assert.equal(sessionHeadline([], opts), null);
  const h = sessionHeadline([row("landed", { state: "merged", merge_method: "squash", number: 4127, bucket: "merged" })], opts)!;
  assert.equal(h.body, "Its commit is in PR #4127, merged 2 hours ago into main (squash).");
  const local = sessionHeadline([row("landed")], { ...opts, providerLinked: false })!;
  assert.match(local.body, /need a code host/);
  // Two merged PRs known from the code host: both named, no merge-commit guess.
  const two = sessionHeadline(
    [
      row("landed", { id: 2, state: "merged", merge_method: "merge", number: 131, bucket: "merged" }, { pr_number: 131 }),
      row("landed", { id: 1, state: "merged", merge_method: "squash", number: 128, bucket: "merged" }, { pr_number: 128 }),
    ],
    opts,
  )!;
  assert.equal(two.kind, "landed_pr");
  assert.equal(two.body, "All 2 commits reached main through 2 merged PRs: #128 and #131.");
});
