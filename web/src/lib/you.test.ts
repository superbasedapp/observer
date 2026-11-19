import assert from "node:assert/strict";
import test from "node:test";

import {
  CONSENT_PER_SCOPE,
  accountLabel,
  avatarInitials,
  consentRows,
  costDisplayLine,
  guardBudgetLines,
  identityLabel,
  integrationSummary,
  machineSourceWords,
  multiAccountTools,
  orgBudgetLine,
  planHeadlineText,
  policyLine,
  presenceWords,
  probeWords,
  shareLines,
  shortFingerprint,
  type ConsentInputs,
} from "./you.ts";

const label = (p: string) => p.toUpperCase();

const none: ConsentInputs = {
  intel: null,
  cloud: null,
  lookup: null,
  provenance: null,
  grant: null,
  signInSeed: null,
  devcontainer: null,
  aggregate: null,
};
const byId = (rows: ReturnType<typeof consentRows>, id: string) => rows.find((r) => r.id === id)!;

test("consentRows: a failed read is unreadable, never not given", () => {
  const rows = consentRows(none, label);
  for (const id of ["org-enrichment", "cloud", "package-checks", "osv-download", "change-records", "org-grant", "sandbox-sign-in-seed", "devcontainer", "community-sharing"]) {
    assert.equal(byId(rows, id).state, "unreadable", id);
  }
  // Per-directory and per-workspace consents have no list route.
  for (const r of CONSENT_PER_SCOPE) assert.equal(byId(rows, r.id).state, "see_page");
  assert.ok(rows.every((r) => !r.withdraw));
});

test("consentRows: org enrichment and cloud", () => {
  const rows = consentRows(
    {
      ...none,
      intel: { class: "individual", active: { event: "accept", created_at: "2026-01-01T00:00:00Z", evidence_level: "titles" } },
      cloud: [
        { id: "a", purpose: "p1", created_at: "t", live: true, mode: "standing" },
        { id: "b", purpose: "p2", created_at: "t", live: false },
      ],
    },
    label,
  );
  assert.deepEqual(byId(rows, "org-enrichment").withdraw, { kind: "intel" });
  assert.equal(byId(rows, "org-enrichment").since, "2026-01-01T00:00:00Z");
  assert.deepEqual(byId(rows, "cloud:p1").withdraw, { kind: "cloud", purpose: "p1" });
  assert.equal(byId(rows, "cloud:p1").title, "Cloud Intelligence: P1");
  assert.equal(rows.some((r) => r.id === "cloud:p2"), false);
  const un = consentRows({ ...none, intel: { class: "unenrolled" }, cloud: [] }, label);
  assert.equal(byId(un, "org-enrichment").state, "not_given");
  assert.equal(byId(un, "cloud").state, "not_given");
});

test("consentRows: package checks withdraw unless the org decides", () => {
  const lookup = (managed: boolean) => ({
    managed,
    download: { accepted: true, accepted_at: "d" },
    remote: { accepted: true, accepted_at: "r" },
    remote_private: { accepted: true, accepted_at: "p" },
  });
  const own = consentRows({ ...none, lookup: lookup(false) }, label);
  assert.deepEqual(byId(own, "package-checks").withdraw, { kind: "lookup", change: { withdraw_remote: true, withdraw_private: true } });
  assert.deepEqual(byId(own, "private-package-names").withdraw, { kind: "lookup", change: { withdraw_private: true, private: "withhold" } });
  assert.equal(byId(own, "osv-download").state, "given");
  assert.equal(byId(own, "osv-download").withdraw, undefined);
  assert.equal(byId(own, "osv-download").since, "d");
  const org = consentRows({ ...none, lookup: lookup(true) }, label);
  assert.equal(byId(org, "package-checks").withdraw, undefined);
  assert.equal(byId(org, "package-checks").detail, "Set by your organization");
  const off = consentRows(
    { ...none, lookup: { managed: false, download: { accepted: false }, remote: { accepted: false }, remote_private: { accepted: false } } },
    label,
  );
  assert.equal(byId(off, "package-checks").state, "not_given");
  assert.equal(off.some((r) => r.id === "private-package-names"), false);
});

test("consentRows: records, grant, seed, dev container and aggregate", () => {
  const rows = consentRows(
    {
      ...none,
      provenance: {
        consents: [
          { root: "a", notes: true, trailer: false, given_at: "2026-03-01" },
          { root: "b", notes: false, trailer: false },
          { root: "c", notes: false, trailer: true, given_at: "2026-02-01" },
        ],
      },
      grant: { state: "governed", granted_at: "g", org_display: "Acme" },
      signInSeed: ["codex"],
      devcontainer: false,
      aggregate: { enabled: true, status: "schema_changed" },
    },
    label,
  );
  assert.equal(byId(rows, "change-records").detail, "2 repositories");
  assert.equal(byId(rows, "change-records").since, "2026-02-01");
  assert.equal(byId(rows, "org-grant").state, "given");
  assert.match(byId(rows, "org-grant").detail!, /Acme/);
  assert.equal(byId(rows, "sandbox-sign-in-seed").detail, "Always copied for: codex");
  assert.equal(byId(rows, "devcontainer").state, "not_given");
  assert.equal(byId(rows, "community-sharing").state, "not_given");
  assert.match(byId(rows, "community-sharing").detail!, /paused/);
  const ng = consentRows({ ...none, grant: { state: "ungoverned" }, provenance: { consents: [] } }, label);
  assert.equal(byId(ng, "org-grant").state, "not_given");
  assert.equal(byId(ng, "change-records").state, "not_given");
  const valid = consentRows({ ...none, aggregate: { enabled: true, status: "valid", consented_at: "c" } }, label);
  assert.equal(byId(valid, "community-sharing").state, "given");
  assert.equal(byId(valid, "community-sharing").since, "c");
});

test("accounts: label and multi-account flag", () => {
  assert.equal(accountLabel({ email: "a@b.c", name: "A" }), "a@b.c");
  assert.equal(accountLabel({ name: "A" }), "A");
  assert.equal(accountLabel({}), "Account not named");
  assert.equal(accountLabel({ key: "25c66846" }), "Account not named · 25c66846");
  const acct = { first_seen: "", last_seen: "", sessions: 1 };
  assert.deepEqual(
    multiAccountTools([
      { tool: "cursor", accounts: [acct, acct], multiple_accounts: true },
      { tool: "codex", accounts: [acct], multiple_accounts: false },
    ]),
    ["cursor"],
  );
});

test("identity and initials", () => {
  assert.equal(identityLabel(" a@b.c ", "me"), "a@b.c");
  assert.equal(identityLabel(undefined, "me"), "me");
  assert.equal(identityLabel(), "");
  assert.equal(avatarInitials("asha.kim@example.com"), "AK");
  assert.equal(avatarInitials("santosh"), "SA");
  assert.equal(avatarInitials("CORP" + String.fromCharCode(92) + "jdoe"), "JD");
  assert.equal(avatarInitials(""), "?");
});

test("words never claim more than is known", () => {
  assert.equal(presenceWords("unknown"), "Cannot tell from here");
  assert.equal(presenceWords("unavailable"), "Keychain not available here");
  assert.equal(presenceWords("weird"), "Not checked");
  assert.match(machineSourceWords("none"), /cannot be told apart/);
  assert.equal(shortFingerprint(""), "");
  assert.equal(shortFingerprint("0123456789abcdef0123"), "0123456789abcdef");
});

test("shareLines: org decisions win and unknown keys still show", () => {
  const lines = shareLines(
    { FullContent: true, RoutingSummary: false },
    { full_content: { effective: false, source: "org" }, brand_new: { effective: true, source: "you" } },
  );
  const get = (k: string) => lines.find((l) => l.key === k)!;
  assert.deepEqual([get("full_content").value, get("full_content").decidedBy], ["not shared", "your organization"]);
  assert.deepEqual([get("routing_summary").value, get("routing_summary").decidedBy], ["not shared", "you"]);
  assert.equal(get("target_action_allowlist").value, "none");
  assert.equal(get("brand_new").value, "shared");
});

test("policy and cost display lines", () => {
  assert.equal(policyLine(null), "No organization policy is in force.");
  assert.equal(
    policyLine({ active: true, version: 3, hidden_sections: ["a", "b"], read_only_sections: ["c"] }),
    "Version 3, 2 pages hidden, 1 page read-only",
  );
  assert.match(costDisplayLine({ source: "org", mode: "tokens" }), /token usage/);
  assert.match(costDisplayLine({ source: "default", mode: "usd" }), /dollar/);
  assert.match(costDisplayLine({ source: "pending" }), /Not known yet/);
  assert.equal(costDisplayLine(null), "");
});

test("orgBudgetLine never prints an amount", () => {
  const l = orgBudgetLine({ window: "monthly", period: "p", ratio: 0.826, enforcement: "hard", level: "warning", subject: "tool:cursor" });
  assert.equal(l.label, "monthly (tool cursor)");
  assert.equal(l.value, "83% of the cap, blocks at the cap");
  assert.equal(l.tone, "warn");
  assert.equal(orgBudgetLine({ window: "", period: "day", ratio: NaN, enforcement: "report", level: "ok" }).value, "not measured, report only");
});

// 2026-11-18: an org cap set to block on a machine that cannot block (observe
// mode, guard off) never reads "blocks at the cap".
test("orgBudgetLine and guardBudgetLines say what this machine does", () => {
  const w = { window: "monthly", period: "p", ratio: 42, enforcement: "hard", level: "exceeded" };
  assert.equal(orgBudgetLine({ ...w, effect: "warn_observe" }).value, "4200% of the cap, set to block, warns only on this machine");
  assert.equal(orgBudgetLine({ ...w, effect: "warn_guard_off" }).value, "4200% of the cap, set to block, warns only on this machine");
  assert.equal(orgBudgetLine({ ...w, effect: "blocks" }).value, "4200% of the cap, blocks at the cap");
  assert.equal(orgBudgetLine({ ...w, effect: "blocks_proxied" }).value, "4200% of the cap, blocks proxied requests at the cap");
  const usd = (n: number) => "$" + String(n);
  const g = { session_usd: 0, daily_usd: 10, hard: true, spend_today_usd: 4 };
  assert.deepEqual(guardBudgetLines({ ...g, guard_mode: "observe" }, true, usd, usd), [
    { label: "Daily", value: "$4 of $10, set to block, warns only on this machine" },
  ]);
  assert.deepEqual(guardBudgetLines({ ...g, guard_mode: "enforce" }, true, usd, usd), [{ label: "Daily", value: "$4 of $10, blocks at the cap" }]);
});

test("guardBudgetLines follow the display choice and skip unset caps", () => {
  const usd = (n: number) => `$${n}`;
  const tok = (n: number) => `${n} tok`;
  const g = { session_usd: 0, daily_usd: 10, hard: true, spend_today_usd: 4, weekly_tokens: 1000, usage_week_tokens: 250, monthly_tokens: 5000 };
  assert.deepEqual(guardBudgetLines(g, true, usd, tok), [{ label: "Daily", value: "$4 of $10, blocks at the cap" }]);
  assert.deepEqual(guardBudgetLines(g, false, usd, tok), [
    { label: "Weekly", value: "250 tok of 1000 tok, blocks at the cap" },
    { label: "Monthly", value: "usage not measured of 5000 tok, blocks at the cap" },
  ]);
  assert.deepEqual(guardBudgetLines({ session_usd: 0, daily_usd: 0, hard: false, spend_today_usd: 0 }, true, usd, tok), []);
});

test("planHeadlineText", () => {
  const f = (u: string, n: number) => `${n} ${u}`;
  assert.equal(planHeadlineText({ kind: "left", unit: "usd", value: 5 }, f), "5 usd left");
  assert.equal(planHeadlineText({ kind: "percent_left", unit: "x", value: 41.6 }, f), "42% left");
  assert.equal(planHeadlineText({ kind: "used_only", unit: "x", used: 3 }, f), "3 x used");
  assert.equal(planHeadlineText({ kind: "none", unit: "x" }, f), "");
  assert.equal(planHeadlineText(undefined, f), "");
});

test("integration summary counts only tools found and only probes that exist", () => {
  const s = integrationSummary([
    { tool: "a", detected: true, hooks: { registered: true }, mcp: { registered: false }, proxy: null },
    { tool: "b", detected: true, hooks: { registered: false, no_hooks: true }, mcp: { registered: true } },
    { tool: "c", detected: false, hooks: { registered: true } },
  ]);
  assert.deepEqual(s, { hooks: "1 of 1", mcp: "1 of 2", proxy: "not available", detected: 2 });
  assert.equal(probeWords(null), "not available");
  assert.equal(probeWords({ registered: true, partial: true }), "partly set up");
  assert.equal(probeWords({ registered: false }), "not set up");
  assert.equal(probeWords({ registered: false, no_hooks: true }), "no hook surface");
});

test("consentRows: community sharing not in this build is never agreed", () => {
  const rows = consentRows({ ...none, aggregate: { available: false, enabled: false } }, label);
  const row = rows.find((r) => r.id === "community-sharing");
  assert.equal(row?.state, "not_given");
  assert.equal(row?.detail, "Not in this build");
});
