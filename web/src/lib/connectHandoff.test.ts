import assert from "node:assert/strict";
import test from "node:test";

import {
  HANDOFF_LIFETIME_MS,
  HANDOFF_RULES,
  HANDOFF_TEXT,
  TWO_DASHBOARDS_NOTE_KEY,
  connectedChipLabel,
  dashboardRolesLine,
  handoffPhase,
  handoffTeamLine,
  onlineKindOf,
  parseHandoff,
  readNoteDismissed,
  showTwoDashboardsNote,
  twoDashboardsNote,
  withArrivalIntent,
  withoutHandoff,
  writeNoteDismissed,
} from "./connectHandoff.ts";
import { surfaceLayout, type Account } from "./getStarted.ts";
import { DASHBOARD_ROLES, LOCAL_DASHBOARD_URL, asSentence } from "../../../shared/lib/twoDashboards.ts";

// connectHandoff.test.ts pins the installer's hand-off to the local
// dashboard (?connecting=1): the query, the phase rules (a failed status
// read only waits longer), the address cleanup, and the two dashboards'
// wording, which the terminal (cmd/observer/connect_request.go) and the
// online approval page (webcloud connectModel) say in the same words.

const account = (over: Partial<Account> = {}): Account => ({
  signedIn: false,
  identityKnown: true,
  connected: false,
  locked: false,
  displayName: "your dashboard",
  onlineUrl: null,
  ...over,
});

const T0 = Date.parse("2026-11-18T10:00:00Z");

test("the installer's query: connecting=1 and an optional team slug", () => {
  assert.deepEqual(parseHandoff("?connecting=1"), { team: "" });
  assert.deepEqual(parseHandoff("?connecting=1&team=acme-eu"), { team: "acme-eu" });
  assert.deepEqual(parseHandoff("?team=Acme&connecting=1"), { team: "acme" });
  // Anything that is not a slug is dropped, never shown.
  assert.deepEqual(parseHandoff("?connecting=1&team=%3Cb%3Ex"), { team: "" });
  assert.deepEqual(parseHandoff("?connecting=1&team=https://evil.example"), { team: "" });
  for (const s of ["", "?", "?connecting=0", "?connecting=true", "?team=acme"]) {
    assert.equal(parseHandoff(s), null, s);
  }
});

test("the address loses only the installer's query", () => {
  assert.equal(withoutHandoff("http://127.0.0.1:8081/?connecting=1"), "/");
  assert.equal(withoutHandoff("http://127.0.0.1:8081/?connecting=1&team=acme"), "/");
  assert.equal(withoutHandoff("http://127.0.0.1:8081/?connecting=1&team=acme&intent=apps"), "/");
  assert.equal(withoutHandoff("http://127.0.0.1:8081/?connecting=1&win=7d#top"), "/?win=7d#top");
  assert.equal(withoutHandoff("http://127.0.0.1:8081/sessions"), "/sessions");
});

// Review FR-M18: the installer's `--apps` adds &intent=apps to the hand-off
// (scripts/install.sh show_local_dashboard); the dashboard reads it.
test("the installer's arrival intent: only apps is read", () => {
  assert.deepEqual(parseHandoff("?connecting=1&intent=apps"), { team: "", intent: "apps" });
  assert.deepEqual(parseHandoff("?connecting=1&team=acme&intent=APPS"), { team: "acme", intent: "apps" });
  for (const s of ["?connecting=1&intent=coding", "?connecting=1&intent=", "?connecting=1&intent=apps2"]) {
    assert.deepEqual(parseHandoff(s), { team: "" }, s);
  }
  // Without the hand-off itself there is no intent to read.
  assert.equal(parseHandoff("?intent=apps"), null);
});

test("withArrivalIntent opens the AI apps track for this visit, and only where it can", () => {
  const coding = surfaceLayout(null);
  const apps = withArrivalIntent(coding, { team: "", intent: "apps" });
  assert.equal(apps.track, "apps");
  assert.deepEqual(apps.columns, ["apps"]);
  assert.equal(apps.switchBack, true);
  assert.equal(apps.showSwitch, false);
  // No intent, or no hand-off: the daemon's layout.
  assert.equal(withArrivalIntent(coding, { team: "" }), coding);
  assert.equal(withArrivalIntent(coding, null), coding);
  // AI Apps not available here: the coding track keeps its disabled switch.
  const unavailable = { ...coding, switchDisabled: "This edition does not include AI Apps." };
  assert.equal(withArrivalIntent(unavailable, { team: "", intent: "apps" }), unavailable);
  // A daemon decision already on AI apps or Both is kept.
  const both = { ...coding, track: "both" as const, columns: ["coding" as const, "apps" as const] };
  assert.equal(withArrivalIntent(both, { team: "", intent: "apps" }), both);
});

test("the hand-off phase: one case per rule, in order", () => {
  const h = { team: "" };
  const cases: [string, Parameters<typeof handoffPhase>[0], string][] = [
    ["no_handoff", { handoff: null, account: account({ connected: true }), startedAt: T0, now: T0 }, "none"],
    ["connected", { handoff: h, account: account({ connected: true }), startedAt: T0, now: T0 + 1000 }, "connected"],
    ["ran_out", { handoff: h, account: account(), startedAt: T0, now: T0 + HANDOFF_LIFETIME_MS + 1 }, "expired"],
    ["waiting", { handoff: h, account: account(), startedAt: T0, now: T0 + 1000 }, "waiting"],
  ];
  assert.deepEqual(
    cases.map((c) => c[0]),
    HANDOFF_RULES.map((r) => r.name),
  );
  for (const [name, input, want] of cases) {
    assert.equal(handoffPhase(input), want, name);
  }
});

test("a failed status read (the daemon restarting after the connect) only waits", () => {
  const h = { team: "" };
  // No answer yet, or the daemon down: the account is unknown, never an error.
  assert.equal(handoffPhase({ handoff: h, account: null, startedAt: T0, now: T0 + 5000 }), "waiting");
  // The last answer before the restart said not connected: still waiting.
  assert.equal(handoffPhase({ handoff: h, account: account(), startedAt: T0, now: T0 + 60_000 }), "waiting");
  // The first answer after the restart says connected.
  assert.equal(handoffPhase({ handoff: h, account: account({ connected: true }), startedAt: T0, now: T0 + 70_000 }), "connected");
  // Connected wins even after the lifetime (a late answer is still good news).
  assert.equal(
    handoffPhase({ handoff: h, account: account({ connected: true }), startedAt: T0, now: T0 + HANDOFF_LIFETIME_MS + 1 }),
    "connected",
  );
  // The wait is the request's own lifetime, 15 minutes.
  assert.equal(HANDOFF_LIFETIME_MS, 15 * 60 * 1000);
  assert.equal(handoffPhase({ handoff: h, account: null, startedAt: T0, now: T0 + HANDOFF_LIFETIME_MS }), "waiting");
});

test("the hand-off card's words", () => {
  assert.equal(
    HANDOFF_TEXT.waiting.line,
    "Approve this machine in the browser tab that just opened (or enter the code shown in your terminal). This page updates when it is connected.",
  );
  assert.match(HANDOFF_TEXT.expired.line, /try again/);
  assert.equal(handoffTeamLine({ team: "acme" }), "Connecting to the team acme.");
  assert.equal(handoffTeamLine({ team: "" }), "");
  assert.equal(handoffTeamLine(null), "");
});

test("the two dashboards are worded as the terminal words them", () => {
  // The terminal's role lines (cmd/observer/connect_request.go).
  assert.equal(DASHBOARD_ROLES.local, "everything Observer records on this computer, in full; it stays here");
  assert.equal(DASHBOARD_ROLES.personal, "a summary from each machine you connect");
  assert.equal(DASHBOARD_ROLES.team, "full detail (prompts, responses, file paths); the team's admins can read it");
  assert.equal(LOCAL_DASHBOARD_URL, "http://127.0.0.1:8081");
  assert.equal(asSentence("a b; c"), "A b; c.");
  assert.equal(asSentence("Done."), "Done.");
  assert.equal(asSentence("  "), "");

  const personal = twoDashboardsNote(account({ connected: true, displayName: "your personal dashboard", onlineUrl: "https://cloud.superbased.app/" }));
  assert.equal(personal.title, "Two dashboards");
  assert.equal(personal.local.label, "This local dashboard");
  assert.equal(personal.local.role, "Everything Observer records on this computer, in full; it stays here.");
  assert.equal(personal.online.label, "Your online dashboard");
  assert.equal(personal.online.role, "A summary from each machine you connect.");
  assert.equal(personal.online.url, "https://cloud.superbased.app/");
  assert.equal(personal.online.button, "Open your online dashboard");

  const team = twoDashboardsNote(account({ connected: true, displayName: "Acme", kind: "team", onlineUrl: null }));
  assert.equal(team.online.label, "Team dashboard: Acme");
  assert.equal(team.online.role, "Full detail (prompts, responses, file paths); the team's admins can read it.");
  assert.equal(team.online.url, null);
  assert.equal(team.online.button, "Open the team dashboard");
});

test("which online dashboard: a team, else the personal dashboard", () => {
  assert.equal(onlineKindOf(account({ kind: "team" })), "team");
  assert.equal(onlineKindOf(account({ kind: "personal" })), "personal");
  assert.equal(onlineKindOf(account()), "personal");
  assert.equal(onlineKindOf(null), "personal");
});

test("the top bar's chip and tooltip sentence", () => {
  assert.equal(connectedChipLabel(account({ displayName: "your personal dashboard" })), "Connected · personal dashboard");
  assert.equal(connectedChipLabel(account({ displayName: "Personal dashboard", kind: "personal" })), "Connected · personal dashboard");
  assert.equal(connectedChipLabel(account({ displayName: "Acme", kind: "team" })), "Connected · Acme");
  assert.equal(connectedChipLabel(account({ displayName: "Sam" })), "Connected · Sam");
  assert.equal(
    dashboardRolesLine(account()),
    "Online dashboard: a summary from each machine you connect. This local dashboard: everything Observer records on this computer, in full; it stays here.",
  );
  assert.match(dashboardRolesLine(account({ kind: "team" })), /^Team dashboard: full detail/);
});

test("the note shows once connected, until put away in this browser", () => {
  assert.equal(showTwoDashboardsNote(account({ connected: true }), false), true);
  assert.equal(showTwoDashboardsNote(account({ connected: true }), true), false);
  assert.equal(showTwoDashboardsNote(account(), false), false);
  assert.equal(showTwoDashboardsNote(null, false), false);

  const mem = new Map<string, string>();
  const store = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v) };
  assert.equal(readNoteDismissed(store), false);
  writeNoteDismissed(store);
  assert.equal(mem.get(TWO_DASHBOARDS_NOTE_KEY), "1");
  assert.equal(readNoteDismissed(store), true);

  // Storage that throws (a private window, blocked site data) never breaks
  // the page: reads as not put away, a write is dropped.
  const broken = {
    getItem: () => {
      throw new Error("blocked");
    },
    setItem: () => {
      throw new Error("blocked");
    },
  };
  assert.equal(readNoteDismissed(broken), false);
  assert.doesNotThrow(() => writeNoteDismissed(broken));
  assert.equal(readNoteDismissed(undefined), false);
  assert.doesNotThrow(() => writeNoteDismissed(null));
});
