import { test } from "node:test";
import assert from "node:assert/strict";
import {
  appsStartNavShown,
  firstRunPageTitle,
  withAppsStart,
  FIRST_RUN_RULES,
  firstRunAction,
  firstRunNote,
  firstRunPhase,
  firstRunSteps,
  receiverNotice,
  showOnOverview,
  SDK_SNIPPETS,
  sdkSnippets,
  type FirstRunAction,
  type FirstRunFacts,
  type FirstRunPhase,
} from "./planeaFirstRun.ts";
import { parseSdkCatalog, SDK_CATALOG } from "../../../shared/lib/sdkCatalog.ts";
import catalogJSON from "../../../shared/lib/sdkCatalog.json" with { type: "json" };
import fixture from "../../../shared/lib/sdkCatalog.fixture.json" with { type: "json" };

// One case per FIRST_RUN_RULES row, in table order.
const CASES: { rule: string; facts: FirstRunFacts; want: FirstRunPhase }[] = [
  { rule: "the routes answer: it is on", facts: { component: "unknown", enabled: null, routesUp: true }, want: "on" },
  { rule: "not in this build", facts: { component: "absent", enabled: true, routesUp: false }, want: "absent" },
  { rule: "blocked on this machine", facts: { component: "blocked", enabled: false, routesUp: false }, want: "blocked" },
  { rule: "a fact is unknown", facts: { component: "available", enabled: null, routesUp: false }, want: "loading" },
  { rule: "the component is off", facts: { component: "available", enabled: true, routesUp: false }, want: "add_component_and_key" },
  { rule: "the component is on, the key is off", facts: { component: "active", enabled: false, routesUp: false }, want: "set_key" },
  { rule: "both on in config: restart", facts: { component: "active", enabled: true, routesUp: false }, want: "restart" },
];

test("every FIRST_RUN_RULES row has a case, in order", () => {
  assert.deepEqual(
    CASES.map((c) => c.rule),
    FIRST_RUN_RULES.map((r) => r.name),
  );
});

for (const c of CASES) {
  test(`first run: ${c.rule}`, () => {
    assert.equal(firstRunPhase(c.facts), c.want);
  });
}

test("an unknown component state never offers a button", () => {
  assert.equal(firstRunPhase({ component: "unknown", enabled: false, routesUp: false }), "loading");
});

test("the one consent adds the component and sets the key, in that order", () => {
  const steps = firstRunSteps("add_component_and_key");
  assert.equal(steps.length, 2);
  assert.match(steps[0], /obs component/);
  assert.match(steps[1], /observability\.enabled = true/);
  assert.deepEqual(firstRunSteps("set_key").length, 1);
  assert.deepEqual(firstRunSteps("absent"), []);
  assert.equal(firstRunNote("absent"), "");
  assert.match(firstRunNote("set_key"), /Stays on this machine\.$/);
});

// Review FR-M02: the "Your apps" card turns on through the one enable seam,
// with no restart, and its data note is the daemon's consent sentence.
test("the card's note: the seam, no restart, the daemon's consent sentence", () => {
  for (const phase of ["add_component_and_key", "set_key", "restart"] as FirstRunPhase[]) {
    const n = firstRunNote(phase, "Also sent to Acme (summaries, traces).");
    assert.match(n, /no restart/, phase);
    assert.doesNotMatch(n, /after the daemon restarts|restart the daemon/i, phase);
    assert.match(n, /Also sent to Acme \(summaries, traces\)\.$/, phase);
    assert.doesNotMatch(n, /stays on this machine/i, phase);
  }
  // Until the daemon has said, the not-enrolled sentence.
  assert.match(firstRunNote("set_key", null), /Stays on this machine\.$/);
  assert.match(firstRunNote("set_key", "  "), /Stays on this machine\.$/);
});

test("the card's action: the seam wherever a click helps, a restart only without the seam", () => {
  const rows: [FirstRunPhase, boolean | null | undefined, FirstRunAction][] = [
    ["add_component_and_key", true, "turn_on"],
    ["set_key", true, "turn_on"],
    ["restart", true, "turn_on"],
    ["restart", undefined, "turn_on"],
    ["restart", false, "restart"],
    ["add_component_and_key", false, "turn_on"],
    ["on", true, "none"],
    ["absent", true, "none"],
    ["blocked", true, "none"],
    ["loading", true, "none"],
  ];
  for (const [phase, hot, want] of rows) assert.equal(firstRunAction(phase, hot), want, `${phase} ${hot}`);
});

test("user-facing copy says machine, never node", () => {
  const text = [firstRunNote("add_component_and_key"), ...SDK_SNIPPETS.map((s) => s.code)].join("\n");
  assert.doesNotMatch(text, /\bnode\b/i);
});

test("the Overview card shows only where a click can help", () => {
  const rows: [FirstRunPhase, boolean, boolean][] = [
    ["add_component_and_key", false, true],
    ["set_key", false, true],
    ["restart", false, true],
    ["set_key", true, false],
    ["absent", false, false],
    ["blocked", false, false],
    ["loading", false, false],
    ["on", false, false],
  ];
  for (const [phase, dismissed, want] of rows) assert.equal(showOnOverview(phase, dismissed), want, `${phase} ${dismissed}`);
});

test("receiverNotice speaks only for a recorded bind failure (E-72)", () => {
  assert.equal(receiverNotice(null), null);
  assert.equal(receiverNotice(undefined), null);
  assert.equal(receiverNotice({ state: "unknown" }), null);
  assert.equal(receiverNotice({ state: "listening", http_addr: "127.0.0.1:4318" }), null);
  const n = receiverNotice({
    state: "bind_failed",
    http_addr: "127.0.0.1:4318",
    grpc_addr: "127.0.0.1:4317",
    error: "listen tcp 127.0.0.1:4318: bind: address already in use",
  });
  assert.ok(n);
  assert.equal(n.tone, "danger");
  assert.match(n.body, /HTTP 127\.0\.0\.1:4318, gRPC 127\.0\.0\.1:4317/);
  assert.match(n.body, /address already in use/);
  assert.match(n.body, /restart the daemon/);
  assert.doesNotMatch(`${n.title} ${n.body}`, /\bnode\b/i);
  assert.match(receiverNotice({ state: "bind_failed" })!.body, /could not open its port, so/);
});

// Review E-71: the persistent AI Apps item shows while the pages are not in
// the nav, after "Not now" too (it does not read the dismissal), and never
// where the organization hides AI Apps.
test("the persistent AI Apps item shows until the pages answer", () => {
  assert.equal(appsStartNavShown(false, false), true);
  assert.equal(appsStartNavShown(null, false), true);
  assert.equal(appsStartNavShown(true, false), false);
  assert.equal(appsStartNavShown(false, true), false);
});

test("withAppsStart keeps the AI Apps group's place", () => {
  const g = (id: string) => ({ id });
  const full = ["monitor", "optimize", "apps", "configure"].map(g);
  const standIn = g("apps");
  assert.deepEqual(withAppsStart(full, [g("monitor"), g("optimize"), g("configure")], standIn).map((x) => x.id), [
    "monitor",
    "optimize",
    "apps",
    "configure",
  ]);
  // A hidden earlier group does not move it.
  assert.deepEqual(withAppsStart(full, [g("monitor"), g("configure")], standIn).map((x) => x.id), [
    "monitor",
    "apps",
    "configure",
  ]);
  // The real group already shown wins.
  assert.equal(withAppsStart(full, full, { id: "apps", extra: 1 } as { id: string }).length, 4);
});

// Review E-71: on a build without AI Apps the page says the edition does not
// include it.
test("the first-run page names a missing edition", () => {
  assert.equal(firstRunPageTitle("absent"), "This edition does not include AI Apps");
  assert.equal(firstRunPageTitle("set_key"), "AI Apps is off");
});

// ------------------------------------------------------------ SDK catalog (C0)

test("the card shows one tab per SDK catalog row, in catalog order", () => {
  assert.deepEqual(
    SDK_SNIPPETS.map((s) => s.id),
    SDK_CATALOG.map((s) => s.id),
  );
  assert.deepEqual(
    SDK_SNIPPETS.map((s) => s.label),
    ["Python", "TypeScript", "Go", "Java"],
  );
  for (const s of SDK_SNIPPETS) {
    const row = SDK_CATALOG.find((r) => r.id === s.id)!;
    assert.equal(s.install, row.published ? row.installPublished : row.installCheckout, s.id);
    assert.equal(s.code, row.code, s.id);
    assert.equal(s.setup, row.setup, s.id);
    assert.match(s.code, /\b(init|Init)\(/, `${s.id}: the snippet is the init line`);
  }
});

test("a new catalog row reaches the card with no other edit", () => {
  const rows = sdkSnippets(parseSdkCatalog({ ...catalogJSON, sdks: [...catalogJSON.sdks, fixture.row] }));
  const added = rows.find((s) => s.id === fixture.row.id);
  assert.ok(added, "the fixture row is a tab");
  assert.equal(added.label, fixture.row.label);
  assert.equal(added.install, fixture.row.install_checkout);
  assert.equal(added.code, fixture.row.snippet.join("\n"));
  const flipped = sdkSnippets(parseSdkCatalog({ sdks: [{ ...fixture.row, published: true }] }));
  assert.equal(flipped[0].install, fixture.row.install_published);
});
