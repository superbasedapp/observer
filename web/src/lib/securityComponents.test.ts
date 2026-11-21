import assert from "node:assert/strict";
import test from "node:test";

import {
  appliedNote,
  buildScannerRows,
  changeFor,
  classifyFailure,
  confirmModel,
  selectionFlips,
  firstSentence,
  projectPickerOptions,
  scannerIds,
  type ComponentPreview,
} from "./securityComponents.ts";
import type { CatalogComponent, ComponentsStateResponse } from "./componentState.ts";

function comp(id: string, over: Partial<CatalogComponent> = {}): CatalogComponent {
  return {
    id,
    class: "feature",
    title: id,
    about: "First sentence. Second sentence.",
    stability: "stable",
    compiled: true,
    requires: [],
    direct_modules: [],
    surface: { listeners: [], egress: [], files_written: [], vendor_configs: [], os_integration: [], processes: [], credentials: [] },
    tables: [],
    routes: [],
    verbs: [],
    teardown: [],
    ledger: [],
    ...over,
  };
}

const catalog = {
  components: [
    comp("security"),
    comp("security.code", { title: "Code rules" }),
    comp("security.deps", { title: "Package checks" }),
    comp("security.scan.opengrep", { title: "Code rules (Opengrep)", requires: ["security.code"] }),
    comp("security.scan.scalibr", { title: "Dependency scan", requires: ["security.deps"] }),
    comp("security.scan.zzz", { title: "New one", requires: ["security.deps"], about: "Does a thing. More." }),
    comp("security.scan.kics", { title: "KICS", compiled: false, requires: ["security.code"] }),
    comp("security.githooks", { title: "Git hooks" }),
    comp("security.reach.go", { title: "Go reach" }),
  ],
};

function state(over: Partial<ComponentsStateResponse> = {}): ComponentsStateResponse {
  const row = (id: string, st: "active" | "available" | "absent" | "blocked") => ({
    id,
    state: st,
    reason: st === "blocked" ? "needs a thing" : "",
    compiled: st !== "absent",
    selected: st === "active",
    in_base: true,
  });
  return {
    wired: true,
    view: {
      configured: true,
      base: "developer",
      add: [],
      remove: [],
      binary_distro: "full",
      components_digest: "x",
      compiled_count: 8,
      active_count: 4,
      components: [
        row("security.code", "active"),
        row("security.deps", "active"),
        row("security.scan.opengrep", "active"),
        row("security.scan.scalibr", "active"),
        row("security.scan.zzz", "available"),
        row("security.scan.kics", "absent"),
        row("security.reach.go", "blocked"),
      ],
      issues: [],
      restart_note: "Restart to finish.",
    },
    started_active: null,
    pending: [],
    inactive_routes: [],
    purgeable: [],
    security_selected: ["security.code", "security.deps", "security.scan.scalibr"],
    ...over,
  };
}

test("the scanner set is the scan rows, what they require, and the extras, in display order", () => {
  assert.deepEqual(scannerIds(catalog.components), [
    "security.deps",
    "security.scan.scalibr",
    "security.scan.kics",
    "security.scan.opengrep",
    "security.code",
    "security.reach.go",
    "security.scan.zzz",
  ]);
});

test("the module root and unrelated security rows are not scanners", () => {
  const ids = scannerIds(catalog.components);
  assert.ok(!ids.includes("security"));
  assert.ok(!ids.includes("security.githooks"));
});

test("on follows the daemon's selection list, not just the resolved state", () => {
  const rows = buildScannerRows(catalog, state());
  const by = Object.fromEntries(rows.map((r) => [r.id, r]));
  assert.equal(by["security.scan.scalibr"].on, true);
  // active in the resolved state but not selected by a block: off
  assert.equal(by["security.scan.opengrep"].on, false);
  assert.equal(by["security.scan.zzz"].on, false);
});

test("an older daemon with no selection list falls back to the resolved state", () => {
  const rows = buildScannerRows(catalog, state({ security_selected: undefined }));
  assert.equal(rows.find((r) => r.id === "security.scan.opengrep")?.on, true);
});

test("a component not in this build shows why and has no switch", () => {
  const kics = buildScannerRows(catalog, state()).find((r) => r.id === "security.scan.kics");
  assert.equal(kics?.switchable, false);
  assert.match(kics?.whyNot ?? "", /does not include/);
  assert.equal(kics?.pills[0].text, "Not in this build");
});

test("a blocked component has no switch and carries the reason", () => {
  const r = buildScannerRows(catalog, state()).find((x) => x.id === "security.reach.go");
  assert.equal(r?.switchable, false);
  assert.equal(r?.whyNot, "needs a thing");
});

test("no loaded state means no switch, not a guess", () => {
  const rows = buildScannerRows(catalog, null);
  assert.ok(rows.every((r) => r.switchable === false || r.pills[0].text === "Not in this build"));
});

test("pending changes and beta show as pills", () => {
  const rows = buildScannerRows(
    catalog,
    state({ pending: [{ id: "security.scan.scalibr", change: "deactivate" }] }),
    [{ component: "security.scan.opengrep", beta: true, platform: "Windows" }],
  );
  assert.ok(rows.find((r) => r.id === "security.scan.scalibr")?.pills.some((p) => p.text === "Off after restart"));
  assert.ok(rows.find((r) => r.id === "security.scan.opengrep")?.pills.some((p) => p.text === "Beta on Windows"));
});

test("an unnamed scanner gets the first sentence of its catalog text", () => {
  assert.equal(buildScannerRows(catalog, state()).find((r) => r.id === "security.scan.zzz")?.line, "Does a thing.");
  assert.equal(firstSentence("No end"), "No end");
});

test("a switch sends add to turn on and remove to turn off", () => {
  assert.deepEqual(changeFor("security.scan.osv", true), { add: ["security.scan.osv"] });
  assert.deepEqual(changeFor("security.scan.osv", false), { remove: ["security.scan.osv"] });
});

const basePreview: ComponentPreview = {
  activated: [],
  deactivated: [],
  cascade: [],
  teardown: [],
  refused: [],
  issues: [],
  restart_required: false,
  fingerprint: "fp1",
  no_change: false,
};

test("turning on lists what else turns on and says installs are separate", () => {
  const m = confirmModel(
    { ...basePreview, activated: ["security.scan.opengrep", "security.code"], restart_required: true },
    { id: "security.scan.opengrep", name: "Code rules", turnOn: true },
    (id) => (id === "security.code" ? "Code rules base" : id),
  );
  assert.equal(m.title, "Turn on Code rules?");
  assert.equal(m.sections[0].heading, "Turns on");
  assert.deepEqual(m.sections[1].items, ["Code rules base"]);
  assert.ok(m.notes.some((n) => /separate step/.test(n)));
  assert.ok(m.notes.some((n) => /restarts/.test(n)));
  assert.equal(m.canApply, true);
});

test("turning off lists dependants and the teardown", () => {
  const m = confirmModel(
    {
      ...basePreview,
      deactivated: ["security.deps"],
      cascade: ["security.scan.scalibr"],
      teardown: [{ what: "Remove the git hook", command: "observer x" }],
    },
    { id: "security.deps", name: "Package checks", turnOn: false },
  );
  assert.equal(m.sections[0].heading, "Turns off");
  assert.ok(m.sections.some((s) => s.heading.startsWith("Also turned off") && s.items.includes("security.scan.scalibr")));
  assert.ok(m.sections.some((s) => s.heading === "Undone on your machine" && s.items[0].includes("observer x")));
  assert.equal(m.notes.length, 0);
});

test("an org-managed refusal blocks the apply and is listed", () => {
  const m = confirmModel(
    { ...basePreview, deactivated: ["security.deps"], managed_by: "Acme", managed_refused: ["remove security.deps"] },
    { id: "security.deps", name: "Package checks", turnOn: false },
  );
  assert.equal(m.canApply, false);
  assert.equal(m.blockedReason, "Your organization manages this setting.");
  assert.ok(m.sections.some((s) => s.heading === "Your organization refuses"));
});

test("a fully refused or empty preview cannot be applied", () => {
  const refused = confirmModel({ ...basePreview, refused: ["x: no"] }, { id: "x", name: "X", turnOn: true });
  assert.equal(refused.canApply, false);
  const none = confirmModel({ ...basePreview, no_change: true }, { id: "x", name: "X", turnOn: true });
  assert.equal(none.blockedReason, "Nothing changes.");
});

// The throwaway-daemon finding (2026-11-06): a full build with no
// [components] block already activates Opengrep, yet the opt-in switch is off
// until the list names it. The preview then activates nothing, and the
// dialog must still say what turns on rather than "Nothing changes".
test("an opt-in scanner already active in the base set still reads as turning on or off", () => {
  const on = confirmModel(
    { ...basePreview, current: { Distro: "", Add: [], Remove: [] }, proposed: { Distro: "", Add: ["security.scan.opengrep"], Remove: [] } },
    { id: "security.scan.opengrep", name: "Code rules (Opengrep)", turnOn: true },
    () => "Code rules (Opengrep)",
  );
  assert.deepEqual(on.sections[0], { heading: "Turns on", items: ["Code rules (Opengrep)"], tone: undefined });
  assert.equal(on.canApply, true);
  const off = confirmModel(
    { ...basePreview, current: { Add: ["security.scan.opengrep"] }, proposed: { Add: [], Remove: ["security.scan.opengrep"] } },
    { id: "security.scan.opengrep", name: "Code rules (Opengrep)", turnOn: false },
  );
  assert.equal(off.sections[0].heading, "Turns off");
  assert.equal(selectionFlips({ ...basePreview, current: { Add: ["a"] }, proposed: { Add: ["a"] } }, "a"), false);
  assert.equal(selectionFlips(basePreview, "a"), false);
});

test("a preview with no fingerprint cannot be applied", () => {
  const m = confirmModel({ ...basePreview, activated: ["a"], fingerprint: "" }, { id: "a", name: "A", turnOn: true });
  assert.equal(m.canApply, false);
});

test("apply failures are classified from the body", () => {
  const stale = classifyFailure(JSON.stringify({ error: "stale_preview", message: "m", preview: basePreview }), "fb");
  assert.equal(stale.kind, "stale");
  assert.equal(stale.preview?.fingerprint, "fp1");
  assert.equal(classifyFailure(JSON.stringify({ error: "managed_by_org", message: "m" }), "fb").kind, "managed");
  assert.equal(classifyFailure(JSON.stringify({ error: "apply_refused", message: "nope" }), "fb").message, "nope");
  assert.deepEqual(classifyFailure("not json", "fb"), { kind: "other", message: "fb" });
});

test("the applied note carries the restart note only when one is needed", () => {
  assert.equal(appliedNote(true, "Trivy", "Restart.", false), "Trivy is on.");
  assert.equal(appliedNote(false, "Trivy", "Restart.", true), "Trivy is off. Restart.");
});

test("the project picker lists active projects first, then idle, keeping each group's order", () => {
  const opts = projectPickerOptions([
    { project_root_hash: "a", label: "a", active: false },
    { project_root_hash: "b", label: "b", active: true },
    { project_root_hash: "c", label: "c", active: false },
    { project_root_hash: "d", label: "d", active: true },
  ]);
  assert.deepEqual(opts.map((o) => o.id), ["b", "d", "a", "c"]);
  assert.equal(opts[0].group, "Active projects");
  assert.equal(opts[2].group, "Idle projects");
});

test("a project list with no activity flags keeps its order and has no groups", () => {
  const opts = projectPickerOptions([
    { project_root_hash: "x", label: "x" },
    { project_root_hash: "y", label: "y" },
  ]);
  assert.deepEqual(opts, [{ id: "x", label: "x" }, { id: "y", label: "y" }]);
});
