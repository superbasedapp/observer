// The Components page's selection sentence (lane UI, SBXD smaller items):
// one case per SELECTION_RULES row. A developer-edition install with no
// selection recorded must say the edition's defaults decide and how many
// components are active, never that every component is active.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SELECTION_RULES,
  baseLabel,
  componentRowAnchor,
  selectionSentence,
  selectionState,
  type ComponentsView,
  type SelectionState,
} from "./componentState.ts";

const base: ComponentsView = {
  configured: false,
  base: "all",
  add: [],
  remove: [],
  binary_distro: "full",
  components_digest: "abc",
  compiled_count: 60,
  active_count: 58,
  components: [],
  issues: [],
  restart_note: "",
};

const cases: { state: SelectionState; view: ComponentsView; want: string }[] = [
  {
    state: "org_governed",
    view: { ...base, org_managed: true, org_name: "Acme", configured: true, base: "managed", active_count: 31 },
    want: "Managed by Acme: your organization decides which components run on this machine. A local change cannot remove or narrow them; request a change from your organization. 31 of 60 components are active.",
  },
  {
    state: "recorded",
    view: { ...base, configured: true, base: "developer", add: ["terminals.sandbox"], remove: ["remote", "browser"], active_count: 24 },
    want: "Your selection starts from the developer edition's defaults, adds 1 component, removes 2 components: 24 of 60 components are active.",
  },
  {
    state: "full_build_default",
    view: base,
    want: "No selection is recorded yet, so everything in this build is selected: 58 of 60 components are active.",
  },
  {
    state: "custom_build_default",
    view: { ...base, base: "custom", binary_distro: "custom", active_count: 12, compiled_count: 20 },
    want: "No selection is recorded yet, so this custom build's defaults decide: 12 of 20 components are active. Add a component below to turn it on.",
  },
  {
    state: "edition_default",
    view: { ...base, base: "developer", binary_distro: "developer", active_count: 22 },
    want: "No selection is recorded yet, so the developer edition's defaults decide: 22 of 60 components are active. Add a component below to turn it on, or choose another base.",
  },
];

test("every selection row has a case, in table order", () => {
  assert.deepEqual(
    cases.map((c) => c.state),
    SELECTION_RULES.map((r) => r.state),
  );
});

for (const c of cases) {
  test(`selection: ${c.state}`, () => {
    assert.equal(selectionState(c.view), c.state);
    assert.equal(selectionSentence(c.view), c.want);
  });
}

test("the minimal and managed editions name themselves", () => {
  assert.match(selectionSentence({ ...base, base: "minimal" }), /the minimal edition's defaults decide/);
  assert.match(selectionSentence({ ...base, base: "managed" }), /the managed edition's defaults decide/);
});

test("an organization with no name reads as your organization", () => {
  assert.match(selectionSentence({ ...base, org_managed: true }), /^Managed by your organization:/);
});

test("a recorded selection with no deltas names only its base", () => {
  assert.equal(
    selectionSentence({ ...base, configured: true }),
    "Your selection starts from everything in this build: 58 of 60 components are active.",
  );
});

test("baseLabel", () => {
  assert.equal(baseLabel("all"), "everything in this build");
  assert.equal(baseLabel(""), "everything in this build");
  assert.equal(baseLabel("custom"), "this custom build's defaults");
  assert.equal(baseLabel("developer"), "the developer edition's defaults");
});

test("componentRowAnchor is the row's element id", () => {
  assert.equal(componentRowAnchor("terminals.sandbox"), "component-terminals.sandbox");
});
