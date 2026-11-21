import { test } from "node:test";
import assert from "node:assert/strict";
import { autoApplyBody, autoApplyChoice, autoApplyOptions, autoApplyWords } from "./updateAutoApply.ts";

// B-S7 (docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the "Update
// automatically" switch replaces "set [update].auto_apply = ...".

test("choice and body round-trip, null back to the default", () => {
  const cases: { explicit: boolean | null | undefined; choice: string; body: boolean | null }[] = [
    { explicit: true, choice: "on", body: true },
    { explicit: false, choice: "off", body: false },
    { explicit: null, choice: "default", body: null },
    { explicit: undefined, choice: "default", body: null },
  ];
  for (const c of cases) {
    const ch = autoApplyChoice(c.explicit);
    assert.equal(ch, c.choice, String(c.explicit));
    assert.deepEqual(autoApplyBody(ch), { auto_apply: c.body });
  }
});

test("the default option names the default only while nothing is written", () => {
  assert.equal(autoApplyOptions(null, true)[0].label, "Default (on)");
  assert.equal(autoApplyOptions(null, false)[0].label, "Default (off)");
  assert.equal(autoApplyOptions(true, true)[0].label, "Default");
  assert.deepEqual(autoApplyOptions(null, false).map((o) => o.id), ["default", "on", "off"]);
});

test("the words name who decided and never a config key", () => {
  const cases: { explicit: boolean | null; effective: boolean; want: RegExp }[] = [
    { explicit: true, effective: true, want: /^On, set on this node/ },
    { explicit: false, effective: false, want: /^Off, set on this node/ },
    { explicit: null, effective: true, want: /^On by default: your organization manages/ },
    { explicit: null, effective: false, want: /^Off by default/ },
  ];
  for (const c of cases) {
    const w = autoApplyWords(c.explicit, c.effective);
    assert.match(w, c.want);
    assert.doesNotMatch(w, /\[update\]|auto_apply|config/);
  }
});
