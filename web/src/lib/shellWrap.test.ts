import assert from "node:assert/strict";
import test from "node:test";

import { HONESTY_TONE, selectionKey, stateLabel } from "./shellWrap.ts";
import type { ShellWrapStatus } from "./types.ts";

const base: ShellWrapStatus = {
  goos: "linux",
  enabled: false,
  shim_dir: "/h/.observer/shims",
  observer_path: "/usr/bin/observer",
  shells: ["bash", "zsh", "fish"],
  detected_shells: null,
  planned_shells: null,
  active: false,
  in_sync: true,
  tools: null,
  rc: null,
  orphans: null,
  warnings: null,
};

test("selectionKey ignores order", () => {
  assert.equal(selectionKey(["b", "a"], ["zsh", "bash"]), selectionKey(["a", "b"], ["bash", "zsh"]));
  assert.notEqual(selectionKey(["a"], []), selectionKey(["a", "b"], []));
  assert.notEqual(selectionKey(["a"], ["bash"]), selectionKey(["a"], []));
});

test("stateLabel table", () => {
  const rows: [Partial<ShellWrapStatus>, string][] = [
    [{ enabled: true, in_sync: true }, "on"],
    [{ enabled: true, in_sync: false }, "on - files differ, re-apply"],
    [{ enabled: false, active: true }, "off - leftovers installed"],
    [{}, "off"],
  ];
  for (const [patch, want] of rows) {
    assert.equal(stateLabel({ ...base, ...patch }).text, want);
  }
});

test("every honesty value has a tone", () => {
  assert.deepEqual(Object.keys(HONESTY_TONE).sort(), ["launch_only", "proof_owed", "routed"]);
});
