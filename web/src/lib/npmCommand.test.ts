import assert from "node:assert/strict";
import test from "node:test";

import { npmUpdateCommand } from "./npmCommand.ts";

test("npmUpdateCommand names npm.cmd only on a Windows host", () => {
  const cases: Array<[string | null | undefined, string]> = [
    ["windows", "npm.cmd i -g @superbased/observer"],
    ["linux", "npm i -g @superbased/observer"],
    ["darwin", "npm i -g @superbased/observer"],
    [null, "npm i -g @superbased/observer"],
    [undefined, "npm i -g @superbased/observer"],
  ];
  for (const [os, want] of cases) {
    assert.equal(npmUpdateCommand(os), want, `host ${String(os)}`);
  }
});
