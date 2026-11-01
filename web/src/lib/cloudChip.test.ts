import assert from "node:assert/strict";
import test from "node:test";

import { cloudChipShown, type CloudChipInput } from "./cloudChip.ts";

// WINNODE2 16b, one case per rule.
test("the Cloud chip shows only where Cloud Intelligence is offered", () => {
  const base: CloudChipInput = { sectionOffered: true, managed: false, signedIn: false, signingIn: false };
  const cases: [string, Partial<CloudChipInput>, boolean][] = [
    ["section hidden by the org or absent from the build", { sectionOffered: false, signedIn: true }, false],
    ["signed in on a managed node is reported", { managed: true, signedIn: true }, true],
    ["signing in is reported", { managed: true, signingIn: true }, true],
    ["managed, not signed in: hidden", { managed: true }, false],
    ["individual, not signed in: shown", {}, true],
  ];
  for (const [name, over, want] of cases) {
    assert.equal(cloudChipShown({ ...base, ...over }), want, name);
  }
});
