// Pins the one mapping of a stored revoke reason to the developer's words
// (round-3 demo wording: an extension reads "replaced by G-<n>").
import { test } from "node:test";
import assert from "node:assert/strict";
import { replacedBy, revokeReasonWords } from "./grantRevokeReason.ts";

test("only an extension's exact reason reads replaced", () => {
  const cases: { reason: string | undefined; by: string | undefined; words?: string }[] = [
    { reason: "superseded by G-6", by: "G-6", words: "replaced by G-6" },
    { reason: "superseded by G-1234", by: "G-1234", words: "replaced by G-1234" },
    { reason: " superseded by G-6 ", by: "G-6", words: "replaced by G-6" },
    // A server that already words it "replaced by" reads the same.
    { reason: "replaced by G-7", by: "G-7", words: "replaced by G-7" },
    { reason: "superseded by the new policy", by: undefined, words: "superseded by the new policy" },
    { reason: "superseded by G-6 because of a typo", by: undefined, words: "superseded by G-6 because of a typo" },
    { reason: "Superseded by G-6", by: undefined, words: "Superseded by G-6" },
    { reason: "budget deleted", by: undefined, words: "budget deleted" },
    { reason: "", by: undefined, words: "" },
    { reason: undefined, by: undefined },
  ];
  for (const c of cases) {
    assert.equal(replacedBy(c.reason), c.by, String(c.reason));
    if (c.reason !== undefined) assert.equal(revokeReasonWords(c.reason), c.words, c.reason);
  }
});
