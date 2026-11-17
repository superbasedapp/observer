import assert from "node:assert/strict";
import test from "node:test";

import { costReliabilityNote } from "./costReliability.ts";

// Demo bug #7: the Total spend tile printed a bare "unreliable".
test("costReliabilityNote explains each reliability, one row per tag", () => {
  const rows = [
    { cost_usd: 75, reliability: "unreliable" },
    { cost_usd: 25, reliability: "accurate" },
  ];
  const cases: Array<[string | undefined, number, string]> = [
    ["unreliable", 0, "estimate: 75% from transcript tokens"],
    ["unknown", 2, "2 models without a rate ($0)"],
    ["unknown", 1, "1 model without a rate ($0)"],
    ["approximate", 0, "from transcripts, close to billed"],
    ["accurate", 0, "provider-reported usage"],
    ["", 0, "-"],
    [undefined, 0, "-"],
  ];
  for (const [overall, unknown, sub] of cases) {
    const n = costReliabilityNote(overall, rows, unknown);
    assert.equal(n.sub, sub, String(overall));
    assert.doesNotMatch(n.sub, /^unreliable$/);
  }
  const why = costReliabilityNote("unreliable", rows).tooltip;
  assert.match(why, /undercount output/);
  assert.match(why, /proxy/);
  // No cost at all: the tag is still explained, without a made-up share.
  assert.equal(costReliabilityNote("unreliable", []).sub, "includes transcript estimates");
});
