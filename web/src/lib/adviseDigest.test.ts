import assert from "node:assert/strict";
import test from "node:test";

import { adviseDigest, DIGEST_TOP, type DigestInput } from "./adviseDigest.ts";

// A stand-in for the cost formatter seam (the page passes fmtUSD).
const money = (usd: number) => `USD ${usd.toFixed(2)}`;

const base: DigestInput = {
  window_days: 14,
  total_savings_usd: 12.5,
  total_count: 2,
  sessions_scanned: 40,
  by_category: { hygiene: 2.5, cost: 10, latency: 0 },
  suggestions: [
    { title: "Trim the balloon session", nudge: "Start a fresh session after the plan.", savings_usd: 10 },
    { title: "Turn compression on", nudge: "Open Settings > Compression.", savings_usd: 2.5 },
  ],
};

test("the digest mirrors the CLI rollup: headline, categories in order, numbered suggestions", () => {
  const d = adviseDigest(base, money);
  const lines = d.split("\n");
  assert.equal(lines[0], "# Observer advisor digest - last 14 day(s)");
  assert.match(d, /\*\*Avoidable spend: USD 12\.50\*\* across 2 suggestions \(40 sessions scanned\)\./);
  // cost before hygiene, a zero category omitted.
  assert.ok(d.indexOf("- cost: USD 10.00") < d.indexOf("- hygiene: USD 2.50"));
  assert.ok(!d.includes("latency"));
  assert.match(d, /## 1\. Trim the balloon session \(USD 10\.00\)\n\nStart a fresh session after the plan\./);
  assert.match(d, /## 2\. Turn compression on \(USD 2\.50\)/);
  assert.ok(!d.includes("more ("), "no overflow line when every suggestion is listed");
  assert.ok(d.endsWith("\n") && !d.endsWith("\n\n"));
});

test("more suggestions than the top list end with an overflow line", () => {
  const many = Array.from({ length: DIGEST_TOP + 3 }, (_, i) => ({ title: `S${i}`, nudge: "n", savings_usd: 1 }));
  const d = adviseDigest({ ...base, total_count: 25, suggestions: many }, money);
  assert.match(d, new RegExp(`## ${DIGEST_TOP}\. S${DIGEST_TOP - 1}`));
  assert.ok(!d.includes(`## ${DIGEST_TOP + 1}.`));
  assert.match(d, /…and 15 more \(the Suggestions page lists them all\)\./);
});

test("an empty report still renders the headline", () => {
  const d = adviseDigest({ ...base, total_savings_usd: 0, total_count: 0, by_category: {}, suggestions: null }, money);
  assert.match(d, /across 0 suggestions/);
  assert.ok(!d.includes("## 1."));
});
