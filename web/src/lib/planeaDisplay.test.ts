// planeaDisplay.test - the AI Apps display rules from the 2026-11-21 design
// review: a real sub-cent cost never reads "$0.00" (usdFine, fmtCostFine),
// an eval run's scorers resolve to chips from every stored shape
// (parseScorers), and every closed AI Apps vocabulary value has a label and
// a glyph (never the raw wire value).
import { test } from "node:test";
import assert from "node:assert/strict";
import { fmtCostFine, setCostDisplayMode, usdFine } from "../../../shared/lib/format.ts";
import { parseScorers, scorerLabel } from "../../../shared/components/planea/scorers.ts";
import { SCORE_KIND, SCORE_SOURCE, TRACE_SOURCE } from "../../../shared/lib/obsVocab.ts";
import { VOCAB_ICONS } from "../../../shared/lib/vocabIcons.ts";

test("usdFine: adaptive precision, a real sub-cent amount never rounds to zero", () => {
  const rows: [number, string][] = [
    [0, "$0.00"],
    [0.0000202, "<$0.0001"],
    [0.00005, "$0.0001"],
    [0.0023, "$0.0023"],
    [0.5, "$0.5000"],
    [1, "$1.00"],
    [12.345, "$12.35"],
    [1234.5, "$1,235"],
    [-2.5, "-$2.50"],
  ];
  for (const [n, want] of rows) assert.equal(usdFine(n), want, String(n));
});

test("fmtCostFine: dollars by default, tokens when the org chose token usage", () => {
  assert.equal(fmtCostFine(0.0023, 900), "$0.0023");
  assert.equal(fmtCostFine(null), "—");
  setCostDisplayMode("tokens");
  try {
    assert.equal(fmtCostFine(0.0023, 900), "900 tok");
  } finally {
    setCostDisplayMode("usd");
  }
});

test("parseScorers: every stored shape resolves to name and version", () => {
  assert.deepEqual(parseScorers('[{"name":"exact_match","version":"1"}]'), [{ name: "exact_match", version: "1" }]);
  assert.deepEqual(parseScorers(["a", "b"]), [{ name: "a" }, { name: "b" }]);
  assert.deepEqual(parseScorers("a, b"), [{ name: "a" }, { name: "b" }]);
  assert.deepEqual(parseScorers({ name: "x", version: 2 }), [{ name: "x", version: "2" }]);
  assert.deepEqual(parseScorers("[not json"), []);
  assert.deepEqual(parseScorers(""), []);
  assert.deepEqual(parseScorers(null), []);
  assert.equal(scorerLabel({ name: "exact_match", version: "1" }), "exact_match v1");
  assert.equal(scorerLabel({ name: "len" }), "len");
});

test("AI Apps vocabularies: every value has a glyph in its shared icon table", () => {
  for (const def of [TRACE_SOURCE, SCORE_SOURCE, SCORE_KIND]) {
    const table = VOCAB_ICONS[def.vocab!] as Record<string, unknown>;
    for (const key of Object.keys(def.entries)) assert.ok(table[key], `${def.vocab}.${key}`);
  }
  assert.equal(TRACE_SOURCE.entries.otlp_trace.label, "OpenTelemetry");
});
