import assert from "node:assert/strict";
import test from "node:test";
import { modelFilterOptions, withSelectedModel } from "../../../shared/lib/modelFilterOptions.ts";

test("drops unknown / placeholder ids, sorts by turns then id", () => {
  const got = modelFilterOptions([
    { key: "claude-haiku-4-5", turn_count: 3 },
    { key: "<unknown>", turn_count: 99 },
    { key: "<synthetic>", turn_count: 5 },
    { key: "", turn_count: 1 },
    { key: "gpt-5.1", turn_count: 10 },
    { key: "claude-opus-4-7", turn_count: 10 },
    { key: "(unknown)", turn_count: 2 },
  ]);
  assert.deepEqual(
    got.map((o) => [o.model, o.turns]),
    [
      ["claude-opus-4-7", 10],
      ["gpt-5.1", 10],
      ["claude-haiku-4-5", 3],
    ],
  );
});

test("duplicate keys merge their turns", () => {
  const got = modelFilterOptions([
    { key: "gpt-5.1", turn_count: 2 },
    { key: " gpt-5.1 ", turn_count: 3 },
  ]);
  assert.deepEqual(got.map((o) => [o.model, o.turns]), [["gpt-5.1", 5]]);
});

test("type-ahead text carries the family and maker, so 'anthropic' finds a Claude id", () => {
  const [opus] = modelFilterOptions([{ key: "anthropic/claude-opus-4-7", turn_count: 1 }]);
  assert.ok(opus.searchable.includes("anthropic/claude-opus-4-7"));
  assert.ok(opus.searchable.includes("claude"));
  assert.ok(opus.searchable.includes("anthropic"));
});

test("an unmatched (stealth) id is still offered, searchable by its id only", () => {
  const [x] = modelFilterOptions([{ key: "zz-stealth-1", turn_count: 4 }]);
  assert.equal(x.model, "zz-stealth-1");
  assert.equal(x.searchable, "zz-stealth-1");
});

test("empty input yields no options", () => {
  assert.deepEqual(modelFilterOptions([]), []);
});

test("withSelectedModel keeps a selected model with no rows, flagged noData, first", () => {
  const opts = modelFilterOptions([{ key: "gpt-5.1", turn_count: 3 }]);
  const got = withSelectedModel(opts, "claude-opus-4-7", true);
  assert.equal(got.selectedMissing, true);
  assert.deepEqual(
    got.options.map((o) => [o.model, o.turns, o.noData ?? false]),
    [
      ["claude-opus-4-7", 0, true],
      ["gpt-5.1", 3, false],
    ],
  );
});

test("withSelectedModel flags nothing while loading, for all, or when present", () => {
  const opts = modelFilterOptions([{ key: "gpt-5.1", turn_count: 3 }]);
  for (const [sel, loaded] of [
    ["claude-opus-4-7", false],
    ["all", true],
    ["", true],
    ["gpt-5.1", true],
  ] as const) {
    const got = withSelectedModel(opts, sel, loaded);
    assert.equal(got.selectedMissing, false, `${sel}/${loaded}`);
    assert.equal(got.options.length, 1);
  }
});
