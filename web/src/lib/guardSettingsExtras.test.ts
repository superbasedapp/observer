import assert from "node:assert/strict";
import { test } from "node:test";
import {
  PROMPT_DETECTOR_MODES,
  addPickerOptions,
  asOverrides,
  choiceOf,
  effectiveChoice,
  extraOverrideIds,
  removeOverride,
  setOverride,
  valueForChoice,
  type DetectorInfo,
} from "./guardSettingsExtras.ts";

const det = (id: string, cls: string, eff: string): DetectorInfo => ({
  id,
  class: cls,
  default_mode: eff,
  effective_mode: eff,
});

test("mode vocabulary mirrors the server", () => {
  assert.deepEqual([...PROMPT_DETECTOR_MODES], ["off", "warn", "ask-once", "block", "redact"]);
});

test("asOverrides", () => {
  const cases: [unknown, Record<string, string>][] = [
    [null, {}],
    [undefined, {}],
    [[], {}],
    [{ a: "warn", b: "block" }, { a: "warn", b: "block" }],
  ];
  for (const [v, want] of cases) assert.deepEqual(asOverrides(v), want);
});

test("extraOverrideIds shows config-only overrides, sorted", () => {
  assert.deepEqual(extraOverrideIds({ z: "warn", email: "off", a: "block" }, ["email"]), ["a", "z"]);
  assert.deepEqual(extraOverrideIds({}, ["email"]), []);
});

test("addPickerOptions skips fixed and already-overridden ids", () => {
  const all = [
    det("email", "pii", "warn"),
    det("zeta", "secret", "block"),
    det("alpha", "", "weird"),
    det("beta", "pii", "off"),
  ];
  const got = addPickerOptions(all, ["email"], { beta: "warn" });
  assert.deepEqual(got, [
    { id: "alpha", label: "alpha", mode: "warn" },
    { id: "zeta", label: "zeta (secret)", mode: "block" },
  ]);
});

test("set and remove are immutable", () => {
  const base = { a: "warn" };
  const s = setOverride(base, "b", "block");
  assert.deepEqual(s, { a: "warn", b: "block" });
  assert.deepEqual(base, { a: "warn" });
  assert.deepEqual(removeOverride(s, "a"), { b: "block" });
  assert.deepEqual(removeOverride(s, "nope"), s);
});

test("tri-state list model keeps null vs [] distinct", () => {
  const rows: [unknown, string][] = [
    [null, "defaults"],
    [undefined, "defaults"],
    [[], "none"],
    [["x"], "custom"],
  ];
  for (const [v, want] of rows) assert.equal(choiceOf(v), want);
  assert.equal(valueForChoice("defaults", ["x"]), null);
  assert.deepEqual(valueForChoice("none", ["x"]), []);
  assert.deepEqual(valueForChoice("custom", ["x"]), ["x"]);
  assert.deepEqual(valueForChoice("custom", null), []);
  assert.equal(effectiveChoice([], true), "custom");
  assert.equal(effectiveChoice([], false), "none");
  assert.equal(effectiveChoice(null, true), "defaults");
  assert.equal(effectiveChoice(["a"], true), "custom");
  assert.equal(JSON.stringify({ l: valueForChoice("defaults", []) }), '{"l":null}');
  assert.equal(JSON.stringify({ l: valueForChoice("none", null) }), '{"l":[]}');
});
