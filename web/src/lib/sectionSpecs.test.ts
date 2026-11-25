// The hand-written Settings specs (pages/settings/sectionSpecs.ts) against
// the generated config schema (internal/config/schema/schema.gen.json,
// `make config-schema-build`). Every spec field names a Go config key by its
// field path (the section or group path plus the field id, e.g.
// Observer.Watch.PollIntervalSeconds), and nothing at compile time ties that
// string to a key that exists. This test does: a renamed or removed Go key
// fails here instead of leaving a form field that reads and writes nothing.
// A select's option list is also checked against the key's enum when the
// schema declares one.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { SECTION_SPECS, type FieldDef } from "../pages/settings/sectionSpecs.ts";

type Leaf = { field_path: string; kind: string; enum?: string[] };

const schema = JSON.parse(readFileSync(new URL("../../../internal/config/schema/schema.gen.json", import.meta.url), "utf8")) as {
  leaves: Leaf[];
};
const LEAVES = new Map(schema.leaves.map((l) => [l.field_path, l]));

// FIELD_RESOLUTION: the ordered ways a spec field can name a config key,
// walked top-down; the first that matches resolves the field.
const FIELD_RESOLUTION: { name: string; resolve: (fieldPath: string) => Leaf | undefined }[] = [
  // The field is a schema leaf itself.
  { name: "leaf", resolve: (fp) => LEAVES.get(fp) },
  // The field is one key of a string map (e.g. Guard.Prompt.Detectors.<id>,
  // Profiles.ByProvider.<provider>): its parent is a string_map leaf.
  {
    name: "map key",
    resolve: (fp) => {
      const parent = LEAVES.get(fp.slice(0, fp.lastIndexOf(".")));
      return parent?.kind === "string_map" ? parent : undefined;
    },
  },
];

// KNOWN_OPTION_DRIFT: select fields whose option list does not match the
// schema enum today, keyed by field path. Each entry is a real difference
// between the form and Go's validation, recorded here so the test passes
// while it is decided; remove the entry when the two agree.
const KNOWN_OPTION_DRIFT: Record<string, string> = {
  // The form offers "trace"; the schema's enum for observer.log_level is
  // debug / info / warn / error.
  "Observer.LogLevel": "the form offers trace, the schema enum does not list it",
};

type SpecField = { where: string; fieldPath: string; field: FieldDef };

function specFields(): SpecField[] {
  const out: SpecField[] = [];
  for (const [id, spec] of Object.entries(SECTION_SPECS)) {
    for (const f of spec.fields ?? []) out.push({ where: id, fieldPath: [...spec.path, f.id].join("."), field: f });
    // A group's path is absolute (it repeats the section's prefix), as
    // Settings.tsx's specFieldPaths reads it.
    for (const g of spec.groups ?? []) {
      for (const f of g.fields) out.push({ where: `${id}/${g.id}`, fieldPath: [...g.path, f.id].join("."), field: f });
    }
  }
  return out;
}

function resolveField(fieldPath: string): Leaf | undefined {
  for (const rule of FIELD_RESOLUTION) {
    const leaf = rule.resolve(fieldPath);
    if (leaf) return leaf;
  }
  return undefined;
}

test("the specs carry fields to check", () => {
  assert.ok(specFields().length > 100, "expected the Settings specs to hold over 100 fields");
});

test("every Settings spec field names a key in the generated config schema", () => {
  const missing = specFields()
    .filter((f) => !resolveField(f.fieldPath))
    .map((f) => `${f.where}: ${f.fieldPath}`);
  assert.deepEqual(missing, [], "spec fields with no config key (renamed or removed in Go?)");
});

test("a select's options match the schema enum where the schema declares one", () => {
  const drift: string[] = [];
  for (const f of specFields()) {
    const leaf = LEAVES.get(f.fieldPath);
    if (!f.field.options || !leaf?.enum) continue;
    if (f.fieldPath in KNOWN_OPTION_DRIFT) continue;
    // The order is the form's own (a presentation choice). The schema's ""
    // is the unset value (Go's default applies), which a select does not
    // offer as an option.
    const want = [...leaf.enum].filter((v) => v !== "").sort();
    const got = [...f.field.options].sort();
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      drift.push(`${f.where}: ${f.fieldPath} offers ${JSON.stringify(f.field.options)}, schema enum ${JSON.stringify(leaf.enum)}`);
    }
  }
  assert.deepEqual(drift, [], "select options that differ from the config schema enum");
});

test("every known option drift is still a drift (remove fixed entries)", () => {
  for (const fieldPath of Object.keys(KNOWN_OPTION_DRIFT)) {
    const f = specFields().find((x) => x.fieldPath === fieldPath);
    const leaf = LEAVES.get(fieldPath);
    assert.ok(f?.field.options && leaf?.enum, `${fieldPath}: no longer a select with a schema enum`);
    const want = [...leaf.enum].filter((v) => v !== "").sort();
    const got = [...f.field.options].sort();
    assert.notDeepEqual(got, want, `${fieldPath} now matches the schema: remove it from KNOWN_OPTION_DRIFT`);
  }
});
