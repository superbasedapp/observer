// Pins the density table (shared/lib/density.ts), its parse + storage helpers,
// and the tokens it depends on: every --density-* token must be defined in
// BOTH the default (comfortable) block and the compact block of
// shared/styles/tokens.css, and each app's index.html pre-paint script must
// read the same storage key the React side writes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  DENSITY,
  DENSITY_MODES,
  DENSITY_STORAGE_KEY,
  DENSITY_TOKENS,
  DEFAULT_DENSITY,
  applyDensity,
  densityRow,
  densityStorageKey,
  parseDensity,
  readDensity,
  writeDensity,
  type DensityApp,
  type DensityMode,
  type DensityStorage,
} from "../../../shared/lib/density.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (rel: string) => readFileSync(path.join(root, rel), "utf8");

// One case per table row.
const ROWS: { mode: DensityMode; label: string }[] = [
  { mode: "comfortable", label: "Comfortable" },
  { mode: "compact", label: "Compact" },
];

test("DENSITY has exactly the expected rows, in order", () => {
  assert.deepEqual(
    DENSITY.map((r) => r.mode),
    ROWS.map((r) => r.mode),
  );
  assert.deepEqual([...DENSITY_MODES], ROWS.map((r) => r.mode));
  assert.equal(DEFAULT_DENSITY, "comfortable");
  assert.equal(DENSITY[0].mode, DEFAULT_DENSITY, "the default is the first row");
});

for (const row of ROWS) {
  test(`DENSITY row ${row.mode}`, () => {
    const r = densityRow(row.mode);
    assert.equal(r.mode, row.mode);
    assert.equal(r.label, row.label);
    assert.ok(r.icon, "has an icon");
    assert.ok(r.description.length > 0, "has a description");
    assert.ok(!/—/.test(r.label + r.description), "no em-dash in copy");
    assert.equal(parseDensity(row.mode), row.mode);
  });
}

test("DENSITY icons are distinct", () => {
  assert.equal(new Set(DENSITY.map((r) => r.icon)).size, DENSITY.length);
});

test("densityRow(null) is the default row", () => {
  assert.equal(densityRow(null).mode, DEFAULT_DENSITY);
});

const JUNK: unknown[] = [
  null,
  undefined,
  "",
  " ",
  "Compact",
  "COMPACT",
  " compact",
  "compact ",
  "dense",
  "cozy",
  "1",
  0,
  1,
  true,
  {},
  ["compact"],
];
for (const j of JUNK) {
  test(`parseDensity(${JSON.stringify(j) ?? String(j)}) is unknown -> null`, () => {
    assert.equal(parseDensity(j), null);
  });
}

function fakeStorage(init: Record<string, string> = {}): DensityStorage & { data: Record<string, string> } {
  const data = { ...init };
  return {
    data,
    getItem: (k: string) => (k in data ? data[k] : null),
    setItem: (k: string, v: string) => {
      data[k] = v;
    },
  };
}

const THROWING: DensityStorage = {
  getItem: () => {
    throw new Error("SecurityError");
  },
  setItem: () => {
    throw new Error("QuotaExceededError");
  },
};

test("readDensity: empty storage -> default", () => {
  assert.equal(readDensity(fakeStorage(), "k"), DEFAULT_DENSITY);
});
test("readDensity: missing storage -> default", () => {
  assert.equal(readDensity(null, "k"), DEFAULT_DENSITY);
  assert.equal(readDensity(undefined, "k"), DEFAULT_DENSITY);
});
test("readDensity: throwing storage -> default", () => {
  assert.equal(readDensity(THROWING, "k"), DEFAULT_DENSITY);
});
test("readDensity: junk value -> default", () => {
  assert.equal(readDensity(fakeStorage({ k: "Compact" }), "k"), DEFAULT_DENSITY);
});
test("readDensity: stored compact -> compact", () => {
  assert.equal(readDensity(fakeStorage({ k: "compact" }), "k"), "compact");
});
test("writeDensity round-trips through readDensity", () => {
  const s = fakeStorage();
  assert.equal(writeDensity(s, "k", "compact"), true);
  assert.equal(s.data.k, "compact");
  assert.equal(readDensity(s, "k"), "compact");
});
test("writeDensity: throwing or missing storage -> false, no throw", () => {
  assert.equal(writeDensity(THROWING, "k", "compact"), false);
  assert.equal(writeDensity(null, "k", "compact"), false);
});

test("applyDensity stamps data-density; tolerates no document", () => {
  const doc = { documentElement: { dataset: {} as DOMStringMap } };
  applyDensity(doc, "compact");
  assert.equal(doc.documentElement.dataset.density, "compact");
  applyDensity(doc, "comfortable");
  assert.equal(doc.documentElement.dataset.density, "comfortable");
  applyDensity(null, "compact");
});

// Storage keys follow each app's theme-key family.
const KEYS: { app: DensityApp; key: string; html: string }[] = [
  { app: "web", key: "superbased.density", html: "web/index.html" },
  { app: "web2", key: "superbased.org.density", html: "web2/index.html" },
  { app: "webcloud", key: "sb_density", html: "webcloud/index.html" },
];
test("DENSITY_STORAGE_KEY has exactly one row per app", () => {
  assert.deepEqual(Object.keys(DENSITY_STORAGE_KEY).sort(), KEYS.map((k) => k.app).sort());
});
for (const k of KEYS) {
  test(`storage key + pre-paint for ${k.app}`, () => {
    assert.equal(densityStorageKey(k.app), k.key);
    const html = read(k.html);
    assert.ok(
      html.includes(`localStorage.getItem("${k.key}")`),
      `${k.html} pre-paint must read ${k.key}`,
    );
    assert.ok(html.includes('"data-density"'), `${k.html} must stamp data-density`);
  });
}

// tokens.css: every density token in both blocks.
function block(css: string, selectorRe: RegExp): string {
  const m = selectorRe.exec(css);
  assert.ok(m, `selector ${selectorRe} not found in tokens.css`);
  const start = css.indexOf("{", m!.index);
  const end = css.indexOf("}", start);
  return css.slice(start + 1, end);
}
function decls(body: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of body.matchAll(/(--density-[a-z0-9-]+)\s*:\s*([^;]+);/g)) out.set(m[1], m[2].trim());
  return out;
}

test("tokens.css defines every density token in the default and compact blocks", () => {
  const css = read("shared/styles/tokens.css");
  const def = decls(block(css, /^:root\[data-density="comfortable"\]\s*\{/m));
  const compact = decls(block(css, /^:root\[data-density="compact"\]\s*\{/m));
  assert.deepEqual([...def.keys()].sort(), [...DENSITY_TOKENS].sort(), "default block tokens");
  assert.deepEqual([...compact.keys()].sort(), [...DENSITY_TOKENS].sort(), "compact block tokens");
  for (const t of DENSITY_TOKENS) {
    const d = parseFloat(def.get(t)!);
    const c = parseFloat(compact.get(t)!);
    assert.ok(Number.isFinite(d) && Number.isFinite(c), `${t} is a px length`);
    assert.ok(c <= d, `${t}: compact (${c}) must not be roomier than comfortable (${d})`);
  }
});

// Comfortable must equal the pre-density rendering exactly: these are the
// Tailwind classes the consumers used before (py-1.5 = 6px, py-2 = 8px,
// px-2 = 8px, px-1.5 = 6px, p-4 = 16px, px-4 = 16px, py-3 = 12px,
// min-h-[104px]).
test("comfortable token values equal the pre-density classes", () => {
  const css = read("shared/styles/tokens.css");
  const def = decls(block(css, /^:root\[data-density="comfortable"\]\s*\{/m));
  assert.deepEqual(Object.fromEntries(def), {
    "--density-row-y": "6px",
    "--density-head-y": "8px",
    "--density-cell-x": "8px",
    "--density-cell-x-num": "6px",
    "--density-card-pad": "16px",
    "--density-stat-x": "16px",
    "--density-stat-y": "12px",
    "--density-stat-min-h": "104px",
  });
});

test("the Tailwind preset exposes every density token", () => {
  const preset = read("shared/styles/tailwind-preset.ts");
  for (const t of DENSITY_TOKENS) {
    assert.ok(preset.includes(`var(${t})`), `preset must map ${t}`);
  }
});
