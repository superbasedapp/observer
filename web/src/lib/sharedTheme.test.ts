// T-463: one owner for the theme preference (shared/lib/theme.ts). The
// per-app differences are rows of THEME_APPS; the app files only bind a row.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  THEME_APPS,
  themePrepaintBlock,
  themePrepaintScript,
  parseThemeMode,
  queryThemeMode,
  readThemeMode,
  resolveEffective,
  writeThemeMode,
  type ThemeApp,
} from "../../../shared/lib/theme.ts";

const repo = fileURLToPath(new URL("../../../", import.meta.url));

// [app, storage key, modes, fallback, honours ?theme=, how "system" is stored]
// webcloud (hosted sign-in fix, lane A): light / dark / system, system the
// default, "system" stored as an ABSENT sb_theme key (the marketing site
// reads only light / dark and follows the OS otherwise).
const ROWS: Array<[ThemeApp, string, string[], string, boolean, string]> = [
  ["web", "superbased.theme", ["light", "dark", "system"], "system", false, "value"],
  ["web2", "superbased.org.theme", ["light", "dark", "system"], "system", false, "value"],
  ["webcloud", "sb_theme", ["light", "dark", "system"], "system", true, "absent"],
];

for (const [app, key, modes, fallback, query, systemStorage] of ROWS) {
  test(`theme row ${app}: key, modes, fallback, query override and system storage are the contract`, () => {
    const row = THEME_APPS[app];
    assert.equal(row.storageKey, key);
    assert.deepEqual([...row.modes], modes);
    assert.equal(row.fallback, fallback);
    assert.equal(row.queryOverride, query);
    assert.equal(row.systemStorage, systemStorage);
  });
}

function mem(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init));
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    m,
  };
}

test("readThemeMode: stored value, unknown value, missing value, throwing storage", () => {
  assert.equal(readThemeMode(mem({ "superbased.theme": "light" }), THEME_APPS.web), "light");
  assert.equal(readThemeMode(mem({ "superbased.theme": "sepia" }), THEME_APPS.web), "system");
  // The portal's default is system: an absent sb_theme follows the OS.
  assert.equal(readThemeMode(mem(), THEME_APPS.webcloud), "system");
  assert.equal(readThemeMode(mem({ sb_theme: "light" }), THEME_APPS.webcloud), "light");
  assert.equal(readThemeMode(mem({ sb_theme: "sepia" }), THEME_APPS.webcloud), "system");
  const boom = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } };
  assert.equal(readThemeMode(boom, THEME_APPS.web2), "system");
  writeThemeMode(boom, THEME_APPS.web2, "dark"); // must not throw
});

test("writeThemeMode writes the app's own key", () => {
  const s = mem();
  writeThemeMode(s, THEME_APPS.web2, "light");
  assert.equal(s.m.get("superbased.org.theme"), "light");
  assert.equal(s.m.get("superbased.theme"), undefined);
});

test("webcloud stores system by removing sb_theme, never by writing a value the website does not read", () => {
  const s = mem({ sb_theme: "dark" });
  writeThemeMode(s, THEME_APPS.webcloud, "system");
  assert.equal(s.m.has("sb_theme"), false);
  assert.equal(readThemeMode(s, THEME_APPS.webcloud), "system");
  writeThemeMode(s, THEME_APPS.webcloud, "light");
  assert.equal(s.m.get("sb_theme"), "light");
  // Only light / dark are ever written to the shared key.
  for (const mode of THEME_APPS.webcloud.modes) {
    const t = mem();
    writeThemeMode(t, THEME_APPS.webcloud, mode);
    const v = t.m.get("sb_theme");
    assert.ok(v === undefined || v === "light" || v === "dark", `${mode} wrote ${v}`);
  }
  // A row that stores "system" as a value still does.
  const w = mem();
  writeThemeMode(w, THEME_APPS.web, "system");
  assert.equal(w.m.get("superbased.theme"), "system");
});

test("queryThemeMode: only where the app honours it, only offered modes", () => {
  assert.equal(queryThemeMode("?theme=light", THEME_APPS.webcloud), "light");
  assert.equal(queryThemeMode("?theme=system", THEME_APPS.webcloud), null);
  assert.equal(queryThemeMode("?theme=light", THEME_APPS.web), null);
  assert.equal(queryThemeMode("", THEME_APPS.webcloud), null);
});

test("resolveEffective and parseThemeMode", () => {
  assert.equal(resolveEffective("system", true), "dark");
  assert.equal(resolveEffective("system", false), "light");
  assert.equal(resolveEffective("light", true), "light");
  assert.equal(parseThemeMode("dark", THEME_APPS.web), "dark");
  assert.equal(parseThemeMode(3, THEME_APPS.web), null);
});

test("the app theme files bind a row only (no storage logic of their own)", () => {
  for (const f of ["web/src/lib/theme.tsx", "web2/src/lib/theme.tsx", "webcloud/src/theme.ts", "webcloud/src/components/ThemeToggle.tsx"]) {
    const src = readFileSync(repo + f, "utf8");
    assert.doesNotMatch(src, /localStorage|matchMedia|setAttribute/, f);
    assert.match(src, /@shared\/(lib\/useTheme|primitives\/ThemeToggle)/, f);
  }
});

// T-551: each app's pre-paint theme script is the generated output for its
// THEME_APPS row, byte for byte. To change it, change the row, then paste the
// "want" block this test prints into the index.html.
const HTML: Record<ThemeApp, string> = { web: "web/index.html", web2: "web2/index.html", webcloud: "webcloud/index.html" };
for (const app of Object.keys(THEME_APPS) as ThemeApp[]) {
  test(`${HTML[app]} pre-paint theme script is generated from THEME_APPS.${app}`, () => {
    const html = readFileSync(repo + HTML[app], "utf8").replace(/\r\n/g, "\n");
    const want = themePrepaintScript(app);
    assert.equal(themePrepaintBlock(html), want, `${HTML[app]} must hold exactly:\n${want}`);
    // The generated block is the only theme read in the page.
    assert.equal(html.split('setAttribute("data-theme"').length - 1, 2, "one generated block (two branches), no hand-written copy");
  });
}

// The generated script behaves like readThemeMode / queryThemeMode /
// resolveEffective, run against a fake window (one case per row shape).
type FakeEnv = { stored?: string | null; throws?: boolean; search?: string; dark?: boolean };
function runPrepaint(app: ThemeApp, env: FakeEnv): string {
  let stamped = "";
  const fakeWindow = {
    location: { search: env.search ?? "" },
    matchMedia: () => ({ matches: env.dark ?? false }),
  };
  const fakeStorage = {
    getItem: (_k: string) => {
      if (env.throws) throw new Error("blocked");
      return env.stored ?? null;
    },
  };
  const fakeDocument = { documentElement: { setAttribute: (_n: string, v: string) => (stamped = v) } };
  const body = themePrepaintScript(app, "");
  new Function("window", "localStorage", "document", "URLSearchParams", body)(fakeWindow, fakeStorage, fakeDocument, URLSearchParams);
  return stamped;
}
const PREPAINT_CASES: Array<[ThemeApp, FakeEnv, string]> = [
  ["web", { stored: "light" }, "light"],
  ["web", { stored: "system", dark: true }, "dark"],
  ["web", { stored: null, dark: false }, "light"],
  ["web", { stored: "sepia", dark: true }, "dark"],
  ["web", { throws: true, dark: false }, "light"],
  ["web", { stored: "dark", search: "?theme=light" }, "dark"],
  ["web2", { stored: "light" }, "light"],
  ["webcloud", { stored: null, dark: true }, "dark"],
  ["webcloud", { stored: null, dark: false }, "light"],
  ["webcloud", { stored: "light", dark: true }, "light"],
  ["webcloud", { stored: "sepia", dark: false }, "light"],
  ["webcloud", { stored: "dark", search: "?theme=light" }, "light"],
  ["webcloud", { stored: "light", search: "?theme=system" }, "light"],
  ["webcloud", { throws: true, dark: false }, "light"],
];
for (const [app, env, want] of PREPAINT_CASES) {
  test(`pre-paint ${app} ${JSON.stringify(env)} -> ${want}`, () => {
    assert.equal(runPrepaint(app, env), want);
  });
}
