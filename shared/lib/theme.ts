// Theme preference: light / dark / system, applied by stamping data-theme on
// <html> so the token palette flips without dark: variants. One owner for
// every app (web, web2, webcloud): the per-app differences are DATA in
// THEME_APPS (storage key, offered modes, fallback, query override), the
// way density keys live in density.ts. Pure: storage, document and the OS
// preference are passed in. React binding: lib/useTheme.tsx; the control:
// primitives/ThemeToggle.tsx. Each index.html carries the same read as a
// pre-paint script (no flash before the bundle loads); that script is
// GENERATED from the app's THEME_APPS row by themePrepaintScript and pinned
// byte for byte by web/src/lib/sharedTheme.test.ts (T-551), so the HTML can
// no longer drift from the row.

export type ThemeMode = "light" | "dark" | "system";
export type EffectiveTheme = "light" | "dark";
export type ThemeApp = "web" | "web2" | "webcloud";

export type ThemeAppRow = {
  /** localStorage key (a per-viewer convenience, never shared state). */
  storageKey: string;
  /** Modes the app offers, in toggle order. */
  modes: readonly ThemeMode[];
  /** The mode when nothing usable is stored. */
  fallback: ThemeMode;
  /** `?theme=light|dark` previews and persists a theme (portal links). */
  queryOverride: boolean;
  /**
   * How "system" is remembered: "value" stores the word "system"; "absent"
   * removes the key instead, for a key shared with a page that understands
   * only light / dark and follows the OS when the key is missing (the
   * marketing site's sb_theme). An absent key reads back as the fallback,
   * which such a row sets to "system".
   */
  systemStorage: "value" | "absent";
};

/**
 * THEME_APPS: one row per app.
 * - web: the node dashboard (localhost origin).
 * - web2: the org dashboard; its own key so a browser that opens both on one
 *   origin keeps two preferences.
 * - webcloud: the portal is served from the superbased.app domain family,
 *   where the marketing site and arcade already use "sb_theme" and read only
 *   "light" / "dark" (anything else follows the OS). It offers light / dark /
 *   system with system the default, remembers "system" by REMOVING the key
 *   (never a value the site does not understand), and honours ?theme=.
 */
export const THEME_APPS: Readonly<Record<ThemeApp, ThemeAppRow>> = {
  web: { storageKey: "superbased.theme", modes: ["light", "dark", "system"], fallback: "system", queryOverride: false, systemStorage: "value" },
  web2: { storageKey: "superbased.org.theme", modes: ["light", "dark", "system"], fallback: "system", queryOverride: false, systemStorage: "value" },
  webcloud: { storageKey: "sb_theme", modes: ["light", "dark", "system"], fallback: "system", queryOverride: true, systemStorage: "absent" },
};

/** THEME_MODE_LABEL: the toggle's title for each mode. */
export const THEME_MODE_LABEL: Readonly<Record<ThemeMode, string>> = {
  light: "Light theme",
  dark: "Dark theme",
  system: "Follow system",
};

/** parseThemeMode returns v when the app offers it, else null (never a guess). */
export function parseThemeMode(v: unknown, row: ThemeAppRow): ThemeMode | null {
  return typeof v === "string" && (row.modes as readonly string[]).includes(v) ? (v as ThemeMode) : null;
}

/** ThemeStorage is the slice of Storage the theme needs; removeItem is used
 * only by a row whose systemStorage is "absent". */
export type ThemeStorage = Pick<Storage, "getItem" | "setItem"> & Partial<Pick<Storage, "removeItem">>;

/** readThemeMode: the stored mode, or the app's fallback (storage may throw). */
export function readThemeMode(storage: ThemeStorage | null, row: ThemeAppRow): ThemeMode {
  try {
    return parseThemeMode(storage?.getItem(row.storageKey), row) ?? row.fallback;
  } catch {
    return row.fallback;
  }
}

/**
 * writeThemeMode persists a mode; a storage failure keeps it for this load
 * only. "system" on a row whose systemStorage is "absent" removes the key
 * (it then reads back as the row's "system" fallback).
 */
export function writeThemeMode(storage: ThemeStorage | null, row: ThemeAppRow, mode: ThemeMode): void {
  try {
    if (mode === "system" && row.systemStorage === "absent") {
      storage?.removeItem?.(row.storageKey);
      return;
    }
    storage?.setItem(row.storageKey, mode);
  } catch {
    // Storage unavailable (private mode / quota): not remembered.
  }
}

/** queryThemeMode: a `?theme=light|dark` override the app honours, else null. */
export function queryThemeMode(search: string, row: ThemeAppRow): ThemeMode | null {
  if (!row.queryOverride) return null;
  try {
    const q = new URLSearchParams(search).get("theme");
    return q === "system" ? null : parseThemeMode(q, row);
  } catch {
    return null;
  }
}

/** resolveEffective maps a mode to the palette actually shown. */
export function resolveEffective(mode: ThemeMode, prefersDark: boolean): EffectiveTheme {
  if (mode === "system") return prefersDark ? "dark" : "light";
  return mode;
}

/** applyTheme stamps the effective theme on <html>. */
export function applyTheme(doc: Pick<Document, "documentElement"> | null, effective: EffectiveTheme): void {
  if (!doc) return;
  doc.documentElement.setAttribute("data-theme", effective);
}

/** THEME_PREPAINT_BEGIN opens the generated pre-paint block in an index.html. */
export const THEME_PREPAINT_BEGIN = "// theme-prepaint:begin";
/** THEME_PREPAINT_END closes it. */
export const THEME_PREPAINT_END = "// theme-prepaint:end";

/**
 * themePrepaintScript renders the pre-paint theme script for one app's
 * THEME_APPS row (T-551), as the lines between (and including) the begin /
 * end markers, each prefixed with indent. It is plain ES5 for an inline
 * <script> and mirrors readThemeMode / queryThemeMode / resolveEffective:
 * a `?theme=` override where the row honours it, else the stored mode when
 * the app offers it, else the row's fallback (also when storage throws);
 * "system" follows the OS preference; any other failure paints dark, the
 * pre-split behaviour. Each index.html holds exactly this output; the pin
 * test fails (and prints the expected block) when the row changes.
 */
export function themePrepaintScript(app: ThemeApp, indent = "      "): string {
  const row = THEME_APPS[app];
  const lines = [
    `${THEME_PREPAINT_BEGIN} ${app}: generated from shared/lib/theme.ts THEME_APPS by themePrepaintScript; do not edit by hand.`,
    "// Pre-paint: stamp data-theme on <html> before any CSS evaluates, so there is no",
    "// flash of the wrong palette before the bundle applies the same preference.",
    "(function () {",
    `  var key = ${JSON.stringify(row.storageKey)};`,
    `  var modes = ${JSON.stringify([...row.modes])};`,
    `  var fallback = ${JSON.stringify(row.fallback)};`,
    "  try {",
    "    var m = null;",
  ];
  if (row.queryOverride) {
    lines.push(
      '    var q = new URLSearchParams(window.location.search).get("theme");',
      '    if (q !== "system" && modes.indexOf(q) >= 0) m = q;',
    );
  }
  lines.push(
    "    if (m === null) {",
    "      try {",
    "        var s = localStorage.getItem(key);",
    "        m = modes.indexOf(s) >= 0 ? s : fallback;",
    "      } catch (_) {",
    "        m = fallback;",
    "      }",
    "    }",
    '    var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;',
    '    document.documentElement.setAttribute("data-theme", m === "system" ? (dark ? "dark" : "light") : m);',
    "  } catch (_) {",
    '    document.documentElement.setAttribute("data-theme", "dark");',
    "  }",
    "})();",
    THEME_PREPAINT_END,
  );
  return lines.map((l) => indent + l).join("\n");
}

/**
 * themePrepaintBlock extracts the generated block (begin marker line through
 * end marker line, with their indentation) from an index.html, or null when
 * the markers are missing.
 */
export function themePrepaintBlock(html: string): string | null {
  const lines = html.split("\n");
  const start = lines.findIndex((l) => l.trimStart().startsWith(THEME_PREPAINT_BEGIN));
  if (start < 0) return null;
  const end = lines.findIndex((l, i) => i > start && l.trim() === THEME_PREPAINT_END);
  if (end < 0) return null;
  return lines.slice(start, end + 1).join("\n");
}
