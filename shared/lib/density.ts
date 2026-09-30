import { Rows3, Rows4, type LucideIcon } from "lucide-react";

// Density - the per-browser "comfortable / compact" preference shared by every
// app surface (web node dashboard, web2 org dashboard, webcloud portal).
//
// The mode is stamped on <html> as `data-density`; the spacing it changes lives
// in shared/styles/tokens.css as `--density-*` custom properties (exposed to
// Tailwind as `py-row`, `px-cell`, `p-card`, ... by the shared preset). The
// DEFAULT block of those tokens equals the pre-density rendering exactly, so a
// viewer who never touches the toggle sees nothing move; `compact` is the only
// override block.
//
// Pure: no React, no DOM globals beyond what is passed in. Storage access is
// injected and every read / write is wrapped, because localStorage can throw
// (private mode, blocked site data) or come back empty.

export type DensityMode = "comfortable" | "compact";

export type DensityRow = {
  mode: DensityMode;
  /** Plain-word label shown on the toggle. */
  label: string;
  icon: LucideIcon;
  /** One line for a tooltip / settings description. */
  description: string;
};

/** DENSITY is the one table of modes, walked in display order. */
export const DENSITY: readonly DensityRow[] = [
  {
    mode: "comfortable",
    label: "Comfortable",
    icon: Rows3,
    description: "Roomier rows and panels. The default.",
  },
  {
    mode: "compact",
    label: "Compact",
    icon: Rows4,
    description: "Tighter rows and panels, so more fits on screen.",
  },
];

export const DENSITY_MODES: readonly DensityMode[] = DENSITY.map((r) => r.mode);

/** The mode used when nothing valid is stored. */
export const DEFAULT_DENSITY: DensityMode = "comfortable";

/** parseDensity accepts only an exact mode string. Anything else (null, junk,
 * a different case, whitespace) is unknown and returns null, so the caller
 * falls back to the default rather than guessing. */
export function parseDensity(v: unknown): DensityMode | null {
  if (typeof v !== "string") return null;
  const row = DENSITY.find((r) => r.mode === v);
  return row ? row.mode : null;
}

/** densityRow returns the table row for a mode (the default row for null). */
export function densityRow(mode: DensityMode | null): DensityRow {
  return DENSITY.find((r) => r.mode === mode) ?? DENSITY[0];
}

export type DensityApp = "web" | "web2" | "webcloud";

/** DENSITY_STORAGE_KEY follows each app's theme-key family: web
 * "superbased.theme", web2 "superbased.org.theme", webcloud "sb_theme". The
 * three apps run on different origins, so the keys never meet; keeping each
 * beside its theme key keeps a support "clear these keys" answer simple. The
 * index.html pre-paint scripts hard-code the same strings (a test pins them). */
export const DENSITY_STORAGE_KEY: Readonly<Record<DensityApp, string>> = {
  web: "superbased.density",
  web2: "superbased.org.density",
  webcloud: "sb_density",
};

export function densityStorageKey(app: DensityApp): string {
  return DENSITY_STORAGE_KEY[app];
}

/** The slice of Storage the helpers need (a fake in tests). */
export type DensityStorage = Pick<Storage, "getItem" | "setItem">;

/** readDensity returns the stored mode, or the default when storage is
 * missing, throws, is empty, or holds an unknown value. */
export function readDensity(
  storage: DensityStorage | null | undefined,
  key: string,
): DensityMode {
  try {
    return parseDensity(storage?.getItem(key)) ?? DEFAULT_DENSITY;
  } catch {
    return DEFAULT_DENSITY;
  }
}

/** writeDensity persists the mode; returns false when storage is unavailable
 * (the choice still applies for this page load, it just is not remembered). */
export function writeDensity(
  storage: DensityStorage | null | undefined,
  key: string,
  mode: DensityMode,
): boolean {
  try {
    if (!storage) return false;
    storage.setItem(key, mode);
    return true;
  } catch {
    return false;
  }
}

/** applyDensity stamps `data-density` on the document root. */
export function applyDensity(
  doc: { documentElement: { dataset: DOMStringMap } } | null | undefined,
  mode: DensityMode,
): void {
  if (!doc) return;
  doc.documentElement.dataset.density = mode;
}

/** DENSITY_TOKENS lists every spacing token the density modes set. tokens.css
 * must define each one in BOTH the default block and the compact block
 * (pinned by web/src/lib/density.test.ts). */
export const DENSITY_TOKENS: readonly string[] = [
  "--density-row-y",
  "--density-head-y",
  "--density-cell-x",
  "--density-cell-x-num",
  "--density-card-pad",
  "--density-stat-x",
  "--density-stat-y",
  "--density-stat-min-h",
];
