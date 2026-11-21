// sdkCatalog.ts is the typed view of sdkCatalog.json, the ONE catalog of the
// superbased SDKs (review P-11, first-run plan revision 2 section 3.9, lane
// C0): language, package, install line, published flag and init snippet.
// web's AI Apps first-run card and web2's Settings > Apps & SDKs read it
// here; the marketing page generator (website/docs-tools/pagegen/sdk.go) and
// scripts/sdk-install-strings.py read the same JSON file. A new language is
// one more row in the JSON file and nothing else.
//
// Pure: no React, no fetch, no app path aliases, so `node --test` loads it.
// parseSdkCatalog validates the file (the same rules the generator and the
// install-strings script apply), so a malformed row fails every surface's
// tests instead of rendering a blank tab.

import raw from "./sdkCatalog.json" with { type: "json" };

/** What publishes a row: the sdk-release workflow on an sdk-v<x.y.z> tag,
 *  or nothing yet (the flag is flipped by hand). */
export type SdkRelease = "sdk-release" | "none";

/** SdkEntry is one SDK as every surface shows it. `install` is the line to
 *  show now: the registry line once published, the checkout line before. */
export interface SdkEntry {
  /** Stable id (lowercase): python, typescript, go, java. */
  id: string;
  /** The language as a tab label. */
  label: string;
  /** The package name in its registry (PyPI, npm, Maven, Go module path). */
  package: string;
  /** The registry the package is (or will be) published on. */
  registry: string;
  /** The SDK's docs page path on superbased.app. */
  docs: string;
  /** Whether the package is on its registry. */
  published: boolean;
  /** What publishes the row. */
  release: SdkRelease;
  /** The install line to show now. */
  install: string;
  /** The install line before publication (from a checkout). */
  installCheckout: string;
  /** The registry install line. */
  installPublished: string;
  /** A minimal init that sends to this machine, as one text. */
  code: string;
}

const ID_RE = /^[a-z][a-z0-9-]*$/;
const RELEASES: readonly SdkRelease[] = ["sdk-release", "none"];

function str(row: Record<string, unknown>, key: string, where: string): string {
  const v = row[key];
  if (typeof v !== "string" || v.trim() === "") throw new Error(`sdkCatalog: ${where}: "${key}" must be a non-empty string`);
  return v;
}

function oneLine(row: Record<string, unknown>, key: string, where: string): string {
  const v = str(row, key, where);
  if (v.includes("\n")) throw new Error(`sdkCatalog: ${where}: "${key}" must be one line`);
  return v;
}

/** parseSdkCatalog validates a decoded sdkCatalog.json and returns its rows
 *  in file order. It throws on a missing or malformed field, a duplicate
 *  id, an unknown release, a multi-line install line, or an empty catalog. */
export function parseSdkCatalog(data: unknown): SdkEntry[] {
  const sdks = (data as { sdks?: unknown } | null)?.sdks;
  if (!Array.isArray(sdks) || sdks.length === 0) throw new Error("sdkCatalog: \"sdks\" must be a non-empty list");
  const seen = new Set<string>();
  return sdks.map((r, i) => {
    if (typeof r !== "object" || r === null) throw new Error(`sdkCatalog: row ${i} is not an object`);
    const row = r as Record<string, unknown>;
    const id = str(row, "id", `row ${i}`);
    if (!ID_RE.test(id)) throw new Error(`sdkCatalog: row ${i}: bad id "${id}"`);
    if (seen.has(id)) throw new Error(`sdkCatalog: duplicate id "${id}"`);
    seen.add(id);
    const where = `row "${id}"`;
    if (typeof row.published !== "boolean") throw new Error(`sdkCatalog: ${where}: "published" must be true or false`);
    const release = str(row, "release", where) as SdkRelease;
    if (!RELEASES.includes(release)) throw new Error(`sdkCatalog: ${where}: unknown release "${release}"`);
    const installCheckout = oneLine(row, "install_checkout", where);
    const installPublished = oneLine(row, "install_published", where);
    if (installCheckout === installPublished) throw new Error(`sdkCatalog: ${where}: the two install lines are the same`);
    const snippet = row.snippet;
    if (!Array.isArray(snippet) || snippet.length === 0 || snippet.some((l) => typeof l !== "string")) {
      throw new Error(`sdkCatalog: ${where}: "snippet" must be a non-empty list of lines`);
    }
    return {
      id,
      label: str(row, "label", where),
      package: str(row, "package", where),
      registry: str(row, "registry", where),
      docs: str(row, "docs", where),
      published: row.published,
      release,
      install: row.published ? installPublished : installCheckout,
      installCheckout,
      installPublished,
      code: (snippet as string[]).join("\n"),
    };
  });
}

/** sdkLanguages names the catalog's languages as prose, in catalog order:
 *  "Python, TypeScript, Go and Java". */
export function sdkLanguages(rows: readonly Pick<SdkEntry, "label">[]): string {
  const labels = rows.map((r) => r.label);
  if (labels.length <= 1) return labels.join("");
  return `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
}

/** SDK_CATALOG is the catalog, validated once at load. */
export const SDK_CATALOG: readonly SdkEntry[] = Object.freeze(parseSdkCatalog(raw).map((r) => Object.freeze(r)));
