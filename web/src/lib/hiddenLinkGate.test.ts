// Drift guard for CG-20/CG-21 (docs/audits/org-node-control-coverage-audit-
// 2026-11-11.md): a link to a page or Settings section that a MANAGED node
// hides by default must go through the visibility gate (components/
// GatedLink.tsx, lib/governance.ts useHrefGate, or the TopBar's
// isSettingsHidden check), so a developer is never offered a control that
// lands on "Managed by your organization".
//
// The hidden-by-default set is read from its one owner, the managed-default
// tables in internal/policyfam/nodegov/managed_defaults.go (rows at
// VisibilityHidden), so a page the org side starts hiding by default is
// covered here without editing this file. The floor (nodegov.Unhideable*:
// you, privacy, messages, requests, settings; enrolment, org) is never in
// that set, so links to it need no gate.
//
// This is a source scan, like noNativeDialogs.test.ts: every non-test file
// under web/src holding a string literal that addresses one of those places
// must also reference the gate, or carry a reasoned row in ALLOWED below.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { NAV_ITEMS } from "./nav.ts";
import { FLOOR_NAV_IDS, FLOOR_SETTINGS_IDS } from "./visibility.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = path.resolve(here, "..");
const repo = path.resolve(src, "..", "..");

/** What counts as going through the gate. */
const GATE = /\b(?:GatedLink|useHrefGate|hrefGate|isSettingsHidden)\b/;

/**
 * Files that address a hidden-by-default place without the gate, each with
 * its reason. `caller` names the file that renders the address and must
 * itself reference the gate (a pure lib takes no hook; its render site
 * gates).
 */
const ALLOWED: Record<string, { why: string; caller?: string }> = {
  "lib/nav.ts": { why: "the nav table itself; Sidebar filters it (filterNavGroups)" },
  "lib/pageTabRoutes.ts": { why: "the tabbed-page table the gate and the palette read" },
  "lib/exportTarget.ts": { why: "export endpoints keyed by page path, not links" },
  "lib/tour.ts": { why: "tour steps; TourProvider drops hidden pages (withoutHiddenPaths)" },
  "lib/help.ts": { why: "help prose naming an address, not a link; HelpDrawer drops hidden entries" },
  "lib/codeSecurityApi.ts": { why: "findingsHref addresses Code security itself; its callers are that page" },
  "pages/codesecurity/OverviewTab.tsx": { why: "a tab link inside Code security to Code security" },
  "pages/codesecurity/ProjectsTab.tsx": { why: "a tab link inside Code security to Code security" },
  "lib/settingsPlaces.ts": {
    why: "pure place table; every render site uses NeedsSettingLink or NeedsSettingNotice, which gate",
    caller: "components/NeedsSettingNotice.tsx",
  },
  "lib/you.ts": { why: "pure consent-row owners", caller: "pages/You.tsx" },
  "lib/adminMessages.ts": { why: "pure attachment links; attachmentView takes the gate", caller: "pages/Messages.tsx" },
  "lib/codeSecurity.ts": { why: "pure approve address", caller: "pages/codesecurity/FindingDrawer.tsx" },
  "lib/guardRecipes.ts": { why: "pure recipe input address", caller: "pages/security/RecipesCard.tsx" },
  "lib/planeaFirstRun.ts": { why: "pure AI Apps home address (E-71)", caller: "components/apps/AppsStart.tsx" },
};

const SKIP_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$/;

function walk(p: string, out: string[]) {
  const st = statSync(p);
  if (st.isDirectory()) {
    for (const e of readdirSync(p)) walk(path.join(p, e), out);
    return;
  }
  if (/\.tsx?$/.test(p) && !SKIP_FILE.test(p) && !p.endsWith(".gen.ts")) out.push(p);
}

/** stripComments blanks block and line comments (a `//` after a colon is
 *  kept: it is a URL inside a string). */
function stripComments(code: string): string {
  return code
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:\\])\/\/.*$/gm, "$1");
}

/** hiddenByDefault reads one managed-default table's VisibilityHidden ids. */
function hiddenByDefault(goSrc: string, table: string): string[] {
  const start = goSrc.indexOf(`var ${table} = []ManagedDefault{`);
  assert.ok(start >= 0, `${table} not found in managed_defaults.go`);
  const body = goSrc.slice(start, goSrc.indexOf("\n}\n", start));
  return [...body.matchAll(/\{"([a-z0-9-]+)",\s*VisibilityHidden,/g)].map((m) => m[1]!);
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

const goSrc = readFileSync(path.join(repo, "internal", "policyfam", "nodegov", "managed_defaults.go"), "utf8");
const hiddenNav = hiddenByDefault(goSrc, "ManagedNavDefaults");
const hiddenSettings = hiddenByDefault(goSrc, "ManagedSettingsDefaults");

/** The literal shapes that address a hidden-by-default place. */
const patterns: RegExp[] = [
  ...hiddenNav.map((id) => {
    const p = NAV_ITEMS.find((n) => n.id === id)?.path;
    assert.ok(p, `managed-default hidden page ${id} has no nav path`);
    return new RegExp(`["'\`]${escape(p)}(?=["'\`?#])`);
  }),
  ...hiddenSettings.map((id) => new RegExp(`section=${escape(id)}(?![\\w-])`)),
];

test("the managed-default hidden set is read and never touches the floor", () => {
  assert.ok(hiddenNav.length >= 3, `read only ${hiddenNav.length} hidden pages: did the Go table move?`);
  assert.ok(hiddenSettings.length >= 3, `read only ${hiddenSettings.length} hidden sections: did the Go table move?`);
  for (const id of hiddenNav) assert.ok(!FLOOR_NAV_IDS.includes(id), id);
  for (const id of hiddenSettings) assert.ok(!FLOOR_SETTINGS_IDS.includes(id), id);
});

test("every link to a hidden-by-default page or Settings section goes through the gate", () => {
  const files: string[] = [];
  walk(src, files);
  assert.ok(files.length > 100, `scanned only ${files.length} files: is web/src right (${src})?`);
  const rel = (f: string) => path.relative(src, f).split(path.sep).join("/");
  const offenders: string[] = [];
  const allowedHit = new Set<string>();
  for (const f of files) {
    const raw = readFileSync(f, "utf8");
    const code = stripComments(raw);
    if (!patterns.some((re) => re.test(code))) continue;
    const name = rel(f);
    if (GATE.test(code)) continue;
    if (ALLOWED[name]) {
      allowedHit.add(name);
      continue;
    }
    const lines = code
      .split("\n")
      .map((l, i) => [i + 1, l] as const)
      .filter(([, l]) => patterns.some((re) => re.test(l)))
      .map(([n, l]) => `${name}:${n}: ${l.trim()}`);
    offenders.push(...lines);
  }
  assert.deepEqual(
    offenders,
    [],
    "a link to a page or Settings section hidden by default on a managed node must use GatedLink (or useHrefGate)",
  );
  // A caller named for a pure lib must itself gate.
  for (const [name, row] of Object.entries(ALLOWED)) {
    if (!row.caller) continue;
    const code = stripComments(readFileSync(path.join(src, row.caller), "utf8"));
    assert.ok(GATE.test(code), `${row.caller} renders ${name}'s addresses (${row.why}) but does not gate them`);
  }
  // No stale allow-list rows.
  const stale = Object.keys(ALLOWED).filter((n) => !allowedHit.has(n));
  assert.deepEqual(stale, [], "ALLOWED rows whose file no longer addresses a hidden-by-default place");
});
