import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// U-32 (AI apps UI review 2026-11-21): at 375 px /apps/traces scrolled
// sideways (page 434 px wide): the top bar's status cluster ran past the
// screen edge, and the page header squeezed its subtitle beside the window
// picker. These pins keep the fixes; the live check is "no horizontal page
// scroll at 375 on every AI apps page".

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");

test("the top bar gives a phone its room", () => {
  const top = read("../components/TopBar.tsx");
  // The idle ribbon chip leaves the bar below sm (the New terminal button
  // starts one there); the live chip stays.
  assert.match(top, /<span className="contents max-sm:\[&>\[data-state=idle\]\]:hidden">\s*<RibbonChip \/>/);
  // The connected chip is its dot below sm; the label stays its name.
  assert.match(top, /<span className="sr-only sm:not-sr-only sm:truncate">\{view\.label\}<\/span>/);
  // The breadcrumb never wraps, and its group label waits for xl.
  assert.match(top, /<div className="flex min-w-0 items-center gap-2 whitespace-nowrap">/);
  assert.match(top, /<span className="hidden xl:inline">\{group\.label\}<\/span>/);
});

test("every AI apps page header stacks its right slot below sm", () => {
  for (const page of ["AppTraces", "AppSessions", "AppAnalytics", "AppEndUsers", "AppPrompts"]) {
    const src = read(`../pages/${page}.tsx`);
    assert.match(src, /<PageHeader[\s\S]{0,200}className=\{APPS_HEADER_CLASS\}/, `${page} header`);
  }
  assert.match(read("../components/apps/AppsChrome.tsx"), /export const APPS_HEADER_CLASS = "flex-col sm:flex-row";/);
});
