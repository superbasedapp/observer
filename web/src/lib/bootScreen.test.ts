// Pins the generated pre-mount boot screen (shared/lib/bootScreen.ts,
// D-665..D-669): each app's index.html holds exactly bootScreenHtml(app)
// between the markers (the T-551 pre-paint pattern), every token the screen
// inlines equals shared/styles/tokens.css in both themes, it is JS-free and
// reduced motion swaps the flying pose for the static idle one by CSS.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BOOT_LABELS,
  BOOT_TOKENS,
  bootScreenBlock,
  bootScreenCss,
  bootScreenHtml,
} from "../../../shared/lib/bootScreen.ts";
import type { ThemeApp } from "../../../shared/lib/theme.ts";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const HTML: Record<ThemeApp, string> = { web: "web/index.html", web2: "web2/index.html", webcloud: "webcloud/index.html" };

for (const app of Object.keys(HTML) as ThemeApp[]) {
  test(`${HTML[app]} boot screen is generated from shared/lib/bootScreen.ts`, () => {
    const html = readFileSync(join(repo, HTML[app]), "utf8").replace(/\r\n/g, "\n");
    const want = bootScreenHtml(app);
    assert.equal(bootScreenBlock(html), want, `${HTML[app]} must hold exactly:\n${want}`);
    // One boot screen, and the retired two-square mark is gone.
    assert.equal(html.split('id="sbo-boot"').length - 1, 1);
    assert.doesNotMatch(html, /sbo-mark/);
    // The block sits where React mounts.
    assert.match(want, /<div id="root">/);
  });
}

test("the boot screen is JS-free and labelled", () => {
  for (const app of Object.keys(HTML) as ThemeApp[]) {
    const block = bootScreenHtml(app);
    assert.doesNotMatch(block, /<script|on[a-z]+=/i);
    assert.match(block, new RegExp(`role="status" aria-label="${BOOT_LABELS[app]}"`));
    assert.match(block, /class="sbo-fly"><svg class="sbo-dash"[^>]*data-state="dash"/);
    assert.match(block, /class="sbo-rest"><svg class="sbo-idle"[^>]*data-state="idle"/);
    assert.match(block, /sbo-cloud/);
    assert.match(block, /sbo-streaks/);
    assert.doesNotMatch(block, /[–—]/, "no en or em dashes");
  }
});

test("reduced motion shows the static idle pose, still clouds and no streaks", () => {
  const css = bootScreenCss();
  assert.match(css, /\.sbo-rest\{display:none\}/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)\{\.sbo-fly\{display:none\}\.sbo-rest\{display:inline-block\}\}/);
  // Scenery motion lives only inside the no-preference gate.
  const gate = css.indexOf("@media (prefers-reduced-motion: no-preference){");
  assert.ok(gate > 0);
  assert.doesNotMatch(css.slice(0, gate), /animation:|@keyframes/);
  assert.match(css, /\.sbo-streaks\{position:absolute;inset:0;pointer-events:none;display:none\}/);
});

// tokens.css: the default (dark) :root block, then the light block.
function tokenBlock(css: string, opener: string): string {
  const at = css.indexOf(opener);
  assert.ok(at >= 0, opener);
  return css.slice(at, css.indexOf("\n}", at));
}

test("every inlined boot token equals shared/styles/tokens.css in both themes", () => {
  const css = readFileSync(join(repo, "shared/styles/tokens.css"), "utf8");
  const blocks = { dark: tokenBlock(css, ":root,\n"), light: tokenBlock(css, ':root[data-theme="light"]') };
  for (const theme of ["dark", "light"] as const) {
    for (const [name, value] of Object.entries(BOOT_TOKENS[theme])) {
      const m = new RegExp(`\\n\\s*${name}:\\s*([^;]+);`).exec(blocks[theme]);
      assert.ok(m, `${theme}: tokens.css defines ${name}`);
      assert.equal(m[1].trim(), value, `${theme}: ${name}`);
    }
  }
});

test("the boot screen inlines every token the art and the scenery read", () => {
  const block = bootScreenHtml("web");
  const read = new Set([...block.matchAll(/var\((--[a-z0-9-]+)/g)].map((m) => m[1]));
  // Per-element knobs the markup sets itself (cloud position, drift period).
  const local = new Set([...block.matchAll(/[;"](--[a-z0-9-]+):/g)].map((m) => m[1]).filter((t) => !(t in BOOT_TOKENS.dark)));
  assert.deepEqual([...local].sort(), ["--d", "--dur", "--x"]);
  for (const t of read) if (!local.has(t)) assert.ok(t in BOOT_TOKENS.dark && t in BOOT_TOKENS.light, `boot reads ${t} but does not inline it`);
});
