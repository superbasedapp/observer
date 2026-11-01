// Pins shared/lib/mascot.ts (the artwork behind shared/primitives/Obs.tsx):
// the named parts per state, the small-size cape switch at the threshold,
// the reduced-motion gate, and that every colour is a --mascot-* token
// defined in BOTH theme blocks of shared/styles/tokens.css. Since
// D-665..D-669 also the Hero dash (`dash`): its parts, the small-rider rules
// (one afterimage, small cape, no loop), its token use, its reduced-motion
// gate, the wide frame and the cape area pinned to the shipped range.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  DASH_LEAN_DEG,
  MASCOT_TOKENS,
  MASCOT_WIDE_VIEWBOX,
  SMALL_CAPE_MAX_PX,
  capePath,
  dashGhostCount,
  mascotFrame,
  mascotSvgMarkup,
  mascotCss,
  mascotNodes,
  type MascotNode,
  type MascotPart,
  type MascotState,
} from "../../../shared/lib/mascot.ts";

function walk(nodes: MascotNode[], out: MascotNode[] = []): MascotNode[] {
  for (const n of nodes) {
    out.push(n);
    if (n.children) walk(n.children, out);
  }
  return out;
}
const partsOf = (nodes: MascotNode[]) =>
  new Set(walk(nodes).map((n) => n.attrs["data-part"]).filter((p): p is string => typeof p === "string"));
const find = (nodes: MascotNode[], p: MascotPart) => walk(nodes).filter((n) => n.attrs["data-part"] === p);

const ALWAYS: MascotPart[] = ["ground", "hop", "tilt", "cape", "arms", "feet", "body", "screen", "face", "badge", "blush"];
const CASES: Array<{ state: MascotState; has: MascotPart[]; lacks: MascotPart[] }> = [
  { state: "idle", has: [...ALWAYS, "cursor", "cape-lining"], lacks: ["burst", "sparkle", "thinking"] },
  { state: "celebrate", has: [...ALWAYS, "burst", "sparkle", "cape-lining"], lacks: ["cursor", "thinking"] },
  { state: "lost", has: [...ALWAYS, "thinking", "cursor", "cape-lining"], lacks: ["burst", "sparkle"] },
];

for (const c of CASES) {
  test(`mascot ${c.state}: named parts`, () => {
    const parts = partsOf(mascotNodes(c.state, 96));
    for (const p of c.has) assert.ok(parts.has(p), `${c.state} is missing part ${p}`);
    for (const p of c.lacks) assert.ok(!parts.has(p), `${c.state} must not draw ${p}`);
  });
}

test("cape switches to the simplified silhouette at the threshold", () => {
  for (const state of ["idle", "celebrate", "lost"] as MascotState[]) {
    const small = mascotNodes(state, SMALL_CAPE_MAX_PX);
    const big = mascotNodes(state, SMALL_CAPE_MAX_PX + 1);
    assert.equal(find(small, "cape-lining").length, 0, `${state} at ${SMALL_CAPE_MAX_PX}px has no lining`);
    assert.equal(find(big, "cape-lining").length, 1, `${state} above the threshold has a lining`);
    assert.notEqual(capePath(state, SMALL_CAPE_MAX_PX), capePath(state, SMALL_CAPE_MAX_PX + 1));
    const capeFill = (nodes: MascotNode[]) => find(nodes, "cape")[0].children!.at(-1)!.attrs.d;
    assert.equal(capeFill(small), capePath(state, 24));
    assert.equal(capeFill(big), capePath(state, 160));
  }
  // The small sparkle is dropped too; the burst stays.
  assert.equal(find(mascotNodes("celebrate", 32), "sparkle").length, 0);
  assert.equal(find(mascotNodes("celebrate", 32), "burst").length, 1);
});

test("every animation sits inside the reduced-motion gate", () => {
  for (const state of ["idle", "celebrate", "lost"] as MascotState[]) {
    const css = mascotCss("sb-mascot-x", state);
    const gate = "@media (prefers-reduced-motion: no-preference){";
    const at = css.indexOf(gate);
    assert.ok(at > 0, `${state}: has the no-preference block`);
    const before = css.slice(0, at);
    assert.doesNotMatch(before, /animation|@keyframes/, `${state}: no motion outside the gate`);
    assert.match(css.slice(at), /animation:/, `${state}: animates inside the gate`);
    assert.ok(css.endsWith("}}"), `${state}: the gate closes at the end`);
    assert.match(css, /\.sb-mascot-x \[data-part="/, `${state}: selectors are scoped`);
  }
  assert.match(mascotCss("s", "idle"), /data-part="cursor"\]\{animation/);
  assert.match(mascotCss("s", "idle"), /data-part="cape"\]\{animation/);
  assert.match(mascotCss("s", "celebrate"), /data-part="burst"\]\{animation/);
  assert.match(mascotCss("s", "celebrate"), /data-part="hop"\]\{animation/);
  assert.match(mascotCss("s", "lost"), /data-part="thinking"\] circle\{animation/);
});

test("colours are tokens only, and lost uses the lost tokens", () => {
  const ALLOWED_LITERALS = new Set(["#ffffff", "none"]); // the gloss highlight; unfilled strokes
  for (const state of ["idle", "celebrate", "lost"] as MascotState[]) {
    const used = new Set<string>();
    for (const n of walk(mascotNodes(state, 96))) {
      for (const key of ["fill", "stroke"]) {
        const val = n.attrs[key];
        if (typeof val !== "string") continue;
        if (ALLOWED_LITERALS.has(val)) continue;
        const m = /^var\((--[a-z0-9-]+)\)$/.exec(val);
        assert.ok(m, `${state}: ${n.tag}.${key}=${val} is not a token`);
        used.add(m[1]);
      }
    }
    for (const t of used) assert.ok(t === "--fg-4" || (MASCOT_TOKENS as readonly string[]).includes(t), `${state}: unknown token ${t}`);
    const lostOnly = [...used].filter((t) => t.startsWith("--mascot-lost-"));
    if (state === "lost") {
      assert.ok(used.has("--mascot-lost-body") && used.has("--mascot-lost-cape"), "lost greys the body and cape");
      assert.ok(!used.has("--mascot-body") && !used.has("--mascot-cape"));
    } else {
      assert.equal(lostOnly.length, 0, `${state} must not use lost tokens`);
    }
  }
});

test("every --mascot-* token is defined in both theme blocks", () => {
  const css = readFileSync(new URL("../../../shared/styles/tokens.css", import.meta.url), "utf8");
  const lightAt = css.indexOf(':root[data-theme="light"]');
  assert.ok(lightAt > 0);
  const dark = css.slice(0, lightAt);
  const light = css.slice(lightAt, css.indexOf("/* Density", lightAt));
  for (const t of MASCOT_TOKENS) {
    assert.match(dark, new RegExp(`${t}:\\s*#[0-9a-f]{6};`), `dark theme defines ${t}`);
    assert.match(light, new RegExp(`${t}:\\s*#[0-9a-f]{6};`), `light theme defines ${t}`);
  }
});

// ---- Hero dash (D-665..D-669): the flying pose built from the shipped parts.

const DASH_PARTS: MascotPart[] = [
  "ghosts", "ghost", "roll", "hop", "stretch", "tilt", "cape", "arms", "feet", "body", "gloss", "screen", "blush", "face", "cursor", "badge",
];

test("mascot dash: named parts, no ground shadow, leans 22 degrees", () => {
  const nodes = mascotNodes("dash", 96);
  const parts = partsOf(nodes);
  for (const p of DASH_PARTS) assert.ok(parts.has(p), `dash is missing part ${p}`);
  for (const p of ["ground", "burst", "sparkle", "thinking"] as MascotPart[]) assert.ok(!parts.has(p), `dash must not draw ${p}`);
  assert.equal(DASH_LEAN_DEG, 22);
  assert.match(String(find(nodes, "tilt")[0]!.attrs.transform), /^rotate\(22 /);
  // The shipped body box and screen, unchanged.
  const body = find(nodes, "body")[0]!.attrs;
  assert.deepEqual([body.x, body.y, body.width, body.height, body.rx], [13, 18, 74, 72, 24]);
  const screen = find(nodes, "screen")[0]!.attrs;
  assert.deepEqual([screen.width, screen.height, screen.rx], [54, 40, 14]);
  // The celebrate fist (r 5.4) and arm (5 x 9), swung ahead.
  const fist = walk(find(nodes, "arms")).find((n) => n.tag === "circle")!;
  assert.equal(fist.attrs.r, 5.4);
  // The cape draws the dash silhouette.
  assert.equal(find(nodes, "cape")[0]!.children!.at(-1)!.attrs.d, capePath("dash", 96));
});

test("mascot dash: three fading afterimages, one at small sizes", () => {
  const ghosts = (size: number) => find(mascotNodes("dash", size), "ghost");
  assert.equal(dashGhostCount(96), 3);
  assert.deepEqual(ghosts(96).map((g) => g.attrs.opacity), [0.1, 0.15, 0.3]);
  assert.equal(dashGhostCount(SMALL_CAPE_MAX_PX), 1);
  assert.equal(ghosts(SMALL_CAPE_MAX_PX).length, 1);
  assert.equal(ghosts(SMALL_CAPE_MAX_PX + 1).length, 3);
  // Small cape, no lining at the threshold; the lining above it.
  assert.equal(find(mascotNodes("dash", SMALL_CAPE_MAX_PX), "cape-lining").length, 0);
  assert.equal(find(mascotNodes("dash", SMALL_CAPE_MAX_PX + 1), "cape-lining").length, 1);
  assert.notEqual(capePath("dash", SMALL_CAPE_MAX_PX), capePath("dash", SMALL_CAPE_MAX_PX + 1));
});

test("mascot dash: the loop flourish is dropped on small riders", () => {
  const big = mascotCss("s", "dash", 96);
  const small = mascotCss("s", "dash", SMALL_CAPE_MAX_PX);
  assert.match(big, /data-part="roll"\]\{animation/);
  assert.doesNotMatch(small, /data-part="roll"\]\{animation/);
  for (const css of [big, small]) {
    assert.match(css, /data-part="cape"\]\{animation:s-cape \.24s/);
    assert.match(css, /data-part="stretch"\]\{animation/);
    assert.match(css, /data-part="ghosts"\]\{animation/);
  }
  // The loop runs on a 5.2 s cycle (about every 5 s).
  assert.match(big, /s-roll 5\.2s/);
});

test("dash draws in the wide frame; the square frame stays for the rest", () => {
  assert.deepEqual(mascotFrame("dash", 100), { viewBox: MASCOT_WIDE_VIEWBOX, width: 180, height: 124 });
  assert.deepEqual(mascotFrame("idle", 40), { viewBox: "0 0 100 100", width: 40, height: 40 });
  assert.deepEqual(mascotFrame("celebrate", 50, true), { viewBox: MASCOT_WIDE_VIEWBOX, width: 90, height: 62 });
});

test("dash colours are tokens only, never the lost set", () => {
  const used = new Set<string>();
  for (const n of walk(mascotNodes("dash", 96))) {
    for (const key of ["fill", "stroke"]) {
      const val = n.attrs[key];
      if (typeof val !== "string" || val === "#ffffff" || val === "none") continue;
      const m = /^var\((--[a-z0-9-]+)\)$/.exec(val);
      assert.ok(m, `dash: ${n.tag}.${key}=${val} is not a token`);
      used.add(m[1]);
    }
  }
  for (const t of used) assert.ok((MASCOT_TOKENS as readonly string[]).includes(t), `dash: unknown token ${t}`);
  assert.ok(![...used].some((t) => t.startsWith("--mascot-lost-")));
  assert.ok(used.has("--mascot-body") && used.has("--mascot-cape"));
});

test("dash animations sit inside the reduced-motion gate", () => {
  for (const size of [96, 28]) {
    const css = mascotCss("sb-mascot-x", "dash", size);
    const gate = "@media (prefers-reduced-motion: no-preference){";
    const at = css.indexOf(gate);
    assert.ok(at > 0);
    assert.doesNotMatch(css.slice(0, at), /animation|@keyframes/);
    assert.ok(css.endsWith("}}"));
  }
});

// Cape area: the dash cape is the shipped cape's size. Measured by sampling
// the path (absolute M / C / Z only, which is all the capes use) and the
// shoelace formula, against the body's rounded-rect area.
function pathArea(d: string): number {
  const nums = (s: string) => s.trim().split(/[\s,]+/).map(Number);
  const pts: Array<[number, number]> = [];
  for (const [, cmd, args] of d.matchAll(/([MCZ])([^MCZ]*)/g)) {
    const a = nums(args);
    if (cmd === "M") pts.push([a[0], a[1]]);
    if (cmd === "C") {
      for (let i = 0; i + 5 < a.length; i += 6) {
        const [x0, y0] = pts.at(-1)!;
        for (let t = 1; t <= 40; t++) {
          const u = t / 40;
          const b = (p0: number, p1: number, p2: number, p3: number) =>
            (1 - u) ** 3 * p0 + 3 * (1 - u) ** 2 * u * p1 + 3 * (1 - u) * u ** 2 * p2 + u ** 3 * p3;
          pts.push([b(x0, a[i], a[i + 2], a[i + 4]), b(y0, a[i + 1], a[i + 3], a[i + 5])]);
        }
      }
    }
  }
  let s = 0;
  for (let i = 0; i < pts.length; i++) {
    const [x1, y1] = pts[i];
    const [x2, y2] = pts[(i + 1) % pts.length];
    s += x1 * y2 - x2 * y1;
  }
  return Math.abs(s / 2);
}
const BODY_AREA = 74 * 72 - (4 - Math.PI) * 24 * 24;

test("dash cape area sits in the shipped capes' range, relative to the body", () => {
  for (const size of [96, SMALL_CAPE_MAX_PX]) {
    const shipped = (["idle", "celebrate"] as MascotState[]).map((s) => pathArea(capePath(s, size)));
    const lo = Math.min(...shipped);
    const hi = Math.max(...shipped);
    const dash = pathArea(capePath("dash", size));
    // Never bigger than the biggest shipped cape, and at least 85% of the
    // smallest: the dash cape streams back, it does not grow.
    assert.ok(dash <= hi, `${size}px: dash cape ${dash.toFixed(0)} exceeds the shipped max ${hi.toFixed(0)}`);
    assert.ok(dash >= 0.85 * lo, `${size}px: dash cape ${dash.toFixed(0)} under 85% of the shipped min ${lo.toFixed(0)}`);
    const ratio = dash / BODY_AREA;
    assert.ok(ratio > 0.24 && ratio < 0.4, `${size}px: dash cape is ${(ratio * 100).toFixed(0)}% of the body`);
  }
});

test("mascotSvgMarkup is the node tree as standalone, decorative SVG", () => {
  const svg = mascotSvgMarkup("dash", 84, "sbo-dash");
  assert.match(svg, /^<svg class="sbo-dash" width="151.2" height="104.2" viewBox="-64 -14 180 124" aria-hidden="true"/);
  assert.match(svg, /stroke-width="4.2"/);
  assert.doesNotMatch(svg, /strokeWidth|strokeLinecap/);
  assert.match(svg, /<style>\.sbo-dash \[data-part="hop"\]/);
  assert.equal(svg.split('data-part="ghost"').length - 1, 3);
  assert.match(mascotSvgMarkup("lost", 56, "x"), /style="transform:rotate\(-4deg\);transform-origin:50% 100%;transform-box:fill-box"/);
});
