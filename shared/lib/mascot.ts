// The SuperBased mascot's artwork as data: "Prompt in a cape" (B4C-1, the
// operator's pick from the 2026-10-02 mascot exploration). A squishy
// terminal buddy whose face IS the prompt (">" winking eye + a blinking
// "_" cursor), wearing a shoulder cape, with the logo mark as a belly badge.
//
// Pure: no React, no DOM. shared/primitives/Obs.tsx maps the node tree to
// elements and injects the CSS; web/src/lib/mascot.test.ts pins the parts,
// the small-size cape switch, the reduced-motion gate and the token use.
//
// Colours are ONLY the --mascot-* tokens (shared/styles/tokens.css, one
// pair per theme) plus --fg-4 for the ground shadow and the thinking dots.
// The single literal is the white gloss highlight, an internal detail that
// never touches the page background.
//
// "dash" (Hero dash, D-665..D-669, 2026-10-15) is the flying pose, built from
// the SAME parts: the shipped body, screen, gloss, blush, badge and feet, the
// celebrate fist-pump arm swung to point ahead, a determined grin, a cape
// streaming straight back at shipped size, a 22 degree forward lean, squash
// and stretch, three fading afterimages and a loop-the-loop about every 5 s.
// It draws in the wide frame (mascotFrame) so the cape and afterimages have
// room. At SMALL_CAPE_MAX_PX and below it keeps one afterimage and the small
// cape, and the loop is dropped.

export type MascotState = "idle" | "celebrate" | "lost" | "dash";

/** At or below this rendered size the cape drops its lining and wave
 *  notches (a chunkier silhouette), so it never turns into noise. The dash
 *  also keeps one afterimage and skips the loop at this size. */
export const SMALL_CAPE_MAX_PX = 40;

/** The forward lean of the dash pose, in degrees. */
export const DASH_LEAN_DEG = 22;

/** The wide frame every flying pose (and any pose sharing a host with one,
 *  so a fly-to-celebrate change never shifts layout) draws in. One frame unit
 *  is still size / 100 px; the frame is 1.8 x 1.24 of the square one. */
export const MASCOT_WIDE_VIEWBOX = "-64 -14 180 124";
const WIDE_W = 1.8;
const WIDE_H = 1.24;

/** mascotFrame is the viewBox and the rendered box for one instance. The
 *  dash always uses the wide frame; other states use it on request. */
export function mascotFrame(
  state: MascotState,
  size: number,
  wide = false,
): { viewBox: string; width: number; height: number } {
  if (state === "dash" || wide) {
    return { viewBox: MASCOT_WIDE_VIEWBOX, width: round1(size * WIDE_W), height: round1(size * WIDE_H) };
  }
  return { viewBox: "0 0 100 100", width: size, height: size };
}

const round1 = (n: number) => Math.round(n * 10) / 10;

/** The parts every caller and test can address via `data-part`. */
export type MascotPart =
  | "ground"
  | "burst"
  | "sparkle"
  | "thinking"
  | "hop"
  | "tilt"
  | "cape"
  | "cape-lining"
  | "arms"
  | "feet"
  | "body"
  | "gloss"
  | "screen"
  | "blush"
  | "face"
  | "cursor"
  | "badge"
  // Dash-only wrappers: squash and stretch along travel, the loop flourish,
  // and the afterimages (each `ghost` is a cape + body silhouette).
  | "stretch"
  | "roll"
  | "ghosts"
  | "ghost";

/** A framework-free SVG node. Attribute keys use React's camelCase names. */
export type MascotNode = {
  tag: string;
  attrs: Record<string, string | number | Record<string, string>>;
  children?: MascotNode[];
};

const el = (tag: string, attrs: MascotNode["attrs"], children?: MascotNode[]): MascotNode =>
  children ? { tag, attrs, children } : { tag, attrs };
const part = (p: MascotPart) => ({ "data-part": p });

/** Token names, so the test can check each one exists in both themes. */
export const MASCOT_TOKENS = [
  "--mascot-body",
  "--mascot-body-shade",
  "--mascot-screen",
  "--mascot-glyph",
  "--mascot-badge",
  "--mascot-blush",
  "--mascot-cape",
  "--mascot-cape-lining",
  "--mascot-burst",
  "--mascot-lost-body",
  "--mascot-lost-body-shade",
  "--mascot-lost-cape",
  "--mascot-lost-cape-lining",
] as const;

const v = (name: (typeof MASCOT_TOKENS)[number]) => `var(${name})`;

function colours(state: MascotState) {
  const lost = state === "lost";
  return {
    body: v(lost ? "--mascot-lost-body" : "--mascot-body"),
    shade: v(lost ? "--mascot-lost-body-shade" : "--mascot-body-shade"),
    cape: v(lost ? "--mascot-lost-cape" : "--mascot-cape"),
    lining: v(lost ? "--mascot-lost-cape-lining" : "--mascot-cape-lining"),
    screen: v("--mascot-screen"),
    glyph: v("--mascot-glyph"),
    badge: v("--mascot-badge"),
    blush: v("--mascot-blush"),
    burst: v("--mascot-burst"),
    muted: "var(--fg-4)",
  };
}

// Cape silhouettes per state, drawn in the character's own frame (the body
// box is x 13..87, y 18..90; the whole character is shifted 8 right so cape
// and body sit centred). The right edge tucks behind the body.
// The dash cape points straight back once the lean is applied, and its area
// sits inside the shipped capes' range (pinned by the test).
const CAPE: Record<MascotState, string> = {
  idle: "M38 21 C24 21 8 24 -8 18 C-3 30 -6 40 -12 47 C-1 49 -4 58 -9 66 C4 66 16 61 22 60 Z",
  celebrate: "M38 21 C22 12 4 2 -12 4 C-5 14 -8 23 -14 30 C-3 35 -8 44 -12 52 C2 54 16 54 22 56 Z",
  lost: "M34 22 C18 30 2 50 0 82 C6 79 10 82 15 85 C14 64 20 42 36 26 Z",
  dash: "M38 21 C25 24 10 29 -6 32 C-2 41 -5 49 -10 55 C-1 59 -4 66 -8 73 C4 70 14 64 22 61 Z",
};
const CAPE_SMALL: Record<MascotState, string> = {
  idle: "M38 21 C22 21 4 24 -10 20 C-9 34 -9 48 -7 62 C6 62 16 60 22 59 Z",
  celebrate: "M38 21 C20 12 2 4 -12 6 C-12 22 -12 38 -10 52 C2 54 16 54 22 56 Z",
  lost: "M34 22 C18 32 2 52 0 82 C7 82 11 84 16 85 C14 64 20 42 36 26 Z",
  dash: "M38 21 C24 25 6 30 -9 33 C-9 47 -9 60 -8 73 C4 70 14 64 22 61 Z",
};

/** The cape path the component draws for a state at a rendered size. */
export function capePath(state: MascotState, size: number): string {
  return (size <= SMALL_CAPE_MAX_PX ? CAPE_SMALL : CAPE)[state];
}

function burstRays(cx: number, cy: number, r1: number, r2: number, n: number): string {
  let d = "";
  for (let i = 0; i < n; i++) {
    const a = (i / n) * Math.PI * 2 + 0.2;
    const p = (r: number) => `${(cx + r * Math.cos(a)).toFixed(1)} ${(cy + r * Math.sin(a)).toFixed(1)}`;
    d += `M${p(r1)} L${p(r2)} `;
  }
  return d.trim();
}

const star4 = (x: number, y: number, s: number) =>
  `M${x} ${y - s} Q${x + s * 0.18} ${y - s * 0.18} ${x + s} ${y} Q${x + s * 0.18} ${y + s * 0.18} ${x} ${y + s} Q${x - s * 0.18} ${y + s * 0.18} ${x - s} ${y} Q${x - s * 0.18} ${y - s * 0.18} ${x} ${y - s} Z`;

function face(state: MascotState, glyph: string): MascotNode[] {
  const chevron = (d: string) =>
    el("path", { d, stroke: glyph, strokeWidth: 4.2, fill: "none", strokeLinecap: "round", strokeLinejoin: "round" });
  if (state === "celebrate")
    return [
      chevron("M33 37 L42 43 L33 49"),
      chevron("M67 37 L58 43 L67 49"),
      el("path", { d: "M43.5 53 Q50 53.6 56.5 53 Q55.5 61 50 61 Q44.5 61 43.5 53 Z", fill: glyph }),
    ];
  if (state === "dash")
    // Determined grin: the focused ">" eye and cursor, with the celebrate smile.
    return [
      chevron("M32 36 L41 42.5 L32 49"),
      el("rect", { ...part("cursor"), x: 55, y: 44, width: 13, height: 4.6, rx: 2.3, fill: glyph }),
      el("path", { d: "M43.5 53 Q50 53.6 56.5 53 Q55.5 61 50 61 Q44.5 61 43.5 53 Z", fill: glyph }),
    ];
  if (state === "lost")
    return [
      el("circle", { cx: 38, cy: 44, r: 3.6, fill: glyph }),
      el("rect", { ...part("cursor"), x: 56, y: 46, width: 12, height: 4.4, rx: 2.2, fill: glyph }),
      el("path", { d: "M45 57 L55 55.5", stroke: glyph, strokeWidth: 2.6, strokeLinecap: "round" }),
    ];
  return [
    chevron("M32 36 L41 42.5 L32 49"),
    el("rect", { ...part("cursor"), x: 55, y: 46, width: 13, height: 4.6, rx: 2.3, fill: glyph }),
    el("path", { d: "M44 55 Q49 59 56 53.5", stroke: glyph, strokeWidth: 2.6, fill: "none", strokeLinecap: "round" }),
  ];
}

/** How many afterimages the dash trails at a rendered size. */
export function dashGhostCount(size: number): number {
  return size <= SMALL_CAPE_MAX_PX ? 1 : 3;
}

// The dash body in the character's own frame. A ghost is only the cape and
// body silhouettes (no addressable parts, so the ghost group owns them).
function dashBody(c: ReturnType<typeof colours>, size: number, ghost: boolean): MascotNode[] {
  const small = size <= SMALL_CAPE_MAX_PX;
  const cape = capePath("dash", size);
  const body = { x: 13, y: 18, width: 74, height: 72, rx: 24, fill: c.body };
  if (ghost) return [el("path", { d: cape, fill: c.cape }), el("rect", body)];
  const capeChildren: MascotNode[] = [];
  if (!small) capeChildren.push(el("path", { ...part("cape-lining"), d: cape, fill: c.lining, transform: "translate(2.5 3.5)" }));
  capeChildren.push(el("path", { d: cape, fill: c.cape }));
  return [
    el("g", part("cape"), capeChildren),
    // The celebrate fist-pump arm and fist (same 5 x 9 arm, r 5.4 fist),
    // swung so that under the lean it points straight ahead.
    el("g", part("arms"), [
      el("ellipse", { cx: 92.4, cy: 36.6, rx: 5, ry: 9, transform: "rotate(68 92.4 36.6)", fill: c.shade }),
      el("circle", { cx: 102.6, cy: 32.6, r: 5.4, fill: c.shade }),
      el("ellipse", { cx: 13, cy: 62, rx: 4.4, ry: 7.2, transform: "rotate(48 13 62)", fill: c.shade }),
    ]),
    // The shipped feet, trailing a little.
    el("g", part("feet"), [
      el("ellipse", { cx: 35, cy: 90, rx: 7.5, ry: 4, transform: "rotate(-24 35 90)", fill: c.shade }),
      el("ellipse", { cx: 58, cy: 91, rx: 7.5, ry: 4, transform: "rotate(-24 58 91)", fill: c.shade }),
    ]),
    el("rect", { ...part("body"), ...body }),
    el("path", { ...part("gloss"), d: "M22 30 Q26 22 36 21", stroke: "#ffffff", strokeWidth: 3, fill: "none", strokeLinecap: "round", opacity: 0.35 }),
    el("rect", { ...part("screen"), x: 23, y: 28, width: 54, height: 40, rx: 14, fill: c.screen }),
    el("g", part("blush"), [
      el("circle", { cx: 28.5, cy: 61, r: 2.6, fill: c.blush, opacity: 0.55 }),
      el("circle", { cx: 71.5, cy: 61, r: 2.6, fill: c.blush, opacity: 0.55 }),
    ]),
    el("g", part("face"), face("dash", c.glyph)),
    el("g", part("badge"), [
      el("rect", { x: 54, y: 75, width: 5, height: 5, rx: 1.1, fill: c.badge }),
      el("rect", { x: 49, y: 80, width: 5, height: 5, rx: 1.1, fill: c.badge }),
    ]),
  ];
}

// The dash: afterimages behind, then the leaning flyer inside the roll (the
// loop flourish), hop (bob) and stretch (squash and stretch) wrappers. No
// ground shadow while airborne.
function dashNodes(size: number): MascotNode[] {
  const c = colours("dash");
  const lean = `rotate(${DASH_LEAN_DEG} 58 54)`;
  const ghosts: MascotNode[] = [];
  for (let i = dashGhostCount(size); i >= 1; i--) {
    ghosts.push(
      el("g", { ...part("ghost"), opacity: Number((0.3 / i).toFixed(2)), transform: `translate(${-20 * i} 0) ${lean}` }, [
        el("g", { transform: "translate(8 0)" }, dashBody(c, size, true)),
      ]),
    );
  }
  return [
    el("g", part("ghosts"), ghosts),
    el("g", part("roll"), [
      el("g", part("hop"), [
        el("g", part("stretch"), [
          el("g", { ...part("tilt"), transform: lean }, [el("g", { transform: "translate(8 0)" }, dashBody(c, size, false))]),
        ]),
      ]),
    ]),
  ];
}

/** The mascot's SVG children (inside a 0 0 100 100 viewBox; the dash
 *  reaches outside it, into the wide frame). */
export function mascotNodes(state: MascotState, size: number): MascotNode[] {
  if (state === "dash") return dashNodes(size);
  const c = colours(state);
  const cel = state === "celebrate";
  const lost = state === "lost";
  const small = size <= SMALL_CAPE_MAX_PX;
  const cape = capePath(state, size);

  const extras: MascotNode[] = [];
  if (cel) {
    extras.push(
      el("path", { ...part("burst"), d: burstRays(60, 50, 42, 50, 12), stroke: c.burst, strokeWidth: 3, fill: "none", strokeLinecap: "round" }),
    );
    if (!small) extras.push(el("path", { ...part("sparkle"), d: star4(4, 86, 4.5), fill: c.burst }));
  }
  if (lost)
    extras.push(
      el("g", part("thinking"), [
        el("circle", { cx: 78, cy: 10, r: 2, fill: c.muted }),
        el("circle", { cx: 84, cy: 6, r: 2.7, fill: c.muted }),
        el("circle", { cx: 91, cy: 1, r: 3.5, fill: c.muted }),
      ]),
    );

  const arms = cel
    ? [
        el("ellipse", { cx: 91, cy: 27, rx: 5, ry: 9, transform: "rotate(22 91 27)", fill: c.shade }),
        el("circle", { cx: 94, cy: 17, r: 5.4, fill: c.shade }),
        el("ellipse", { cx: 13, cy: 60, rx: 4.4, ry: 7.2, transform: "rotate(30 13 60)", fill: c.shade }),
      ]
    : [
        el("ellipse", { cx: 13, cy: 62, rx: 4.4, ry: 7.2, transform: "rotate(22 13 62)", fill: c.shade }),
        el("ellipse", { cx: 87, cy: 62, rx: 4.4, ry: 7.2, transform: "rotate(-22 87 62)", fill: c.shade }),
      ];

  const capeChildren: MascotNode[] = [];
  if (!small) capeChildren.push(el("path", { ...part("cape-lining"), d: cape, fill: c.lining, transform: "translate(2.5 3.5)" }));
  capeChildren.push(el("path", { d: cape, fill: c.cape }));

  const tiltAttrs: MascotNode["attrs"] = lost
    ? { ...part("tilt"), style: { transform: "rotate(-4deg)", transformOrigin: "50% 100%", transformBox: "fill-box" } }
    : part("tilt");

  return [
    el("ellipse", { ...part("ground"), cx: 56, cy: 95, rx: cel ? 18 : 26, ry: 3, fill: c.muted, opacity: 0.28 }),
    ...extras,
    el("g", part("hop"), [
      el("g", tiltAttrs, [
        el("g", { transform: "translate(8 0)" }, [
          el("g", part("cape"), capeChildren),
          el("g", part("arms"), arms),
          el("g", part("feet"), [
            el("ellipse", { cx: 38, cy: 90, rx: 7.5, ry: 4, fill: c.shade }),
            el("ellipse", { cx: 62, cy: 90, rx: 7.5, ry: 4, fill: c.shade }),
          ]),
          el("rect", { ...part("body"), x: 13, y: 18, width: 74, height: 72, rx: 24, fill: c.body }),
          el("path", { ...part("gloss"), d: "M22 30 Q26 22 36 21", stroke: "#ffffff", strokeWidth: 3, fill: "none", strokeLinecap: "round", opacity: 0.35 }),
          el("rect", { ...part("screen"), x: 23, y: 28, width: 54, height: 40, rx: 14, fill: c.screen }),
          el("g", part("blush"), [
            el("circle", { cx: 28.5, cy: 61, r: 2.6, fill: c.blush, opacity: 0.55 }),
            el("circle", { cx: 71.5, cy: 61, r: 2.6, fill: c.blush, opacity: 0.55 }),
          ]),
          el("g", part("face"), face(state, c.glyph)),
          el("g", part("badge"), [
            el("rect", { x: 54, y: 75, width: 5, height: 5, rx: 1.1, fill: c.badge }),
            el("rect", { x: 49, y: 80, width: 5, height: 5, rx: 1.1, fill: c.badge }),
          ]),
        ]),
      ]),
    ]),
  ];
}

/** Scoped CSS for one mascot instance. Every animation lives inside the
 *  prefers-reduced-motion: no-preference block, so a reduced-motion viewer
 *  gets the static frame with no JS involved. `size` matters only for the
 *  dash: at SMALL_CAPE_MAX_PX and below the loop flourish is dropped. */
export function mascotCss(scope: string, state: MascotState, size = 100): string {
  const s = `.${scope}`;
  const p = (name: MascotPart) => `${s} [data-part="${name}"]`;
  const k = (name: string) => `${scope}-${name}`;
  if (state === "dash") {
    const loop =
      size > SMALL_CAPE_MAX_PX
        ? `${p("roll")}{animation:${k("roll")} 5.2s cubic-bezier(.5,0,.5,1) infinite}@keyframes ${k("roll")}{0%,86%{transform:rotate(0)}100%{transform:rotate(-360deg)}}`
        : "";
    return (
      `${p("hop")},${p("stretch")}{transform-box:fill-box;transform-origin:center}` +
      `${p("roll")}{transform-box:fill-box;transform-origin:50% 38%}` +
      `${p("cape")}{transform-box:view-box;transform-origin:38px 22px}` +
      "@media (prefers-reduced-motion: no-preference){" +
      `${p("cursor")}{animation:${k("cur")} 1.1s steps(1) infinite}@keyframes ${k("cur")}{50%{opacity:0}}` +
      `${p("cape")}{animation:${k("cape")} .24s ease-in-out infinite}@keyframes ${k("cape")}{0%,100%{transform:skewY(0) scaleX(1)}30%{transform:skewY(-7deg) scaleX(1.08)}70%{transform:skewY(4deg) scaleX(.95)}}` +
      `${p("stretch")}{animation:${k("st")} .5s ease-in-out infinite alternate}@keyframes ${k("st")}{from{transform:scale(1.05,.96)}to{transform:scale(1.12,.9)}}` +
      `${p("hop")}{animation:${k("bob")} 1.2s ease-in-out infinite}@keyframes ${k("bob")}{0%,100%{transform:translate(0,0)}50%{transform:translate(0,-5%)}}` +
      `${p("ghosts")}{animation:${k("gs")} .3s ease-in-out infinite alternate}@keyframes ${k("gs")}{from{opacity:1}to{opacity:.7}}` +
      loop +
      "}"
    );
  }
  const base =
    `${p("hop")},${p("tilt")},${p("burst")},${p("sparkle")}{transform-box:fill-box;transform-origin:center}` +
    `${p("cape")}{transform-box:view-box;transform-origin:38px 22px}`;
  let motion = "";
  if (state === "idle") {
    motion =
      `${p("cursor")}{animation:${k("cur")} 1.1s steps(1) infinite}@keyframes ${k("cur")}{50%{opacity:0}}` +
      `${p("cape")}{animation:${k("cape")} 1.8s ease-in-out infinite}@keyframes ${k("cape")}{0%,100%{transform:skewY(0) scaleX(1)}50%{transform:skewY(-3deg) scaleX(.95)}}`;
  } else if (state === "celebrate") {
    motion =
      `${p("hop")}{animation:${k("hop")} .9s cubic-bezier(.3,.7,.4,1) infinite;transform-origin:50% 100%}` +
      `@keyframes ${k("hop")}{0%,100%{transform:translate(0,0) scale(1.06,.94)}15%{transform:translate(0,0) scale(1,1)}45%{transform:translate(3%,-9%) scale(.97,1.04)}75%{transform:translate(0,0)}}` +
      `${p("burst")}{animation:${k("burst")} .9s ease-out infinite}@keyframes ${k("burst")}{0%{transform:scale(.7);opacity:.2}40%{opacity:1}100%{transform:scale(1.12);opacity:0}}` +
      `${p("sparkle")}{animation:${k("tw")} .9s ease-in-out infinite}@keyframes ${k("tw")}{0%,100%{transform:scale(.4);opacity:.5}50%{transform:scale(1.15);opacity:1}}` +
      `${p("cape")}{animation:${k("cape")} .45s ease-in-out infinite}@keyframes ${k("cape")}{0%,100%{transform:skewY(0) scaleX(1)}50%{transform:skewY(-5deg) scaleX(1.05)}}`;
  } else {
    motion =
      `${p("tilt")}{animation:${k("sway")} 3.2s ease-in-out infinite;transform-origin:50% 100%}@keyframes ${k("sway")}{0%,100%{transform:rotate(-5deg)}50%{transform:rotate(-1deg)}}` +
      `${p("thinking")} circle{animation:${k("dot")} 1.5s ease-in-out infinite}${p("thinking")} circle:nth-child(2){animation-delay:.25s}${p("thinking")} circle:nth-child(3){animation-delay:.5s}` +
      `@keyframes ${k("dot")}{0%,100%{opacity:.35}50%{opacity:1}}` +
      `${p("cursor")}{animation:${k("cur")} 1.6s steps(1) infinite}@keyframes ${k("cur")}{50%{opacity:0}}` +
      `${p("cape")}{animation:${k("cape")} 3.2s ease-in-out infinite}@keyframes ${k("cape")}{0%,100%{transform:rotate(0)}50%{transform:rotate(2deg)}}`;
  }
  return `${base}@media (prefers-reduced-motion: no-preference){${motion}}`;
}

const kebab = (k: string) => (k === "viewBox" ? k : k.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`));
const escAttr = (v: string) => v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

function nodeMarkup(n: MascotNode): string {
  let attrs = "";
  for (const [key, val] of Object.entries(n.attrs)) {
    const text =
      typeof val === "object"
        ? Object.entries(val)
            .map(([sk, sv]) => `${kebab(sk)}:${sv}`)
            .join(";")
        : String(val);
    attrs += ` ${kebab(key)}="${escAttr(text)}"`;
  }
  return n.children ? `<${n.tag}${attrs}>${n.children.map(nodeMarkup).join("")}</${n.tag}>` : `<${n.tag}${attrs}/>`;
}

/**
 * mascotSvgMarkup renders one instance as standalone SVG markup, the same
 * element tree and scoped CSS shared/primitives/Obs.tsx renders. The
 * pre-mount boot screens use it (shared/lib/bootScreen.ts), since they run
 * before any JS. Decorative: aria-hidden, the surrounding status carries the
 * label.
 */
export function mascotSvgMarkup(state: MascotState, size: number, scope: string, wide = false): string {
  const f = mascotFrame(state, size, wide);
  return (
    `<svg class="${scope}" width="${f.width}" height="${f.height}" viewBox="${f.viewBox}" aria-hidden="true" focusable="false" data-state="${state}" style="overflow:visible">` +
    `<style>${mascotCss(scope, state, size)}</style>` +
    mascotNodes(state, size).map(nodeMarkup).join("") +
    "</svg>"
  );
}
