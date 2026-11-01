// The pre-mount boot screen every app's index.html shows before any JS or
// stylesheet loads (D-665..D-669): Obs in the Hero dash pose flying through
// the same sky as the React stage (shared/primitives/ObsFlight.tsx). It must
// stay JS-free, so the markup and CSS are GENERATED here from the mascot data
// (shared/lib/mascot.ts) and the scenery (shared/lib/obsFlight.ts), and each
// index.html holds exactly bootScreenHtml(app) between the markers, pinned
// byte for byte by web/src/lib/bootScreen.test.ts (the T-551 theme
// pre-paint pattern). To change it, change the source, then paste the block
// the test prints.
//
// No stylesheet is loaded yet, so the tokens the screen uses are inlined
// below (BOOT_TOKENS); the same test pins every value to
// shared/styles/tokens.css in both themes. Reduced motion needs no JS
// either: the static idle pose replaces the flying one by a media query, the
// clouds stand still and the streaks are hidden.

import { mascotSvgMarkup } from "./mascot.ts";
import { flightSceneCss, flightSceneMarkup } from "./obsFlight.ts";
import type { ThemeApp } from "./theme.ts";

/** BOOT_SCREEN_BEGIN opens the generated block in an index.html. */
export const BOOT_SCREEN_BEGIN = "<!-- boot-screen:begin";
/** BOOT_SCREEN_END closes it. */
export const BOOT_SCREEN_END = "<!-- boot-screen:end -->";

/** The caption per app (it is also the status label). */
export const BOOT_LABELS: Record<ThemeApp, string> = {
  web: "Loading dashboard…",
  web2: "Loading org dashboard…",
  webcloud: "Loading…",
};

/** Rendered size of the boot Obs (CSS px for the 100 unit frame). */
export const BOOT_OBS_PX = 84;

/**
 * BOOT_TOKENS: every token the boot screen reads, per theme, copied from
 * shared/styles/tokens.css (the dark block is the default :root, the light
 * block is :root[data-theme="light"]). Pinned value for value by the test.
 */
export const BOOT_TOKENS: Record<"dark" | "light", Record<string, string>> = {
  dark: {
    "--bg-0": "#08090d",
    "--fg-1": "#e2e6ef",
    "--fg-3": "#848ca2",
    "--fg-4": "#5d6478",
    "--line-2": "#262a36",
    "--mascot-body": "#ffb000",
    "--mascot-body-shade": "#c98700",
    "--mascot-screen": "#11163a",
    "--mascot-glyph": "#ffc23d",
    "--mascot-badge": "#1b2470",
    "--mascot-blush": "#ff8fb8",
    "--mascot-cape": "#7c98ff",
    "--mascot-cape-lining": "#3e5ad0",
    "--mascot-burst": "#7c9eff",
    "--flight-sky-top": "#0b1030",
    "--flight-sky-bottom": "#171c3c",
    "--flight-cloud": "#2a3366",
    "--flight-cloud-far": "#1d2450",
    "--flight-speed": "rgba(124, 152, 255, 0.38)",
  },
  light: {
    "--bg-0": "#f4f5f9",
    "--fg-1": "#1b1f28",
    "--fg-3": "#646d86",
    "--fg-4": "#8d94a8",
    "--line-2": "#dde0e8",
    "--mascot-body": "#2647e8",
    "--mascot-body-shade": "#1631b4",
    "--mascot-screen": "#11163a",
    "--mascot-glyph": "#ffc23d",
    "--mascot-badge": "#ffffff",
    "--mascot-blush": "#ff8fb8",
    "--mascot-cape": "#ffb000",
    "--mascot-cape-lining": "#c98200",
    "--mascot-burst": "#ffb000",
    "--flight-sky-top": "#d7e3ff",
    "--flight-sky-bottom": "#f1f5ff",
    "--flight-cloud": "#ffffff",
    "--flight-cloud-far": "#e9efff",
    "--flight-speed": "rgba(38, 71, 232, 0.3)",
  },
};

const decls = (t: Record<string, string>) =>
  Object.entries(t)
    .map(([k, v]) => `${k}:${v}`)
    .join(";");

/** bootScreenCss is the boot screen's whole stylesheet (one line). */
export function bootScreenCss(): string {
  return (
    `#sbo-boot{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:0 16px;font-family:Inter,system-ui,-apple-system,sans-serif;${decls(BOOT_TOKENS.dark)};background:var(--bg-0)}` +
    `@media (prefers-color-scheme: light){:root:not([data-theme]) #sbo-boot{${decls(BOOT_TOKENS.light)}}}` +
    `:root[data-theme="light"] #sbo-boot{${decls(BOOT_TOKENS.light)}}` +
    ".sbo-rest{display:none}" +
    "@media (prefers-reduced-motion: reduce){.sbo-fly{display:none}.sbo-rest{display:inline-block}}" +
    flightSceneCss("sbo")
  );
}

/**
 * bootScreenHtml is the generated block for one app: the begin marker, the
 * #root container holding the boot screen, its <style>, and the end marker,
 * each line prefixed with indent. React replaces #root's content on mount.
 */
export function bootScreenHtml(app: ThemeApp, indent = "    "): string {
  const label = BOOT_LABELS[app];
  const fly = mascotSvgMarkup("dash", BOOT_OBS_PX, "sbo-dash");
  // The reduced-motion pose stands centred in the square frame.
  const rest = mascotSvgMarkup("idle", BOOT_OBS_PX, "sbo-idle");
  const lines = [
    `${BOOT_SCREEN_BEGIN} ${app}: generated from shared/lib/bootScreen.ts by bootScreenHtml; do not edit by hand. -->`,
    '<div id="root">',
    `  <div id="sbo-boot" role="status" aria-label="${label}">`,
    '    <div class="sbo-sky">',
    `      ${flightSceneMarkup("sbo")}`,
    `      <div class="sbo-flyer" aria-hidden="true"><span class="sbo-fly">${fly}</span><span class="sbo-rest">${rest}</span></div>`,
    `      <div class="sbo-caption" aria-hidden="true">${label}</div>`,
    "    </div>",
    "  </div>",
    "</div>",
    `<style>${bootScreenCss()}</style>`,
    BOOT_SCREEN_END,
  ];
  return lines.map((l) => indent + l).join("\n");
}

/**
 * bootScreenBlock extracts the generated block (begin marker line through
 * end marker line, with their indentation) from an index.html, or null.
 */
export function bootScreenBlock(html: string): string | null {
  const lines = html.split("\n");
  const start = lines.findIndex((l) => l.trimStart().startsWith(BOOT_SCREEN_BEGIN));
  const end = lines.findIndex((l) => l.trimStart().startsWith(BOOT_SCREEN_END));
  if (start < 0 || end < start) return null;
  return lines.slice(start, end + 1).join("\n");
}
