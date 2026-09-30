import assert from "node:assert/strict";
import test from "node:test";

import {
  TERMINAL_THEMES,
  parseTerminalThemePref,
  resolveTerminalTheme,
} from "../../../shared/lib/terminalTheme.ts";

// The light terminal theme (backlog item 1: "terminals only have a dark
// background") must keep every ANSI color legible: TUIs paint yellow, cyan
// and even "white" text on the default background.

function lum(hex: string): number {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
  const f = (c: number) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const ANSI = [
  "foreground",
  "black",
  "red",
  "green",
  "yellow",
  "blue",
  "magenta",
  "cyan",
  "white",
  "brightBlack",
  "brightRed",
  "brightGreen",
  "brightYellow",
  "brightBlue",
  "brightMagenta",
  "brightCyan",
  "brightWhite",
] as const;

test("every light-theme ANSI color clears WCAG AA on the canvas", () => {
  const t = TERMINAL_THEMES.light;
  for (const k of ANSI) {
    const c = contrast(t[k], t.background);
    assert.ok(c >= 4.5, `${k} ${t[k]} is ${c.toFixed(2)}:1`);
  }
});

test("dark-theme foreground colors (not black) clear AA on the canvas", () => {
  const t = TERMINAL_THEMES.dark;
  for (const k of ANSI) {
    if (k === "black" || k === "brightBlack") continue;
    const c = contrast(t[k], t.background);
    assert.ok(c >= 4.5, `${k} ${t[k]} is ${c.toFixed(2)}:1`);
  }
});

test("preference resolution", () => {
  assert.equal(resolveTerminalTheme("app", "light"), "light");
  assert.equal(resolveTerminalTheme("app", "dark"), "dark");
  assert.equal(resolveTerminalTheme("dark", "light"), "dark");
  assert.equal(resolveTerminalTheme("light", "dark"), "light");
  assert.equal(parseTerminalThemePref("bogus"), "app");
  assert.equal(parseTerminalThemePref(null), "app");
  assert.equal(parseTerminalThemePref("light"), "light");
});
