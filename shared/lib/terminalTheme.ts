// Terminal color themes (xterm.js ITheme shape) for every surface that renders
// a terminal. Terminals used to be dark-only (a hardcoded #0b0b0f). They now
// follow the app theme by default, or a pinned preference.
//
// Structural type only: this file never imports @xterm/xterm, so it stays out
// of the shell bundle (xterm itself is a lazy chunk) and runs under node --test.
// The panel chrome around the terminal reads the matching CSS tokens
// (--term-bg / --term-chrome / --term-banner / --term-pop in tokens.css) via
// data-theme-scope, so chrome and canvas always agree.

export type TerminalThemeName = "dark" | "light";
/** "app" follows the app theme; "dark" / "light" pin one. */
export type TerminalThemePref = "app" | TerminalThemeName;

export type TerminalColors = {
  background: string;
  foreground: string;
  cursor: string;
  cursorAccent: string;
  selectionBackground: string;
  selectionForeground?: string;
  black: string;
  red: string;
  green: string;
  yellow: string;
  blue: string;
  magenta: string;
  cyan: string;
  white: string;
  brightBlack: string;
  brightRed: string;
  brightGreen: string;
  brightYellow: string;
  brightBlue: string;
  brightMagenta: string;
  brightCyan: string;
  brightWhite: string;
};

// Dark: the long-standing #0b0b0f canvas with an ANSI palette tuned to the
// dashboard's accent / semantic hues.
const DARK: TerminalColors = {
  background: "#0b0b0f",
  foreground: "#e6e6e6",
  cursor: "#93b1ff",
  cursorAccent: "#0b0b0f",
  selectionBackground: "rgba(124, 158, 255, 0.35)",
  black: "#1a1d27",
  red: "#f87171",
  green: "#34d399",
  yellow: "#fbbf24",
  blue: "#7c9eff",
  magenta: "#c084fc",
  cyan: "#22d3ee",
  white: "#d6dae3",
  brightBlack: "#6b7388",
  brightRed: "#fca5a5",
  brightGreen: "#6ee7b7",
  brightYellow: "#fde68a",
  brightBlue: "#a9c0ff",
  brightMagenta: "#d8b4fe",
  brightCyan: "#67e8f9",
  brightWhite: "#f5f7fb",
};

// Light: every ANSI color darkened until it clears 4.5:1 against the
// #fbfbfd canvas, so TUIs that paint yellow/cyan/white text stay legible.
// "white" / "brightWhite" map to dark grays on purpose: a TUI that prints
// "white" text on the default background must not vanish.
const LIGHT: TerminalColors = {
  background: "#fbfbfd",
  foreground: "#1b1f28",
  cursor: "#3850dd",
  cursorAccent: "#fbfbfd",
  selectionBackground: "rgba(71, 99, 237, 0.22)",
  black: "#1b1f28",
  red: "#c52929",
  green: "#067a55",
  yellow: "#8a5a00",
  blue: "#2f4fd8",
  magenta: "#8b2fc9",
  cyan: "#0a6e86",
  white: "#56607a",
  brightBlack: "#646d86",
  brightRed: "#a31d1d",
  brightGreen: "#05613f",
  brightYellow: "#704700",
  brightBlue: "#243fb8",
  brightMagenta: "#7121a8",
  brightCyan: "#07596d",
  brightWhite: "#0c0f15",
};

export const TERMINAL_THEMES: Record<TerminalThemeName, TerminalColors> = {
  dark: DARK,
  light: LIGHT,
};

/** resolveTerminalTheme picks the concrete theme for a preference. */
export function resolveTerminalTheme(
  pref: TerminalThemePref,
  appTheme: TerminalThemeName,
): TerminalThemeName {
  return pref === "app" ? appTheme : pref;
}

/** parseTerminalThemePref normalises a stored value (unknown -> "app"). */
export function parseTerminalThemePref(v: unknown): TerminalThemePref {
  return v === "dark" || v === "light" || v === "app" ? v : "app";
}
