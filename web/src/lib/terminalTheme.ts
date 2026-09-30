import { useCallback, useEffect, useState } from "react";
import {
  TERMINAL_THEMES,
  parseTerminalThemePref,
  resolveTerminalTheme,
  type TerminalColors,
  type TerminalThemeName,
  type TerminalThemePref,
} from "@shared/lib/terminalTheme";
import { useTheme } from "@/lib/theme";

// Terminal theme preference for the node dashboard (Settings > Appearance):
// "app" (default) follows the dashboard theme, "dark" / "light" pin one.
// Stored per browser in localStorage (a convenience, never load-bearing); a
// window event keeps every open terminal panel in sync when it changes.

const STORAGE_KEY = "superbased.terminalTheme";
const CHANGE_EVENT = "sb-terminal-theme";

function readPref(): TerminalThemePref {
  try {
    return parseTerminalThemePref(localStorage.getItem(STORAGE_KEY));
  } catch {
    return "app";
  }
}

export function setTerminalThemePref(pref: TerminalThemePref): void {
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // Storage unavailable (private window): the choice lasts this page view.
  }
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT, { detail: pref }));
}

export type TerminalThemeState = {
  pref: TerminalThemePref;
  /** The concrete theme to render. */
  name: TerminalThemeName;
  /** xterm.js theme object for `name`. */
  colors: TerminalColors;
  setPref: (p: TerminalThemePref) => void;
};

export function useTerminalTheme(): TerminalThemeState {
  const { effective } = useTheme();
  const [pref, setPrefState] = useState<TerminalThemePref>(readPref);
  useEffect(() => {
    const onChange = (e: Event) => {
      const next = (e as CustomEvent<unknown>).detail;
      setPrefState(parseTerminalThemePref(next));
    };
    window.addEventListener(CHANGE_EVENT, onChange);
    return () => window.removeEventListener(CHANGE_EVENT, onChange);
  }, []);
  const setPref = useCallback((p: TerminalThemePref) => {
    setPrefState(p);
    setTerminalThemePref(p);
  }, []);
  const name = resolveTerminalTheme(pref, effective);
  return { pref, name, colors: TERMINAL_THEMES[name], setPref };
}
