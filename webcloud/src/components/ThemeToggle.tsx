// ThemeToggle — a small icon button that flips dark/light and persists the
// choice to localStorage "sb_theme" (the dashboard's contract). Optional
// nicety; the portal ships dark by default and works with the toggle absent.

import { useState } from "react";
import type { Theme } from "../theme";
import { applyTheme, readTheme, storeTheme } from "../theme";

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
    storeTheme(next);
  }

  const isDark = theme === "dark";
  return (
    <button
      type="button"
      className="icon-btn"
      onClick={toggle}
      aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
      title={isDark ? "Switch to light theme" : "Switch to dark theme"}
    >
      {isDark ? (
        // Moon
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden>
          <path
            d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"
            fill="currentColor"
          />
        </svg>
      ) : (
        // Sun
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden>
          <circle cx="12" cy="12" r="4" fill="currentColor" />
          <g stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4" />
          </g>
        </svg>
      )}
    </button>
  );
}
