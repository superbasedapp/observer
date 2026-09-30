// ThemeToggle - a small icon Button (the shared primitive) that flips dark/light and persists the
// choice to localStorage "sb_theme" (the dashboard's contract). Optional
// nicety; the portal ships dark by default and works with the toggle absent.

import { useState } from "react";
import { Moon, Sun } from "lucide-react";
import { Icon } from "@shared/primitives/Icon";
import { Tooltip } from "@shared/primitives/Tooltip";
import { Button } from "@shared/primitives/Button";
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
  const hint = isDark ? "Switch to light theme" : "Switch to dark theme";
  return (
    <Tooltip content={hint} side="bottom">
      <Button variant="secondary" className="h-8 w-8 !p-0" onClick={toggle} aria-label={hint}>
        <Icon icon={isDark ? Moon : Sun} size={15} />
      </Button>
    </Tooltip>
  );
}
