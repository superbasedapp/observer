// Theme toggle: the choice persists in localStorage under "sb_theme" and is
// applied by stamping data-theme on <html>. Dark is the default when nothing
// is stored or storage is unavailable. index.html runs the same logic as a
// pre-paint script so the boot screen and first paint never flash.
//
// Why "sb_theme" and not the node dashboard's "superbased.theme": the portal
// is served from the superbased.app domain family, where the marketing site
// and arcade already use "sb_theme"; the node dashboard runs on localhost (a
// different origin), so the two keys never meet. The portal also offers only
// dark / light, not "system".

export type Theme = "dark" | "light";

const KEY = "sb_theme";

export function readTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
}

export function storeTheme(theme: Theme): void {
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Storage unavailable (private mode / quota) — the toggle still works
    // for this page load; it just will not be remembered.
  }
}

/** initTheme applies the stored (or default dark) theme at boot. Call once
 * before the app renders so there is no flash of the wrong palette. A
 * `?theme=light|dark` query param overrides and is persisted, so a theme can
 * be previewed or linked directly. */
export function initTheme(): void {
  let theme = readTheme();
  try {
    const q = new URLSearchParams(window.location.search).get("theme");
    if (q === "light" || q === "dark") {
      theme = q;
      storeTheme(theme);
    }
  } catch {
    /* no query params available — use the stored/default theme */
  }
  applyTheme(theme);
}
