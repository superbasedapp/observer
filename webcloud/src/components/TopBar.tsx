// TopBar - the full-width top status bar above <main>, matching the local
// dashboard's shell (web/src/components/TopBar.tsx). The portal has none of
// the dashboard's operational surfaces (export/refresh, status pills,
// instance switcher, help drawer) - this is the plain header the app needs:
// a page label on the left, and the signed-in account + density + theme
// toggles + sign out on the right.
//
// The account chip shows WHO is signed in, in the most human form available:
// the display name the identity provider gave, then the email, then a
// shortened account id. The full email (and the account id, which support
// asks for) stays reachable through the chip's themed tooltip, so the bar
// carries the identity without spending a line of chrome on a UUID.

import { useNavigate } from "react-router-dom";
import { getAccountId, getProfile, logout } from "../api";
import { clearConsentState } from "../consent";
import { ThemeToggle } from "./ThemeToggle";
import { BrandLockup } from "./BrandMark";
import { fmtShortId } from "@shared/lib/format";
import { Button } from "@shared/primitives/Button";
import { Tooltip } from "@shared/primitives/Tooltip";
import { DensityToggle } from "@shared/primitives/DensityToggle";
import { DENSITY_STORAGE_KEY } from "@shared/lib/density";
import { useDensity } from "@shared/lib/useDensity";

/** accountChip resolves what to show and what to reveal on hover. Returns null
 * when nothing at all is known, so the chip is omitted rather than blank. */
function accountChip(
  accountId: string | null,
  profile: { email: string; display_name: string } | null,
): { label: string; title: string[]; mono: boolean } | null {
  const name = profile?.display_name?.trim() ?? "";
  const email = profile?.email?.trim() ?? "";

  // The tooltip always carries the full identity: the email when there is one,
  // and the account id, which is what support and the CLI ask for.
  const titleParts: string[] = [];
  if (email) titleParts.push(email);
  if (accountId) titleParts.push("Account " + accountId);
  const title = titleParts.length > 0 ? titleParts : ["Signed in"];

  if (name) return { label: name, title, mono: false };
  if (email) return { label: email, title, mono: false };
  if (accountId)
    return { label: fmtShortId(accountId), title, mono: true };
  return null;
}

export function TopBar() {
  const navigate = useNavigate();
  // Comfortable / Compact, a per-browser preference like the theme; the
  // index.html pre-paint script stamps it before first paint.
  const [density, setDensity] = useDensity(DENSITY_STORAGE_KEY.webcloud);
  const chip = accountChip(getAccountId(), getProfile());

  async function onSignOut() {
    try {
      await logout();
    } finally {
      clearConsentState();
      navigate("/");
    }
  }

  return (
    <header className="topbar">
      {/* The page's own heading (with its intro line) names the page, so the
          bar no longer repeats it. On phones, where the sidebar collapses to
          a nav strip without its brand row, the bar carries the brand. */}
      <div className="topbar-brand">
        <BrandLockup size={17} />
      </div>
      <div className="topbar-actions">
        {chip && (
          <Tooltip
            side="bottom"
            content={
              <span className="flex flex-col gap-0.5">
                {chip.title.map((line) => (
                  <span key={line}>{line}</span>
                ))}
              </span>
            }
          >
            <span
              tabIndex={0}
              className={
                (chip.mono ? "topbar-account mono" : "topbar-account") +
                " focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
              }
            >
              {chip.label}
            </span>
          </Tooltip>
        )}
        {/* Not on phones: the bar there already holds the brand, the account
            chip, the theme toggle and Sign out, and one more control clips
            the brand. The stored choice still applies at every width. */}
        <span className="hidden sm:inline-flex">
          <DensityToggle value={density} onChange={setDensity} labels="wide" />
        </span>
        <ThemeToggle />
        <Button variant="ghost" size="sm" onClick={onSignOut}>
          Sign out
        </Button>
      </div>
    </header>
  );
}
