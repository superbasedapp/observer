// TopBar - the full-width top status bar above <main>, matching the local
// dashboard's shell (web/src/components/TopBar.tsx). The portal has none of
// the dashboard's operational surfaces (export/refresh, status pills,
// instance switcher, help drawer) - this is the plain header the app needs:
// a page label on the left, and the signed-in account + theme toggle + sign
// out on the right.
//
// The account chip shows WHO is signed in, in the most human form available:
// the display name the identity provider gave, then the email, then a
// shortened account id. The full email (and the account id, which support
// asks for) stays reachable through the chip's title tooltip, so the bar
// carries the identity without spending a line of chrome on a UUID.

import { useLocation, useNavigate } from "react-router-dom";
import { getAccountId, getProfile, logout } from "../api";
import { clearConsentState } from "../consent";
import { ThemeToggle } from "./ThemeToggle";
import { fmtShortId } from "@shared/lib/format";

const PAGE_TITLES: Record<string, string> = {
  "/overview": "Overview",
  "/sessions": "Sessions",
  "/community": "Community",
  "/usage": "Usage",
  "/billing": "Billing",
  "/privacy": "Privacy & devices",
};

function pageTitle(pathname: string): string {
  if (PAGE_TITLES[pathname]) return PAGE_TITLES[pathname];
  if (pathname.startsWith("/sessions/")) return "Session detail";
  return "";
}

/** accountChip resolves what to show and what to reveal on hover. Returns null
 * when nothing at all is known, so the chip is omitted rather than blank. */
function accountChip(
  accountId: string | null,
  profile: { email: string; display_name: string } | null,
): { label: string; title: string; mono: boolean } | null {
  const name = profile?.display_name?.trim() ?? "";
  const email = profile?.email?.trim() ?? "";

  // The tooltip always carries the full identity: the email when there is one,
  // and the account id, which is what support and the CLI ask for.
  const titleParts: string[] = [];
  if (email) titleParts.push(email);
  if (accountId) titleParts.push("Account " + accountId);
  const title = titleParts.length > 0 ? titleParts.join("\n") : "Signed in";

  if (name) return { label: name, title, mono: false };
  if (email) return { label: email, title, mono: false };
  if (accountId)
    return { label: fmtShortId(accountId), title, mono: true };
  return null;
}

export function TopBar() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
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
      <div className="topbar-title">{pageTitle(pathname)}</div>
      <div className="topbar-actions">
        {chip && (
          <span
            className={chip.mono ? "topbar-account mono" : "topbar-account"}
            title={chip.title}
          >
            {chip.label}
          </span>
        )}
        <ThemeToggle />
        <button className="btn btn-ghost btn-sm" onClick={onSignOut}>
          Sign out
        </button>
      </div>
    </header>
  );
}
