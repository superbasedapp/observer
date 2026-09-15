// Sidebar — the portal's left navigation rail, matching the local
// dashboard's shell (web/src/components/Sidebar.tsx): a fixed-width aside
// with the brand lockup in a header-height row, then the route list as
// vertical nav items with a small leading icon each. The portal has none of
// the dashboard's backend surfaces (watcher health, governance notices,
// collapse toggle, nav badges/counts) — this is the plain six-route rail
// that section needs.

import { NavLink } from "react-router-dom";
import { BrandLockup } from "./BrandMark";

type NavIcon =
  | "overview"
  | "sessions"
  | "community"
  | "usage"
  | "billing"
  | "privacy";

interface NavItemDef {
  to: string;
  label: string;
  icon: NavIcon;
}

const NAV_ITEMS: NavItemDef[] = [
  { to: "/overview", label: "Overview", icon: "overview" },
  { to: "/sessions", label: "Sessions", icon: "sessions" },
  { to: "/community", label: "Community", icon: "community" },
  { to: "/usage", label: "Usage", icon: "usage" },
  { to: "/billing", label: "Billing", icon: "billing" },
  { to: "/privacy", label: "Privacy & devices", icon: "privacy" },
];

export function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <BrandLockup size={21} />
      </div>
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              isActive ? "nav-item nav-item-active" : "nav-item"
            }
          >
            <span className="nav-item-icon" aria-hidden="true">
              <NavIconGlyph icon={item.icon} />
            </span>
            <span className="nav-item-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}

// NavIconGlyph — hand-rolled inline SVGs, matching the app-wide icon
// convention (16px, viewBox 0 0 16 16, stroke=currentColor, strokeWidth 1.4,
// round caps/joins; see web/src/components/icons.tsx).
function NavIconGlyph({ icon }: { icon: NavIcon }) {
  switch (icon) {
    case "overview":
      return (
        <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
          <path
            d="M1 8S3.5 3.5 8 3.5 15 8 15 8s-2.5 4.5-7 4.5S1 8 1 8Z"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.4" />
        </svg>
      );
    case "sessions":
      return (
        <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
          <path
            d="M2.5 4.5h1M2.5 8h1M2.5 11.5h1M6 4.5h8M6 8h8M6 11.5h8"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      );
    case "community":
      return (
        <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
          <circle cx="5.6" cy="6" r="2" stroke="currentColor" strokeWidth="1.4" />
          <path
            d="M1.6 13c0-2.24 1.79-3.6 4-3.6s4 1.36 4 3.6"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
          <circle cx="11.2" cy="5.3" r="1.5" stroke="currentColor" strokeWidth="1.4" />
          <path
            d="M9.9 9.15c1.9.28 3.2 1.53 3.55 3.15"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      );
    case "usage":
      return (
        <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
          <path
            d="M3 13V8M8 13V3M13 13V6.5"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      );
    case "billing":
      return (
        <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
          <rect
            x="1.5"
            y="4"
            width="13"
            height="8"
            rx="1.3"
            stroke="currentColor"
            strokeWidth="1.4"
          />
          <path d="M1.5 6.6h13" stroke="currentColor" strokeWidth="1.4" />
          <path
            d="M4 9.8h3"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      );
    case "privacy":
      return (
        <svg viewBox="0 0 16 16" width="16" height="16" fill="none">
          <path
            d="M8 1.5 13.2 3.4v4.15c0 3.35-2.28 5.35-5.2 6.95-2.92-1.6-5.2-3.6-5.2-6.95V3.4L8 1.5Z"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinejoin="round"
          />
        </svg>
      );
  }
}
