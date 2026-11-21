// Sidebar — the portal's left navigation rail, matching the local
// dashboard's shell (web/src/components/Sidebar.tsx): a fixed-width aside
// with the brand lockup in a header-height row, then the route list as
// vertical nav items with a small leading icon each. The portal has none of
// the dashboard's backend surfaces (watcher health, governance notices,
// collapse toggle, nav badges/counts) — this is the plain route rail
// that section needs.

import { NavLink } from "react-router-dom";
import { Icon } from "@shared/primitives/Icon";
import { getPersonalPlane } from "../api";
import { LEGACY_NAV_LABEL, LEGACY_ROUTE_ICONS, NAV_ITEMS, type NavItemDef } from "../lib/nav";
import { legacyView } from "../lib/personalModel";
import { BrandLockup } from "./BrandMark";

// NAV_ITEMS (lib/nav.ts) is the portal's route table, one distinct lucide
// icon per route (rendered through the shared <Icon>, so stroke and size
// match both dashboards). Page headers read the same table via routeIcon.

function NavRow({ item }: { item: NavItemDef }) {
  return (
    <NavLink
      to={item.to}
      className={({ isActive }) =>
        isActive ? "nav-item nav-item-active" : "nav-item"
      }
    >
      {/* The active item's icon takes the accent colour and a 2px
          accent bar marks its left edge (styles.css .nav-item-active). */}
      <span className="nav-item-icon" aria-hidden="true">
        <Icon icon={item.icon} size="md" />
      </span>
      <span className="nav-item-label">{item.label}</span>
    </NavLink>
  );
}

// The legacy section (Cloud Intelligence, the old personal plane) shows while
// the plane is serving: lib/personalModel.ts LEGACY_RULES.
export function Sidebar() {
  const legacy = legacyView(getPersonalPlane());
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <BrandLockup size={21} />
      </div>
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <NavRow key={item.to} item={item} />
        ))}
        {legacy.showNavSection && (
          <div role="group" aria-label={LEGACY_NAV_LABEL} className="mt-4">
            <div className="nav-section-label">{LEGACY_NAV_LABEL}</div>
            {LEGACY_ROUTE_ICONS.map((item) => (
              <NavRow key={item.to} item={item} />
            ))}
          </div>
        )}
      </nav>
    </aside>
  );
}
