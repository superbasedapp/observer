// Sidebar — the portal's left navigation rail, matching the local
// dashboard's shell (web/src/components/Sidebar.tsx): a fixed-width aside
// with the brand lockup in a header-height row, then the route list as
// vertical nav items with a small leading icon each. The portal has none of
// the dashboard's backend surfaces (watcher health, governance notices,
// collapse toggle, nav badges/counts) — this is the plain six-route rail
// that section needs.

import { NavLink } from "react-router-dom";
import { Icon } from "@shared/primitives/Icon";
import { NAV_ITEMS } from "../lib/nav";
import { BrandLockup } from "./BrandMark";

// NAV_ITEMS (lib/nav.ts) is the portal's route table, one distinct lucide
// icon per route (rendered through the shared <Icon>, so stroke and size
// match both dashboards). Page headers read the same table via routeIcon.

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
            {/* The active item's icon takes the accent colour and a 2px
                accent bar marks its left edge (styles.css .nav-item-active). */}
            <span className="nav-item-icon" aria-hidden="true">
              <Icon icon={item.icon} size="md" />
            </span>
            <span className="nav-item-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
