import {
  Building2,
  CreditCard,
  FileText,
  Gauge,
  History,
  KeyRound,
  LayoutDashboard,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";

// The portal's route table: one distinct lucide icon per route. The sidebar
// renders it, and every page header takes its icon from the same row via
// routeIcon, so a page and its nav item always show the same glyph.
//
// D-IND-8: the console home is Organizations (the personal org first, then
// teams). The old personal portal pages (Overview, Sessions, Community,
// Usage) are not part of the one-platform console: while the personal plane
// is serving they stay reachable under a clearly labelled "Cloud
// Intelligence (legacy)" section (LEGACY_NAV_LABEL, LEGACY_ROUTE_ICONS;
// operator ruling 2026-11-16: nothing is retired before the end-to-end
// sign-off), decided by lib/personalModel.ts LEGACY_RULES.

export interface NavItemDef {
  to: string;
  label: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: NavItemDef[] = [
  // Plan 07 M6.5 + D-IND-8: the account's orgs, the personal org first.
  { to: "/home", label: "Home", icon: Building2 },
  { to: "/billing", label: "Billing", icon: CreditCard },
  { to: "/privacy", label: "Privacy & machines", icon: ShieldCheck },
  // C2: passkeys and recovery codes (portalmfa.go).
  { to: "/security", label: "Sign-in security", icon: KeyRound },
];

/** LEGACY_NAV_LABEL heads the navigation section of the old personal pages. */
export const LEGACY_NAV_LABEL = "AI summaries";

/** LEGACY_ROUTE_ICONS are the old personal pages: the legacy navigation
 * section's rows and their page headers' icons. */
export const LEGACY_ROUTE_ICONS: NavItemDef[] = [
  { to: "/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/sessions", label: "Sessions", icon: History },
  { to: "/community", label: "Community", icon: Users },
  { to: "/usage", label: "Usage", icon: Gauge },
];

// routeIcon returns the icon for a route (the nav row, or the legacy row,
// with that exact `to`), else `fallback`, a generic page glyph, never a
// guessed neighbour's.
export function routeIcon(to: string, fallback: LucideIcon = FileText): LucideIcon {
  return (
    NAV_ITEMS.find((item) => item.to === to)?.icon ??
    LEGACY_ROUTE_ICONS.find((item) => item.to === to)?.icon ??
    fallback
  );
}
