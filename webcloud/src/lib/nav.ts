import {
  CreditCard,
  FileText,
  Gauge,
  History,
  LayoutDashboard,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";

// The portal's route table: one distinct lucide icon per route. The sidebar
// renders it, and every page header takes its icon from the same row via
// routeIcon, so a page and its nav item always show the same glyph. Overview
// and Sessions reuse the org dashboard's icons for the same concepts.

export interface NavItemDef {
  to: string;
  label: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: NavItemDef[] = [
  { to: "/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/sessions", label: "Sessions", icon: History },
  { to: "/community", label: "Community", icon: Users },
  { to: "/usage", label: "Usage", icon: Gauge },
  { to: "/billing", label: "Billing", icon: CreditCard },
  { to: "/privacy", label: "Privacy & devices", icon: ShieldCheck },
];

// routeIcon returns the nav icon for a route (the sidebar row with that exact
// `to`), else `fallback`, a generic page glyph, never a guessed neighbour's.
export function routeIcon(to: string, fallback: LucideIcon = FileText): LucideIcon {
  return NAV_ITEMS.find((item) => item.to === to)?.icon ?? fallback;
}
