import {
  Activity,
  ChartLine,
  DatabaseZap,
  DollarSign,
  FileCog,
  FolderKanban,
  Gauge,
  Hourglass,
  Inbox,
  LayoutDashboard,
  Mail,
  Lightbulb,
  Lock,
  MessagesSquare,
  Minimize2,
  Radar,
  Route,
  SatelliteDish,
  ScrollText,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Sparkles,
  Split,
  SquareTerminal,
  Trophy,
  Wrench,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { costLabel, dollarsShown } from "../../../shared/lib/format.ts";

// NavItem.icon is the lucide glyph itself, so the nav table below is the ONE
// place a page's icon is decided. The Sidebar and the command palette both
// render it through the shared <Icon> wrapper; nav.test.ts pins that every
// item's glyph is distinct (no two pages share an icon).
export type NavItem = {
  id: string;
  label: string;
  path: string;
  icon: LucideIcon;
};

export type NavGroup = {
  id: string;
  label: string;
  items: NavItem[];
};

// The cost page's entry follows the org's developer cost display (format.ts
// cost affordances): in token-usage mode it reads "Usage" with a non-dollar
// glyph, on the same /cost route. Getters, not values: this table is built
// at module load, before the boot-time gate sets the mode, and every reader
// (sidebar, breadcrumb, command palette, page header) reads it at render.
const costNavItem: NavItem = {
  id: "cost",
  get label() {
    return costLabel("Cost", "Usage");
  },
  path: "/cost",
  get icon() {
    return dollarsShown() ? DollarSign : Gauge;
  },
};

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "monitor",
    label: "Monitor",
    items: [
      { id: "overview", label: "Overview", path: "/", icon: LayoutDashboard },
      { id: "live", label: "Live", path: "/live", icon: Activity },
      { id: "sessions", label: "Sessions", path: "/sessions", icon: MessagesSquare },
      { id: "actions", label: "Actions", path: "/actions", icon: Zap },
      { id: "projects", label: "Projects", path: "/projects", icon: FolderKanban },
      { id: "security", label: "Security", path: "/security", icon: Shield },
      { id: "code-security", label: "Code security", path: "/code-security", icon: ShieldCheck },
      { id: "egress", label: "Egress", path: "/egress", icon: Route },
      { id: "search", label: "Search", path: "/search", icon: Search },
    ],
  },
  {
    id: "analyze",
    label: "Analyze",
    items: [
      costNavItem,
      { id: "plans", label: "Plans & limits", path: "/plans", icon: Hourglass },
      { id: "analysis", label: "Analysis", path: "/analysis", icon: ChartLine },
      { id: "tools", label: "Tools", path: "/tools", icon: Wrench },
    ],
  },
  {
    id: "optimize",
    label: "Optimize",
    items: [
      { id: "compression", label: "Compression", path: "/compression", icon: Minimize2 },
      { id: "cache", label: "Cache", path: "/cache", icon: DatabaseZap },
      { id: "suggestions", label: "Suggestions", path: "/suggestions", icon: Lightbulb },
      { id: "routing", label: "Routing", path: "/routing", icon: Split },
      { id: "benchmarks", label: "Benchmarks", path: "/benchmarks", icon: Trophy },
      { id: "discovery", label: "Discovery", path: "/discovery", icon: Radar },
      { id: "patterns", label: "Patterns", path: "/patterns", icon: Sparkles },
    ],
  },
  {
    id: "configure",
    label: "Configure",
    items: [
      { id: "policies", label: "Policies", path: "/policies", icon: ScrollText },
      { id: "agent-config", label: "AI tool settings", path: "/agent-config", icon: FileCog },
      { id: "privacy", label: "Privacy", path: "/privacy", icon: Lock },
      { id: "terminals", label: "Terminals", path: "/terminals", icon: SquareTerminal },
      { id: "remote", label: "Remote", path: "/remote", icon: SatelliteDish },
      { id: "messages", label: "Messages", path: "/messages", icon: Mail },
      { id: "requests", label: "Requests", path: "/requests", icon: Inbox },
      { id: "settings", label: "Settings", path: "/settings", icon: Settings },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

const NAV_BY_ID = new Map(NAV_ITEMS.map((i) => [i.id, i]));

/**
 * navIcon returns the sidebar glyph of the nav item with this id. Every
 * routed page passes `icon={navIcon("<id>")}` to its PageHeader, so a page
 * header and its nav entry resolve the icon from this ONE table and cannot
 * drift. An unknown id yields undefined (the header renders without a tile).
 */
export function navIcon(id: string): LucideIcon | undefined {
  return NAV_BY_ID.get(id)?.icon;
}
