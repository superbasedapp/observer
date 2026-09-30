import {
  Activity,
  ChartLine,
  DatabaseZap,
  DollarSign,
  FolderKanban,
  LayoutDashboard,
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
  Sparkles,
  Split,
  SquareTerminal,
  Trophy,
  Wrench,
  Zap,
  type LucideIcon,
} from "lucide-react";

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
      { id: "egress", label: "Egress", path: "/egress", icon: Route },
      { id: "search", label: "Search", path: "/search", icon: Search },
    ],
  },
  {
    id: "analyze",
    label: "Analyze",
    items: [
      { id: "cost", label: "Cost", path: "/cost", icon: DollarSign },
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
      { id: "privacy", label: "Privacy", path: "/privacy", icon: Lock },
      { id: "terminals", label: "Terminals", path: "/terminals", icon: SquareTerminal },
      { id: "remote", label: "Remote", path: "/remote", icon: SatelliteDish },
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
