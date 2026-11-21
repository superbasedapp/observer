import {
  Activity,
  BellRing,
  ChartColumn,
  FileText,
  FlaskConical,
  MessageSquareText,
  Spline,
  Star,
  Users,
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
  UserRound,
  Wrench,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { costLabel, dollarsShown } from "../../../shared/lib/format.ts";
import { PRODUCT_NAMES } from "../../../shared/lib/productNames.ts";

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
  // Your apps (Plane A lane B5, plan W2-5, D17): the LLM apps the user
  // builds, observed on this machine. Shown only when app observability is
  // on (APPS_NAV_IDS, Sidebar); Egress and Policies joined it from Monitor
  // and Configure, since both read only /api/obs.
  {
    id: "apps",
    label: PRODUCT_NAMES.planea_local,
    items: [
      { id: "app-traces", label: "Traces", path: "/apps/traces", icon: Spline },
      { id: "app-sessions", label: "Sessions", path: "/apps/sessions", icon: MessageSquareText },
      { id: "app-analytics", label: "Analytics", path: "/apps/analytics", icon: ChartColumn },
      { id: "app-end-users", label: "End users", path: "/apps/end-users", icon: Users },
      { id: "app-evals", label: "Evals", path: "/apps/evals", icon: FlaskConical },
      { id: "app-scores", label: "Scores", path: "/apps/scores", icon: Star },
      { id: "app-prompts", label: "Prompts", path: "/apps/prompts", icon: FileText },
      { id: "app-alerts", label: "Alerts", path: "/apps/alerts", icon: BellRing },
      { id: "policies", label: "Policies", path: "/policies", icon: ScrollText },
      { id: "egress", label: "Egress", path: "/egress", icon: Route },
    ],
  },
  {
    id: "configure",
    label: "Configure",
    items: [
      { id: "you", label: "You", path: "/you", icon: UserRound },
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

/** APPS_NAV_IDS: the Your apps group's items, which leave the nav until app
 *  observability answers on this machine (Sidebar; the first-run card on
 *  the Overview offers to turn it on). */
export const APPS_NAV_IDS: readonly string[] = NAV_GROUPS.find((g) => g.id === "apps")?.items.map((i) => i.id) ?? [];

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

/**
 * navGroupsForTrack puts the AI Apps group first when the daemon's
 * getting-started track is "apps" or "both" (first-run plan revision 2,
 * section 2.4 and decision 4): order only, nothing hidden or collapsed.
 * Any other track (or none) keeps the order as given.
 */
export function navGroupsForTrack<G extends { id: string }>(groups: readonly G[], track: string | null | undefined): G[] {
  if (track !== "apps" && track !== "both") return [...groups];
  const at = groups.findIndex((g) => g.id === "apps");
  if (at <= 0) return [...groups];
  return [groups[at], ...groups.slice(0, at), ...groups.slice(at + 1)];
}
