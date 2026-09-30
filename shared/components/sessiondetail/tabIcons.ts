import type { LucideIcon } from "lucide-react";
import {
  Brain,
  Cpu,
  DatabaseZap,
  Gauge,
  LayoutDashboard,
  ListTodo,
  MessagesSquare,
  Plug,
} from "lucide-react";

// SESSION_TAB_ICONS: the one icon per session-detail drawer tab, shared by the
// node drawer (web SessionDetailPanel) and the org drawer (web2 Sessions) so
// the two stay in parity (standing rule: node session-detail changes reach
// the org drawer through shared code). A tab id with no row renders no icon.
export const SESSION_TAB_ICONS: Readonly<Record<string, LucideIcon>> = {
  overview: LayoutDashboard,
  messages: MessagesSquare,
  cost: Gauge,
  cache: DatabaseZap,
  tasks: ListTodo,
  mcp: Plug,
  intel: Brain,
  system: Cpu,
};

/** sessionTabIcon - the drawer tab's icon, undefined for an unlisted tab. */
export function sessionTabIcon(id: string): LucideIcon | undefined {
  return SESSION_TAB_ICONS[id];
}
