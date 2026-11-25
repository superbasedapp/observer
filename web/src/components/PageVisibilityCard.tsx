import { Link } from "react-router-dom";
import { ChartShell, Pill, Table } from "@/components/primitives";
import { NAV_ITEMS } from "@/lib/nav";
import { pageRequestLink } from "@/lib/requestEntry";
import { NODE_TAB_ROUTES } from "@/lib/pageTabRoutes";
import { governedOrgLabel, useGovernance } from "@/lib/governance";
import { onlineHref, orgDisplayLabelSentence, type VisibilityEntry } from "@/lib/visibility";

// PageVisibilityCard is the Privacy page's answer to "which pages did my
// organization hide or lock on this machine, and why". It reads the same
// resolved visibility block (GET /api/governance) every other surface filters
// on, so it can never list a page the nav still shows. Renders nothing when
// every page and Settings section is visible (every individual node).

const LEVEL_LABEL: Record<string, string> = {
  hidden: "Hidden",
  read_only: "Read-only",
};

// The decider is the organization's NAME (never its id): the org's own choice
// shows who made it, a default says it is the managed-machine default.
const DEFAULT_SOURCE_LABEL = "Default for organization-managed machines";
// A page-access grant (T-435) shows a hidden page read-only until it ends.
const GRANT_SOURCE_LABEL = "Your access request (read-only until the grant ends)";

function sourceLabel(source: string, orgDecider: string): string {
  if (source === "default") return DEFAULT_SOURCE_LABEL;
  if (source === "grant") return GRANT_SOURCE_LABEL;
  return orgDecider;
}

// settingsLabel renders a Settings section id ("cachetrack") readably. The
// Settings page owns the real labels; this card only needs a legible name.
function settingsLabel(id: string): string {
  const special: Record<string, string> = {
    otel: "OTel export",
    mcp: "MCP tools",
    cachetrack: "Cache tracking",
    org: "Org sharing",
    tools: "Connected tools",
    terminal: "Session attach",
    cloud: "Cloud Intelligence",
    process: "Process capture",
    browser: "Browser capture",
    secrets: "Secrets scrubbing",
    tasks: "Task tracking",
  };
  return special[id] ?? id.charAt(0).toUpperCase() + id.slice(1);
}

/** requestId is set on a hidden page or tab: the one a page-access request
 *  (T-435) can ask to see. */
type Row = { key: string; label: string; entry: VisibilityEntry; requestId?: string };

export function PageVisibilityCard() {
  const gov = useGovernance();
  const vis = gov.data?.visibility;
  if (!vis) return null;
  const orgDecider = orgDisplayLabelSentence(gov.data?.notice?.org_display_name, gov.data?.org_name);
  const rows: Row[] = [];
  // Pages in sidebar order, then Settings sections by name.
  for (const n of NAV_ITEMS) {
    const entry = vis.sections?.[n.id];
    if (!entry || entry.level === "visible") continue;
    rows.push({ key: `page:${n.id}`, label: `${n.label} page`, entry, requestId: entry.level === "hidden" ? n.id : undefined });
  }
  // Tabs the organization hid on a page that is still shown (T-132).
  for (const id of vis.hidden_tabs ?? []) {
    const [navId, tab] = id.split("/", 2);
    const route = NODE_TAB_ROUTES.find((r) => r.navId === navId);
    const page = NAV_ITEMS.find((n) => n.id === navId);
    const tabLabel = route ? (route.tabs.labels as Record<string, string>)[tab] : undefined;
    rows.push({
      key: `tab:${id}`,
      label: `${page?.label ?? navId} › ${tabLabel ?? tab} tab`,
      entry: vis.tabs?.[id] ?? { level: "hidden", source: "org" },
      requestId: id,
    });
  }
  const settingsRows = Object.entries(vis.settings ?? {})
    .filter(([, entry]) => entry.level !== "visible")
    .map(([id, entry]) => ({ key: `settings:${id}`, label: `Settings: ${settingsLabel(id)}`, entry }))
    .sort((a, b) => a.label.localeCompare(b.label));
  rows.push(...settingsRows);
  if (rows.length === 0) return null;
  // Who can change it, and where (operator ruling 2, 2026-11-24): the owner
  // of a personal organization changes it themselves on their dashboard.
  const online = gov.data?.online;
  const owner = online?.kind === "personal";
  const placeHref = onlineHref(online?.visibility.href);
  const placeLabel = online?.visibility.label || "Settings > Developer dashboards";

  return (
    <ChartShell
      title={owner ? "Pages hidden or locked by your personal dashboard" : "Pages managed by your organization"}
      sub={
        owner
          ? `What your personal dashboard hid or locked on this machine. The daemon refuses the same pages, so this list is exactly what applies. You are its owner, so you can change any of them in ${placeLabel}.`
          : `What ${governedOrgLabel(gov.data)} hid or locked on this machine. The daemon refuses the same pages, so this list is exactly what applies. Your administrator can make any of them available.`
      }
    >
      {owner && placeHref && (
        <a
          href={placeHref}
          target="_blank"
          rel="noreferrer"
          className="mb-2 inline-block text-[11.5px] font-medium text-accent hover:text-accent-strong"
          data-testid="page-visibility-online"
        >
          Open {placeLabel}
        </a>
      )}
      <Table
        head={
          <tr className="text-left">
            <th className="py-1.5 pr-3 font-medium">Page</th>
            <th className="py-1.5 pr-3 font-medium">On this machine</th>
            <th className="py-1.5 font-medium">Decided by</th>
          </tr>
        }
      >
        {rows.map((r) => (
          <tr key={r.key} className="border-t border-line-1 first:border-t-0">
            <td className="py-1.5 pr-3 align-top text-fg-1">{r.label}</td>
            <td className="py-1.5 pr-3 align-top">
              <Pill variant={r.entry.level === "hidden" ? "warn" : "info"}>
                {LEVEL_LABEL[r.entry.level] ?? r.entry.level}
              </Pill>
              {r.requestId && (
                <Link to={pageRequestLink(r.requestId)} className="ml-2 text-[11.5px] text-accent hover:underline">
                  Request access
                </Link>
              )}
            </td>
            <td className="py-1.5 align-top text-[11.5px] text-fg-2">{sourceLabel(r.entry.source, orgDecider)}</td>
          </tr>
        ))}
      </Table>
    </ChartShell>
  );
}
