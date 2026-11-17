import { ExternalLink, Laptop } from "lucide-react";
import { Card } from "@shared/primitives/Card";
import { Icon } from "@shared/primitives/Icon";
import type { MachineLink } from "../../lib/orgsModel";

// MachinesPanel - where to see your machines (plan 07 M6.5; wave 15
// C2.front-door-4 B): one link per active team to that team's own dashboard
// page listing your machines in it. The console no longer reads each team
// from the browser and adds them up (the cross-origin aggregation of M6.0
// A13 is dropped), so it shows no cross-team total. Every URL is the
// server's (portal_orgs.go machines_page_url); machineLinks
// (lib/orgsModel.ts) builds the input.

export function MachinesPanel({ links }: { links: MachineLink[] }) {
  return (
    <Card
      title="Your machines"
      icon={Laptop}
      sub="Each team lists the machines you have connected to it on its own dashboard."
    >
      {links.length === 0 ? (
        <p className="text-[12px] text-fg-3">None of your teams is ready yet. Once one is, its machines page is linked here.</p>
      ) : (
        <ul className="divide-y divide-line-1 text-[12px]" aria-label="Machines by team">
          {links.map((l) => (
            <li key={l.orgId} className="flex items-center gap-3 py-2">
              <span className="min-w-0 flex-1 truncate text-fg-1">{l.orgName}</span>
              <span className="hidden truncate font-mono text-[11px] text-fg-3 sm:inline">{l.host}</span>
              <a
                href={l.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex shrink-0 items-center gap-1 font-medium text-accent hover:underline"
              >
                Open machines
                <Icon icon={ExternalLink} size="sm" />
              </a>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
