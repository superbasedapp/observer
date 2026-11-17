import { Link } from "react-router-dom";
import { ExternalLink, UserPlus } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Pill } from "@shared/primitives/Pill";
import type { PortalOrg } from "../../api";
import { teamMembersLabel } from "../../lib/connectModel";
import { OrgStatusPill } from "../orgs/OrgList";

// TeamRows - the account home's teams (Getting started v2): one row per team
// with its member count, "Full detail" (what a machine connected to a team
// sends), its state while it is being set up, and Open and Invite people
// once it is ready (both server-built links). The name opens the team's
// details page here. Presentational: the page fetches.

export function TeamRows({ teams }: { teams: PortalOrg[] }) {
  return (
    <ul className="divide-y divide-line-1 rounded-3 border border-line-1 bg-bg-1" aria-label="Your teams">
      {teams.map((t) => (
        <li key={t.org_id} className="flex flex-wrap items-center gap-3 px-4 py-3">
          <div className="min-w-0 flex-1">
            <Link
              to={"/orgs/" + encodeURIComponent(t.org_id)}
              className="truncate text-[13px] font-semibold text-fg-0 hover:underline"
            >
              {t.display_name}
            </Link>
            <div className="mt-0.5 text-[11px] text-fg-3">{teamMembersLabel(t)}</div>
          </div>
          <Pill variant="info">Full detail</Pill>
          {t.status !== "active" && <OrgStatusPill org={t} />}
          {t.dashboard_url && (
            <Button variant="secondary" size="sm" iconRight={ExternalLink} href={t.dashboard_url} target="_blank" rel="noopener">
              Open
            </Button>
          )}
          {t.invite_url && (
            <Button variant="ghost" size="sm" iconLeft={UserPlus} href={t.invite_url} target="_blank" rel="noopener">
              Invite people
            </Button>
          )}
        </li>
      ))}
    </ul>
  );
}
