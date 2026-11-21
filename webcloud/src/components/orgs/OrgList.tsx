import { Link } from "react-router-dom";
import { ChevronRight, Hourglass } from "lucide-react";
import { Icon } from "@shared/primitives/Icon";
import { Pill } from "@shared/primitives/Pill";
import type { PortalOrg } from "../../api";
import { ROLE_LABEL, orgStatusView } from "../../lib/orgsModel";

// OrgList - the account home's list of the signed-in user's orgs (plan 07
// M6.5): one row per org with its address, the caller's console role and the
// org's state (a team still being created reads by its stage, so a
// waitlisted team says "Waitlisted"). Presentational: the page fetches.

/** OrgStatusPill is an org's state as one pill. */
export function OrgStatusPill({ org }: { org: PortalOrg }) {
  const v = orgStatusView(org);
  return (
    <Pill variant={v.tone} icon={org.provisioning?.stage === "waitlisted" ? Hourglass : undefined}>
      {v.label}
    </Pill>
  );
}

export function OrgList({ orgs }: { orgs: PortalOrg[] }) {
  return (
    <ul className="divide-y divide-line-1 rounded-3 border border-line-1 bg-bg-1" aria-label="Your teams">
      {orgs.map((o) => (
        <li key={o.org_id}>
          <Link
            to={"/orgs/" + encodeURIComponent(o.org_id)}
            className="sb-lift flex items-center gap-3 px-4 py-3 hover:bg-bg-2"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-[13px] font-semibold text-fg-0">{o.display_name}</span>
                {o.kind === "personal" && <Pill variant="neutral">Personal</Pill>}
              </div>
              <div className="mt-0.5 truncate font-mono text-[11px] text-fg-3">{o.host ?? o.slug}</div>
            </div>
            <span className="text-[11px] text-fg-3">{ROLE_LABEL[o.console_role] ?? o.console_role}</span>
            <OrgStatusPill org={o} />
            <Icon icon={ChevronRight} size="sm" className="shrink-0 text-fg-4" />
          </Link>
        </li>
      ))}
    </ul>
  );
}
