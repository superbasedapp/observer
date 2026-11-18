import { Link } from "react-router-dom";
import { ChevronRight, ExternalLink, UserRound } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Card } from "@shared/primitives/Card";
import { Icon } from "@shared/primitives/Icon";
import { Pill } from "@shared/primitives/Pill";
import type { PortalOrg } from "../../api";
import { PERSONAL_ORG_FACTS, personalCardView } from "../../lib/personalModel";

// PersonalOrgCard - the account home's personal dashboard (Getting started
// v2; D-IND-8: an individual is an org of one). The dashboard is created at
// sign-in, so with none yet the card says it is being set up (the page
// polls); once active it opens the dashboard from a button. Its address
// (a u-... host) is never shown as text. Presentational: the page fetches;
// personalCardView (lib/personalModel.ts) decides what shows.

export interface PersonalOrgCardProps {
  /** org is the account's personal org, absent until it appears. */
  org?: PortalOrg;
}

/** personalOpenUrl is the personal dashboard's Open button target: the
 * server-built open_url, or none (the console never derives it). */
export function personalOpenUrl(org: PortalOrg): string | null {
  return org.open_url ?? null;
}

export function PersonalOrgCard({ org }: PersonalOrgCardProps) {
  const v = personalCardView({ org, creating: false });
  const open = org && v.showLinks ? personalOpenUrl(org) : null;
  return (
    <Card
      title={PERSONAL_ORG_FACTS.title}
      icon={UserRound}
      sub={v.sentence}
      actions={v.pill && <Pill variant={v.pill.tone}>{v.pill.label}</Pill>}
    >
      <div className="flex flex-col gap-3">
        <p className="text-[12px] leading-snug text-fg-2">{PERSONAL_ORG_FACTS.privacy}</p>
        <p className="text-[11px] leading-snug text-fg-3">{PERSONAL_ORG_FACTS.members}</p>
        <div className="flex flex-wrap items-center gap-2">
          {open && (
            <Button variant="primary" size="sm" iconRight={ExternalLink} href={open} target="_blank" rel="noopener">
              Open your dashboard
            </Button>
          )}
          {org && (
            <Link
              to={"/orgs/" + encodeURIComponent(org.org_id)}
              className="inline-flex items-center gap-1 text-[12px] font-medium text-accent hover:underline"
            >
              Details and billing
              <Icon icon={ChevronRight} size="sm" />
            </Link>
          )}
        </div>
      </div>
    </Card>
  );
}
