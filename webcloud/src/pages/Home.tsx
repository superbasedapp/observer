import { useEffect, useState, type ReactNode } from "react";
import { History, Plus } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "@shared/primitives/Button";
import { EmptyState } from "@shared/primitives/EmptyState";
import { Icon } from "@shared/primitives/Icon";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Stagger } from "@shared/primitives/Motion";
import { getConnectHome, getPersonalPlane, listOrgs } from "../api";
import type { ConnectHome, OrgsList } from "../api";
import { CardSkeleton, ErrorPanel, ListSkeleton } from "../components/LoadState";
import { MachineCard } from "../components/connect/MachineCard";
import { TeamRows } from "../components/connect/TeamRows";
import { PersonalOrgCard, personalOpenUrl } from "../components/orgs/PersonalOrgCard";
import { homeMachineView, tabForUserAgent } from "../lib/connectModel";
import { routeIcon } from "../lib/nav";
import { teamCapView } from "../lib/orgsModel";
import { EARLIER_RESULTS_LINK, legacyView, personalCardView, personalOrg, teamOrgsOf } from "../lib/personalModel";
import { usePortalQuery } from "../lib/query";

// Home - the account home (Getting started v2; it replaces Organizations).
// First the machine card: with no machine yet, "Connect your first machine"
// with the install command for this browser's system and a live waiting
// line that flips to "Connected: <machine>" by itself (the page polls the
// connect machines route); then the personal dashboard, created at sign-in
// (the page polls while it is being set up); then Teams with "Create a team"
// and one row per team. A personal dashboard's address is opened from
// buttons only, never shown as text.

const MACHINE_POLL_MS = 4_000;
const SETUP_POLL_MS = 5_000;

function SectionTitle({ children, right }: { children: string; right?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-[13px] font-semibold uppercase tracking-wide text-fg-2">{children}</h2>
      {right}
    </div>
  );
}

export function Home() {
  const navigate = useNavigate();
  // Poll only while something is still moving: the personal dashboard or a
  // team being set up, or no machine connected yet.
  const [settingUp, setSettingUp] = useState(true);
  const [waiting, setWaiting] = useState(true);
  const orgsQ = usePortalQuery<OrgsList>("orgs", listOrgs, [], { refreshMs: settingUp ? SETUP_POLL_MS : 0 });
  const data = orgsQ.data;
  const personal = personalOrg(data?.orgs);
  const teams = teamOrgsOf(data?.orgs);
  const personalView = personalCardView({ org: personal, creating: false });
  const personalUrl = personal && personalView.showLinks ? personalOpenUrl(personal) : null;

  const homeQ = usePortalQuery<ConnectHome>("connect:home", getConnectHome, [], { refreshMs: waiting ? MACHINE_POLL_MS : 0 });
  const machine = homeMachineView(homeQ.data, personalUrl);
  const moving = personalView.pending || teams.some((t) => t.status === "provisioning");
  useEffect(() => {
    if (data) setSettingUp(moving);
  }, [data, moving]);
  useEffect(() => {
    setWaiting(machine.poll);
  }, [machine.poll]);
  const cap = teamCapView(data?.team_orgs);
  const legacy = legacyView(getPersonalPlane());
  const initialTab = tabForUserAgent(typeof navigator === "undefined" ? "" : navigator.userAgent);

  if (orgsQ.error && !data) {
    return <ErrorPanel variant="page" what="your dashboards" error={orgsQ.error} onRetry={orgsQ.reload} />;
  }
  return (
    <Stagger className="flex flex-col gap-6">
      <PageHeader
        title="Home"
        icon={routeIcon("/home")}
        sub="Your machines, your personal dashboard and your teams."
      />
      <section className="flex flex-col gap-3" aria-label="Machines">
        {homeQ.error && !homeQ.data ? (
          <ErrorPanel what="your machines" error={homeQ.error} onRetry={homeQ.reload} />
        ) : !homeQ.data ? (
          <CardSkeleton />
        ) : (
          <MachineCard view={machine} initialTab={initialTab} />
        )}
      </section>
      <section className="flex flex-col gap-3" aria-label="Personal dashboard">
        <SectionTitle>Personal dashboard</SectionTitle>
        {!data ? <CardSkeleton /> : <PersonalOrgCard org={personal} />}
      </section>
      <section className="flex flex-col gap-3" aria-label="Teams">
        <SectionTitle
          right={
            <Button
              variant="primary"
              size="sm"
              iconLeft={Plus}
              disabled={!cap.canCreate}
              onClick={() => navigate("/orgs/new")}
            >
              Create a team
            </Button>
          }
        >
          Teams
        </SectionTitle>
        {cap.note && !cap.canCreate && (
          <p role="status" className="text-[12px] text-fg-2">
            {cap.note}
          </p>
        )}
        {!data ? (
          <ListSkeleton />
        ) : teams.length === 0 ? (
          <EmptyState
            title="You are not in a team yet"
            body="A team shares one dashboard across everyone's machines, with full detail. Create one, or ask a teammate to invite you."
            to="/orgs/new"
            toLabel="Create a team"
          />
        ) : (
          <TeamRows teams={teams} />
        )}
      </section>
      {legacy.showEarlierLink && (
        <p className="text-[11px] text-fg-3">
          <Link to={EARLIER_RESULTS_LINK.to} className="inline-flex items-center gap-1 hover:text-fg-1 hover:underline">
            <Icon icon={History} size="sm" />
            {EARLIER_RESULTS_LINK.label}
          </Link>
        </p>
      )}
    </Stagger>
  );
}
