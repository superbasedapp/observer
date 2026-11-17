import { useState, type FormEvent, type ReactNode } from "react";
import { Building2, ExternalLink, Gauge, Hourglass, Rocket, UserRound } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Card } from "@shared/primitives/Card";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { Input } from "@shared/primitives/Input";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Pill } from "@shared/primitives/Pill";
import { fmtInt } from "@shared/lib/format";
import type { OrgDetail } from "../../api";
import { PLAN_SOURCE_TEXT, ROLE_LABEL, TEAM_NAME_MAX } from "../../lib/orgsModel";
import { PERSONAL_ORG_FACTS, isPersonal, orgNoun, stageViewFor } from "../../lib/personalModel";
import { dateWithRelative } from "../billing/util";
import { OrgStatusPill } from "./OrgList";

// OrgDetailView - one org's page (plan 07 M6.5): where its setup stands
// (including a create waiting on the capacity waitlist), the plan its signed
// entitlement document carries and why, the seats its tenant last reported,
// the deep link to the tenant's "Connect a machine" page once it exists, and
// the rename form for an owner or admin (refused by the server while the org
// is still being created). Presentational: the page fetches, polls and hands
// the billing card in as `billing` and the danger-zone deletion card (M6.9,
// OrgDeletionCard) in as `deletion`, last on the page.
//
// A personal org (D-IND-8: an org of one) reads as one: personal wording for
// every stage and card, what a personal org is (one member, metadata only
// unless opted in), the plan without seats, and no role or members language
// that implies anyone else can join. The address (slug) is never editable;
// only the display name is, and only when the server says so (can.rename).

export interface OrgDetailViewProps {
  detail: OrgDetail;
  /** The billing card (or its loading / error frame); null hides it. */
  billing: ReactNode;
  /** The "Delete organization" card (or its loading / error frame); absent
   * or null hides it. */
  deletion?: ReactNode;
  onRename: (name: string) => Promise<void>;
}

/** ProvisioningCard says where an org's setup stands. */
export function ProvisioningCard({ detail }: { detail: OrgDetail }) {
  const p = detail.org.provisioning;
  if (!p) return null;
  const v = stageViewFor(p.stage, detail.org.kind);
  return (
    <Card title={`Setting up your ${orgNoun(detail.org.kind)}`} icon={p.stage === "waitlisted" ? Hourglass : Rocket}>
      <div className="flex items-start gap-3">
        <Pill variant={v.tone}>{v.label}</Pill>
        <p className="text-[12px] leading-snug text-fg-2">{v.sentence}</p>
      </div>
      {(p.queued_at || (p.next_attempt_at && v.pending)) && (
        <DefinitionList className="mt-3 divide-y divide-line-1 text-[12px]">
          {p.queued_at && <DefinitionRow label="Requested" value={dateWithRelative(p.queued_at)} />}
          {p.next_attempt_at && v.pending && p.attempts > 0 && (
            <DefinitionRow label="Next try" value={dateWithRelative(p.next_attempt_at)} />
          )}
        </DefinitionList>
      )}
    </Card>
  );
}

function RenameCard({ detail, onRename }: { detail: OrgDetail; onRename: (n: string) => Promise<void> }) {
  const [name, setName] = useState(detail.org.display_name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const personal = isPersonal(detail.org);
  const trimmed = name.trim();
  const valid = trimmed.length > 0 && [...trimmed].length <= TEAM_NAME_MAX;
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid || trimmed === detail.org.display_name) return;
    setBusy(true);
    setError(null);
    try {
      await onRename(trimmed);
    } catch (err) {
      setError(err instanceof Error ? err.message : `could not rename the ${orgNoun(detail.org.kind)}`);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card
      title={personal ? "Display name" : "Team name"}
      sub={personal ? "The name shown on its dashboard. The address stays the same." : "The address stays the same."}
    >
      <form className="flex max-w-[520px] items-end gap-2" onSubmit={submit}>
        <div className="flex-1">
          <Input
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={busy}
            error={error ?? (valid ? undefined : `Use 1 to ${TEAM_NAME_MAX} characters.`)}
          />
        </div>
        <Button type="submit" size="sm" variant="secondary" loading={busy} disabled={!valid || trimmed === detail.org.display_name}>
          Save
        </Button>
      </form>
    </Card>
  );
}

export function OrgDetailView({ detail, billing, deletion, onRename }: OrgDetailViewProps) {
  const { org, plan, seats } = detail;
  const personal = isPersonal(org);
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={org.display_name}
        icon={personal ? UserRound : Building2}
        sub={org.host ? <span className="break-all font-mono">{org.host}</span> : org.slug}
        right={
          <div className="flex items-center gap-2">
            {personal ? (
              <Pill variant="neutral">Personal</Pill>
            ) : (
              <Pill variant="neutral">{ROLE_LABEL[org.console_role] ?? org.console_role}</Pill>
            )}
            <OrgStatusPill org={org} />
          </div>
        }
      />
      <ProvisioningCard detail={detail} />
      {personal && (
        <Card title="Your personal dashboard" icon={UserRound}>
          <ul className="flex list-disc flex-col gap-1.5 pl-5 text-[12px] leading-snug text-fg-2">
            <li>{PERSONAL_ORG_FACTS.members}</li>
            <li>{PERSONAL_ORG_FACTS.privacy}</li>
          </ul>
        </Card>
      )}
      {detail.launch_url && (
        <Card
          title="Connect your machines"
          icon={Rocket}
          sub={
            personal
              ? "Open your personal dashboard to install Observer on a machine and connect it."
              : "Open your team's dashboard to install Observer on a machine and connect it."
          }
        >
          <Button variant="primary" size="sm" iconRight={ExternalLink} href={detail.launch_url} target="_blank" rel="noopener">
            Open the install page
          </Button>
        </Card>
      )}
      {(plan || (seats && !personal)) && (
        <Card title={personal ? "Plan" : "Plan and seats"} icon={Gauge}>
          <DefinitionList className="divide-y divide-line-1 text-[12px]">
            {plan && <DefinitionRow label="Plan" value={plan.label || plan.name} />}
            {plan && (
              <DefinitionRow
                label="Why"
                value={
                  (plan.source === "launch" || plan.source === "org_grant") && plan.not_after
                    ? `${PLAN_SOURCE_TEXT[plan.source]}, until ${dateWithRelative(plan.not_after)}`
                    : (PLAN_SOURCE_TEXT[plan.source] ?? plan.source)
                }
              />
            )}
            {!personal && plan?.seats_min ? <DefinitionRow label="Minimum seats" value={fmtInt(plan.seats_min)} /> : null}
            {!personal && seats && <DefinitionRow label="Seats in use" value={`${fmtInt(seats.in_use)} (reported ${seats.day})`} />}
          </DefinitionList>
        </Card>
      )}
      {billing}
      {detail.can.rename && <RenameCard detail={detail} onRename={onRename} />}
      {deletion}
    </div>
  );
}
