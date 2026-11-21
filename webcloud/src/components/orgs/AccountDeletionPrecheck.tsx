import { Link } from "react-router-dom";
import { Callout } from "@shared/primitives/Callout";
import type { AccountDeletionBlocker, AccountDeletionPrecheck, OrgRef } from "../../api";
import { accountBlockerView } from "../../lib/deletionModel";

// AccountDeletionPrecheck - what the account deletion would hit, read before
// the step-up (plan 07 M6.9, GET /portal/api/account/deletion-precheck): the
// teams that block it, each with why and the way out (a link to that team's
// page in this console), the personal dashboard deleted with the
// account, and the team memberships it removes. A team keeps its own data:
// the team is the controller of what its members' machines sent it, so
// leaving does not delete that data. The rules are deletionModel.ts's.

function orgName(o: OrgRef): string {
  return o.display_name || o.slug || o.org_id;
}

/** BlockerList names each blocking team, why, and the way out. Shared by the
 * precheck and the account_deletion_blocked refusal (DeletionError). */
export function BlockerList({ blockers }: { blockers: AccountDeletionBlocker[] }) {
  return (
    <ul className="mt-1 space-y-1.5" data-testid="deletion-blockers">
      {blockers.map((b) => {
        const v = accountBlockerView(b.code);
        return (
          <li key={b.org_id + ":" + b.code} className="text-[12px] leading-snug">
            <strong className="text-fg-1">{orgName(b)}</strong>: {v.why} {v.wayOut}{" "}
            {v.linkToTeam && (
              <Link to={"/orgs/" + encodeURIComponent(b.org_id)} className="font-medium underline">
                Open {orgName(b)}
              </Link>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** AccountDeletionPrecheckPanel renders the precheck above the delete
 * action. */
export function AccountDeletionPrecheckPanel({ precheck }: { precheck: AccountDeletionPrecheck }) {
  const { blockers, personal_org: personal, memberships_removed: memberships } = precheck;
  return (
    <div className="mb-3 flex flex-col gap-3">
      {blockers.length > 0 && (
        <div>
          <Callout tone="danger" title="Your account cannot be deleted yet">
            {blockers.length === 1 ? "One team needs a change first." : "These teams need a change first."}
          </Callout>
          <BlockerList blockers={blockers} />
        </div>
      )}
      {personal && (
        <p className="text-[12px] leading-snug text-fg-2" data-testid="deletion-personal-org">
          Deleted with your account: your personal dashboard{" "}
          <strong className="text-fg-1">{orgName(personal)}</strong> and its data.
        </p>
      )}
      {memberships.length > 0 && (
        <div className="text-[12px] leading-snug text-fg-2" data-testid="deletion-memberships">
          <p>
            You leave {memberships.length === 1 ? "this team" : "these teams"}. What your machines sent{" "}
            {memberships.length === 1 ? "it stays with the team" : "them stays with each team"}, which controls that
            data:
          </p>
          <ul className="ml-4 mt-1 list-disc space-y-0.5">
            {memberships.map((m) => (
              <li key={m.org_id}>{orgName(m)}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
