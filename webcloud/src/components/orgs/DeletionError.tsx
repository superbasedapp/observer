import { Link } from "react-router-dom";
import type { AccountDeletionBlocker } from "../../api";
import { ACCOUNT_DELETION_BLOCKED } from "../../lib/deletionModel";
import { PAYS_FOR_LIVE_ORG } from "../../lib/orgsModel";
import { BlockerList } from "./AccountDeletionPrecheck";

// DeletionError - the account deletion's refusal line (Privacy, "Delete my
// data"). The server's message is shown as it came. Two refusals add the way
// out:
//   - pays_for_live_org (C2.front-door-5 A): the account pays for a team that
//     is still live; links to the teams, whose billing page ends it.
//   - account_deletion_blocked (plan 07 M6.9): teams block the deletion; the
//     refusal carries the same `blockers` as the precheck, rendered with the
//     way out per team (BlockerList). With no blockers in the body it falls
//     back to the teams link.

export function DeletionError({
  message,
  code,
  blockers = [],
}: {
  message: string;
  code: string;
  blockers?: AccountDeletionBlocker[];
}) {
  const blocked = code === ACCOUNT_DELETION_BLOCKED;
  return (
    <div role="alert" className="banner banner-error">
      {message}
      {(code === PAYS_FOR_LIVE_ORG || (blocked && blockers.length === 0)) && (
        <>
          {" "}
          <Link to="/home" className="font-medium underline">
            Open your teams
          </Link>
        </>
      )}
      {blocked && blockers.length > 0 && <BlockerList blockers={blockers} />}
    </div>
  );
}
