// Support access (plan 06 5.8.7; M7a.2; design m6.0 4.9 "The support
// claim"). The GRANT that lets staff into an org lives in that org's own
// tenant (an org admin turns it on); the control plane cannot see it. What
// the console holds is the staff side: the platform issuer's support sign-in,
// which needs a passkey assertion from the last 15 minutes, and its audit -
// one staff_actions row per support code issued, and one per refusal.

import { useMemo } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Card } from "@shared/primitives/Card";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { EmptyState } from "@shared/primitives/EmptyState";
import { ErrorState } from "@shared/primitives/ErrorState";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Pill } from "@shared/primitives/Pill";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { listLog } from "../api";
import { LogTable } from "../components/LogTable";
import { useStaff, useStaffQuery } from "../session";

export function Support() {
  const staff = useStaff();
  const signins = useStaffQuery("staff:log:support", () => listLog({ verb: "support.signin", limit: 200 }));
  const refusals = useStaffQuery("staff:log:refused", () => listLog({ verb: "action.refused", limit: 200 }));
  const refusedSupport = useMemo(() => (refusals.data?.actions ?? []).filter((a) => a.target === "support.signin"), [refusals.data]);
  const configured = staff.feature("support_signin");
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Support access" icon={ShieldCheck} sub="Signing in to a customer org as support, and the record of every support sign-in." />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="How support access works">
          <ol className="list-decimal space-y-1.5 pl-4 text-[12px] text-fg-2">
            <li>An admin of the org turns support access on in their own dashboard. That grant lives in the org; this console cannot see or change it.</li>
            <li>From the org's sign-in page, choose support sign-in. The org sends you to this console's authorize step.</li>
            <li>
              The console checks your staff session and a passkey check from the last 15 minutes, records the sign-in below, and returns you with a support
              identity.
            </li>
            <li>The org decides whether to let you in, and its own operator log shows the visit to its admins.</li>
          </ol>
        </Card>
        <Card title="Your support readiness">
          <DefinitionList>
            <DefinitionRow
              label="Support sign-in on this console"
              value={configured ? <Pill variant="success">configured</Pill> : <Pill variant="warn">not configured</Pill>}
            />
            <DefinitionRow label="Your role" value={staff.me.role} />
            <DefinitionRow label="Passkey check" value={staff.fresh.label} />
          </DefinitionList>
          {!staff.fresh.fresh && (
            <div className="mt-3">
              <Button size="sm" variant="soft" iconLeft={KeyRound} onClick={() => void staff.reverify().catch(() => undefined)}>
                Verify passkey now
              </Button>
            </div>
          )}
          {!configured && (
            <p className="mt-3 text-[11.5px] text-fg-3">
              The staff process has no support issuer configured (SBCI_STAFF_SUPPORT_ISSUER), so the authorize step answers not available.
            </p>
          )}
        </Card>
      </div>
      <Card title="Support sign-ins" sub="One row per support code the console issued, newest first.">
        {signins.error && !signins.data ? (
          <ErrorState variant="inline" title="Could not load the sign-ins" error={signins.error} onRetry={signins.reload} />
        ) : !signins.data ? (
          <TableSkeleton />
        ) : signins.data.actions.length === 0 ? (
          <EmptyState variant="inline" title="No support sign-in yet" />
        ) : (
          <LogTable actions={signins.data.actions} self={staff.me.staff_id} />
        )}
      </Card>
      <Card title="Refused support attempts" sub="Support sign-ins the console refused (a stale passkey check or a role without access).">
        {refusals.error && !refusals.data ? (
          <ErrorState variant="inline" title="Could not load the refusals" error={refusals.error} onRetry={refusals.reload} />
        ) : !refusals.data ? (
          <TableSkeleton />
        ) : refusedSupport.length === 0 ? (
          <p className="text-[12px] text-fg-3">None in the last 200 refusals.</p>
        ) : (
          <LogTable actions={refusedSupport} self={staff.me.staff_id} />
        )}
      </Card>
    </div>
  );
}
