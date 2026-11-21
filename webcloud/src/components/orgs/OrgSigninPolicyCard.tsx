import { useState } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { Toggle } from "@shared/primitives/Toggle";
import { ApiError, getOrgSigninPolicy, setOrgSigninPolicy, type OrgSigninPolicy } from "../../api";
import { invalidatePortal, usePortalQuery } from "../../lib/query";
import { CardSkeleton, ErrorPanel } from "../LoadState";

// OrgSigninPolicyCard - an owner's or admin's "Require a second factor"
// switch for a team (C2; internal/cloudserver/api/portalmfa.go). When on,
// the team's superbased sign-in lets a member in only after a passkey; the
// server enforces it at the sign-in itself. Changing it needs a passkey
// sign-in in this session, so turning it on cannot lock the changer out.

const POLICY_REFUSAL: Readonly<Record<string, string>> = {
  passkey_signin_required: "Sign in with a passkey to change this.",
  forbidden: "Only a team owner or admin can change this.",
};

export function OrgSigninPolicyCard({ orgId }: { orgId: string }) {
  const key = "org-signin:" + orgId;
  const q = usePortalQuery<OrgSigninPolicy>(key, () => getOrgSigninPolicy(orgId), [orgId]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (q.error && !q.data) return <ErrorPanel what="the sign-in setting" error={q.error} onRetry={q.reload} />;
  if (!q.data) return <CardSkeleton />;
  const p = q.data;

  async function onChange(next: boolean) {
    setBusy(true);
    setError(null);
    try {
      await setOrgSigninPolicy(orgId, next);
      invalidatePortal(key);
    } catch (e) {
      setError(e instanceof ApiError ? (POLICY_REFUSAL[e.code] ?? e.message) : "could not change the setting");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Sign-in security"
      icon={ShieldCheck}
      sub="Members sign in to this team with their superbased account."
    >
      <div className="flex flex-col gap-3">
        <Toggle
          on={p.require_second_factor}
          onChange={(next) => void onChange(next)}
          disabled={!p.can_change || busy}
          label="Require a second factor"
        />
        <p className="text-[11.5px] leading-relaxed text-fg-3">
          When on, every member must use a passkey to sign in to this team. Members without one are asked to add one
          first. The team&apos;s break-glass local sign-in is not affected.
        </p>
        {!p.can_change && p.reason === "passkey_signin_required" && (
          <Callout tone="info">
            To change this, add a passkey under <Link to="/security">Sign-in security</Link> and sign in with it.
          </Callout>
        )}
        {error && <Callout tone="danger">{error}</Callout>}
      </div>
    </Card>
  );
}
