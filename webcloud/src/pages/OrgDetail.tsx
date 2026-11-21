import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Callout } from "@shared/primitives/Callout";
import {
  ApiError,
  cancelOrgDeletion,
  createOrgBillingPortalSession,
  createOrgCheckout,
  getOrg,
  getAuthMode,
  getOrgBilling,
  getOrgDeletion,
  renameOrg,
  requestOrgDeletion,
} from "../api";
import type { OrgBillingView, OrgDeletionProof, OrgDeletionView, OrgDetail as OrgDetailData } from "../api";
import { CardSkeleton, DashboardSkeleton, ErrorPanel } from "../components/LoadState";
import { OrgBillingCard } from "../components/orgs/OrgBillingCard";
import { OrgDeletionCard, type OrgDeletionRequestOutcome } from "../components/orgs/OrgDeletionCard";
import { OrgDetailView } from "../components/orgs/OrgDetailView";
import { OrgSigninPolicyCard } from "../components/orgs/OrgSigninPolicyCard";
import { ensurePaddleReady, loadPaddleJs, paddleFailureText } from "../components/billing/paddleCheckout";
import {
  ORG_DELETION_ERROR_TEXT,
  ORG_DELETION_STEP_UP_KEY,
  orgDeletionRefusalNext,
  orgDeletionStepUpURL,
  parseStepUpStash,
  type OrgDeletionStepUpStash,
} from "../lib/deletionModel";
import { stageView } from "../lib/orgsModel";
import { orgNoun } from "../lib/personalModel";
import { invalidatePortal, usePortalQuery } from "../lib/query";

// OrgDetail - one org's page (plan 07 M6.5; a personal org too, D-IND-8,
// worded by its kind). It polls while the org is still being set up (a waitlisted create included), reads billing only for
// a caller allowed to see it, and opens the Paddle checkout for the
// billing owner; the subscription then lands through the webhook, so the
// page polls billing for a short while after a completed checkout.

const PENDING_POLL_MS = 5000;
const CONFIRM_POLL_MS = 3000;
const CONFIRM_TIMEOUT_MS = 120_000;
// A deletion that is purging moves on its own; the page re-reads it.
const PURGING_POLL_MS = 15_000;

/** ORG_ERROR_TEXT words the org routes' refusals for a team's page. */
const ORG_ERROR_TEXT: Readonly<Record<string, string>> = {
  org_provisioning: "The team is still being set up; rename it once it is ready.",
  forbidden: "Only a team owner or admin can do that.",
  already_subscribed: "This team already has an active subscription. Refresh to see it.",
  billing_owner_required: "Only the team's billing owner can start a checkout.",
  checkout_unavailable: "Checkout is not configured for this team's plan on this deployment.",
  org_not_billable: "This team cannot take a subscription right now.",
  ...ORG_DELETION_ERROR_TEXT,
};

/** PERSONAL_ORG_ERROR_TEXT words the same refusals for a personal org's page. */
const PERSONAL_ORG_ERROR_TEXT: Readonly<Record<string, string>> = {
  org_provisioning: "Your personal dashboard is still being set up; rename it once it is ready.",
  forbidden: "Only the owner of this personal dashboard can do that.",
  already_subscribed: "This personal dashboard already has an active subscription. Refresh to see it.",
  billing_owner_required: "Only the owner of this personal dashboard can start a checkout.",
  checkout_unavailable: "Checkout is not configured for the personal plans on this deployment.",
  org_not_billable: "This personal dashboard cannot take a subscription right now.",
};

// rememberDeletionStepUp stashes the request across the WorkOS
// re-authentication, so the page can finish it on return. sessionStorage may
// be unavailable (private mode): the owner then types the address again.
function rememberDeletionStepUp(stash: OrgDeletionStepUpStash): void {
  try {
    window.sessionStorage.setItem(ORG_DELETION_STEP_UP_KEY, JSON.stringify(stash));
  } catch {
    // see above
  }
}

// takeDeletionStepUp reads and clears the stash (one use).
function takeDeletionStepUp(): OrgDeletionStepUpStash | null {
  try {
    const raw = window.sessionStorage.getItem(ORG_DELETION_STEP_UP_KEY);
    window.sessionStorage.removeItem(ORG_DELETION_STEP_UP_KEY);
    return parseStepUpStash(raw);
  } catch {
    return null;
  }
}

function worded(e: unknown, fallback: string, kind: OrgDetailData["org"]["kind"] = "team"): Error {
  const text = kind === "personal" ? PERSONAL_ORG_ERROR_TEXT : ORG_ERROR_TEXT;
  if (e instanceof ApiError && text[e.code]) return new Error(text[e.code]);
  return e instanceof Error ? e : new Error(fallback);
}

export function OrgDetail() {
  const { id = "" } = useParams();
  const [pending, setPending] = useState(false);
  const q = usePortalQuery<OrgDetailData>("org:" + id, () => getOrg(id), [id], {
    refreshMs: pending ? PENDING_POLL_MS : 0,
  });
  const detail = q.data;
  useEffect(() => {
    const p = detail?.org.provisioning;
    setPending(!!p && stageView(p.stage).pending);
  }, [detail]);

  // The deletion status and preview: every member reads it (the card shows
  // the control to an owner only). Polled while a purge runs.
  const [purging, setPurging] = useState(false);
  const del = usePortalQuery<OrgDeletionView>("org-deletion:" + id, () => getOrgDeletion(id), [id], {
    refreshMs: purging ? PURGING_POLL_MS : 0,
  });
  useEffect(() => {
    setPurging(del.data?.deletion?.state === "purging");
  }, [del.data]);

  // The one-use WorkOS step-up authorization for a deletion, read from
  // ?step_up=<id> on mount and stripped from the address bar at once (it
  // must not linger in history or a referrer), with the stash saved before
  // leaving (Privacy's DeleteSection does the same for the account).
  const [stepUpId, setStepUpId] = useState<string | null>(null);
  const [stepUpStash, setStepUpStash] = useState<OrgDeletionStepUpStash | null>(null);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const stepUp = params.get("step_up");
    if (stepUp === null) return;
    params.delete("step_up");
    const rest = params.toString();
    window.history.replaceState(null, "", window.location.pathname + (rest ? "?" + rest : ""));
    setStepUpStash(takeDeletionStepUp());
    setStepUpId(stepUp);
  }, []);

  const [confirming, setConfirming] = useState(false);
  // A checkout.failed event arrives after Checkout.open returned, so it is
  // shown here, beside the card, rather than thrown.
  const [paddleError, setPaddleError] = useState<string | null>(null);
  const canBill = !!detail?.can.view_billing;
  const b = usePortalQuery<OrgBillingView>(canBill ? "org-billing:" + id : null, () => getOrgBilling(id), [id], {
    refreshMs: confirming ? CONFIRM_POLL_MS : 0,
  });
  // Land-back from Paddle's successUrl: strip the flag and start confirming.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("checkout") !== "success") return;
    params.delete("checkout");
    const rest = params.toString();
    window.history.replaceState(null, "", window.location.pathname + (rest ? "?" + rest : ""));
    setConfirming(true);
  }, []);
  useEffect(() => {
    if (!confirming) return;
    const t = window.setTimeout(() => setConfirming(false), CONFIRM_TIMEOUT_MS);
    return () => window.clearTimeout(t);
  }, [confirming]);
  useEffect(() => {
    if (confirming && b.data?.has_subscription) {
      setConfirming(false);
      invalidatePortal("org:" + id);
    }
  }, [confirming, b.data, id]);

  if (q.error && !detail) {
    return <ErrorPanel variant="page" what="this dashboard" error={q.error} onRetry={q.reload} />;
  }
  if (!detail) return <DashboardSkeleton stats={2} />;
  const kind = detail.org.kind;

  async function onCheckout(priceId: string) {
    if (!b.data) return;
    setPaddleError(null);
    let intent;
    try {
      intent = await createOrgCheckout(id, priceId);
    } catch (e) {
      throw worded(e, "could not start checkout", kind);
    }
    try {
      await loadPaddleJs();
    } catch {
      throw new Error("Could not load Paddle's checkout script. Check your connection and try again.");
    }
    const checkout = b.data.checkout;
    const paddle = ensurePaddleReady(checkout, (event) => {
      if (event.name === "checkout.completed") setConfirming(true);
      else if (event.name === "checkout.failed") {
        window.Paddle?.Checkout.close?.();
        setPaddleError(paddleFailureText(event));
      }
    });
    paddle.Checkout.open({
      items: [{ priceId: intent.price_id, quantity: intent.quantity ?? 1 }],
      customData: intent.custom_data,
      settings: {
        displayMode: "overlay",
        successUrl: window.location.origin + "/portal/orgs/" + encodeURIComponent(id) + "?checkout=success",
      },
    });
  }

  async function onPortal() {
    try {
      return await createOrgBillingPortalSession(id);
    } catch (e) {
      throw worded(e, "could not open the billing portal");
    }
  }

  async function onRename(name: string) {
    try {
      await renameOrg(id, name);
    } catch (e) {
      throw worded(e, "could not rename the " + orgNoun(kind), kind);
    }
    invalidatePortal("org:" + id);
    invalidatePortal("orgs");
  }

  // afterDeletionChange re-reads everything a deletion request or cancel
  // changes: the deletion itself, the org's status and the teams list.
  function afterDeletionChange() {
    invalidatePortal("org-deletion:" + id);
    invalidatePortal("org:" + id);
    invalidatePortal("orgs");
  }

  // onRequestDeletion posts the request; when the server asks for WorkOS
  // re-authentication it stashes the request and leaves for it, and a spent
  // authorization is dropped so the next try re-authenticates again.
  async function onRequestDeletion(confirmSlug: string, proof: OrgDeletionProof): Promise<OrgDeletionRequestOutcome> {
    try {
      await requestOrgDeletion(id, confirmSlug, proof);
    } catch (e) {
      const next = e instanceof ApiError ? orgDeletionRefusalNext(e.code) : "show";
      if (next === "start_step_up") {
        rememberDeletionStepUp({ orgId: id, slug: confirmSlug });
        window.location.assign(orgDeletionStepUpURL(id));
        return "reauth";
      }
      if (next === "drop_step_up") setStepUpId(null);
      throw worded(e, "could not request the deletion");
    }
    setStepUpId(null);
    setStepUpStash(null);
    afterDeletionChange();
    return "requested";
  }

  async function onCancelDeletion() {
    try {
      await cancelOrgDeletion(id);
    } catch (e) {
      // A cancel that lost the race with the purge: show the new state too.
      afterDeletionChange();
      throw worded(e, "could not cancel the deletion");
    }
    afterDeletionChange();
  }

  const deletion = del.error && !del.data ? (
    <ErrorPanel what="this team's deletion status" error={del.error} onRetry={del.reload} />
  ) : !del.data ? null : (
    <OrgDeletionCard
      org={detail.org}
      view={del.data}
      authMode={getAuthMode()}
      stepUpId={stepUpId}
      stepUpStash={stepUpStash}
      onRequest={onRequestDeletion}
      onCancel={onCancelDeletion}
    />
  );

  const billing = !canBill ? null : b.error && !b.data ? (
    <ErrorPanel what="billing" error={b.error} onRetry={b.reload} />
  ) : !b.data ? (
    <CardSkeleton />
  ) : (
    <>
      {paddleError && <Callout tone="danger" title="Checkout did not complete">{paddleError}</Callout>}
      {confirming && <Callout tone="info" title="Confirming your subscription">This takes a moment while Paddle&apos;s confirmation lands.</Callout>}
      <OrgBillingCard billing={b.data} onCheckout={onCheckout} onPortal={onPortal} kind={kind} />
    </>
  );

  // C2: an owner or admin of a team sets whether members need a passkey.
  const admin = detail.org.console_role === "owner" || detail.org.console_role === "admin";
  return (
    <div className="flex flex-col gap-6">
      <OrgDetailView detail={detail} billing={billing} deletion={deletion} onRename={onRename} />
      {admin && detail.org.kind === "team" && <OrgSigninPolicyCard orgId={id} />}
    </div>
  );
}
