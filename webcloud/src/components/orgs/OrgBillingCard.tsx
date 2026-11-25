import { useState } from "react";
import { CreditCard, ExternalLink } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Card } from "@shared/primitives/Card";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { Pill } from "@shared/primitives/Pill";
import type { OrgBillingView, PortalOrg, PortalSession } from "../../api";
import { billingState } from "../../lib/orgsModel";
import { PLAN_LABELS } from "../../lib/labels";
import { billingTextFor, subscribeLabel } from "../../lib/personalModel";
import { dateWithRelative, statusMeta } from "../billing/util";
import { BillingPortalButton } from "../billing/BillingPortalButton";

// OrgBillingCard - billing per org (lead decision W14-D3): the org's
// subscription as Paddle reported it, and, for the billing owner, the
// checkout (a team on the Team plan, a personal org on the personal plans,
// worded per kind by lib/personalModel.ts). Paddle is the merchant of record: no card details are
// entered here. Presentational: the page fetches the view and opens the
// checkout (onCheckout); billingState (lib/orgsModel.ts) picks what shows.

export interface OrgBillingCardProps {
  billing: OrgBillingView;
  /** Opens the Paddle checkout for a price; rejects with a worded error. */
  onCheckout: (priceId: string) => Promise<void>;
  /** Mints the billing owner's Paddle customer portal session (shown only
   * when billing.portal_available). */
  onPortal?: () => Promise<PortalSession>;
  /** kind words the card for a personal org or a team (default team). */
  kind?: PortalOrg["kind"];
}

export function OrgBillingCard({ billing, onCheckout, onPortal, kind = "team" }: OrgBillingCardProps) {
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const state = billingState(billing);
  const sub = billing.subscription;
  // Team and Business are both team plans, so an org may be offered more
  // than one price (wave 17): the billing owner picks one. Ordered by the
  // plan's place in PLAN_ORDER (Team before Business), then by price id.
  const prices = [...billing.checkout.prices].sort(
    (a, b) => planRank(a.plan_name) - planRank(b.plan_name) || a.price_id.localeCompare(b.price_id),
  );
  const [chosen, setChosen] = useState<string | null>(null);
  const price = prices.find((p) => p.price_id === chosen) ?? prices[0];
  const offer = (state === "can_subscribe" || state === "ended") && !!price;

  async function checkout() {
    if (!price) return;
    setError(null);
    setBusy(true);
    try {
      await onCheckout(price.price_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not start checkout");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Billing" icon={CreditCard} sub={billingTextFor(state, kind)}>
      {sub && (
        <DefinitionList className="divide-y divide-line-1 text-[12px]">
          <DefinitionRow
            label="Subscription"
            value={
              <Pill variant={statusMeta(sub.status).variant} icon={statusMeta(sub.status).icon}>
                {statusMeta(sub.status).label}
              </Pill>
            }
          />
          <DefinitionRow label="Plan" value={planLabel(sub.plan_name)} />
          {sub.trial_ends_at && <DefinitionRow label="Trial ends" value={dateWithRelative(sub.trial_ends_at)} />}
          {sub.status === "past_due" && sub.past_due_since && (
            <DefinitionRow label="Payment due since" value={dateWithRelative(sub.past_due_since)} />
          )}
          {sub.current_period_end && !sub.trial_ends_at && (
            <DefinitionRow label={sub.status === "canceled" ? "Access until" : "Renews"} value={dateWithRelative(sub.current_period_end)} />
          )}
        </DefinitionList>
      )}
      {sub?.management_urls && (sub.management_urls.update_payment_method || sub.management_urls.cancel) && (
        <div className="mt-3 flex flex-wrap gap-2">
          {sub.management_urls.update_payment_method && (
            <Button size="sm" variant="secondary" iconRight={ExternalLink} href={sub.management_urls.update_payment_method} target="_blank" rel="noopener">
              Update payment method
            </Button>
          )}
          {sub.management_urls.cancel && (
            <Button size="sm" variant="secondary" iconRight={ExternalLink} href={sub.management_urls.cancel} target="_blank" rel="noopener">
              Cancel subscription
            </Button>
          )}
        </div>
      )}
      {billing.portal_available && onPortal && (
        <div className="mt-3">
          <BillingPortalButton open={onPortal} />
        </div>
      )}
      {offer && price && (
        <div className="mt-3 border-t border-line-1 pt-3">
          {prices.length > 1 ? (
            <fieldset className="flex flex-col gap-1.5">
              <legend className="mb-1 text-[11px] text-fg-3">Choose a plan</legend>
              {prices.map((p) => (
                <label key={p.price_id} className="flex items-baseline gap-2 text-[12px] text-fg-1">
                  <input
                    type="radio"
                    name="org-plan"
                    className="accent-accent"
                    checked={p.price_id === price.price_id}
                    onChange={() => setChosen(p.price_id)}
                    disabled={busy}
                  />
                  <span className="font-semibold text-fg-0">{planLabel(p.plan_name)}</span>
                  <span>{p.display || (p.interval ? "per " + p.interval : "")}</span>
                </label>
              ))}
            </fieldset>
          ) : (
            <div className="flex items-baseline gap-1.5">
              <span className="text-[20px] font-bold text-fg-0">{price.display || price.plan_name}</span>
              {price.interval && !price.display.includes("/") && <span className="text-[12px] text-fg-3">/ {price.interval}</span>}
            </div>
          )}
          {error && (
            <div role="alert" className="mt-2 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11px] text-danger">
              <p>{error}</p>
              <a href="mailto:help@paddle.com" target="_blank" rel="noopener" className="mt-1 inline-block underline">
                Email Paddle support: help@paddle.com
              </a>
            </div>
          )}
          <label className="mt-3 flex items-start gap-2 text-[11px] leading-snug text-fg-3">
            <input
              type="checkbox"
              className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-accent"
              checked={accepted}
              onChange={(e) => setAccepted(e.target.checked)}
              disabled={busy}
            />
            <span>
              By subscribing you agree to the{" "}
              <a href="https://superbased.app/terms" target="_blank" rel="noopener" className="text-accent">Terms</a>,{" "}
              <a href="https://superbased.app/privacy" target="_blank" rel="noopener" className="text-accent">Privacy Policy</a> and{" "}
              <a href="https://superbased.app/refund-policy" target="_blank" rel="noopener" className="text-accent">Refund Policy</a>
            </span>
          </label>
          <Button type="button" variant="primary" size="sm" className="mt-3" disabled={!accepted} loading={busy} onClick={checkout}>
            {busy
              ? "Opening checkout"
              : state === "ended" || kind === "personal"
                ? subscribeLabel(state, kind)
                : "Subscribe to " + planLabel(price.plan_name)}
          </Button>
          <p className="mt-2 text-[11px] text-fg-3">
            Checkout runs in a Paddle-hosted overlay; card details are entered there, never in this portal.
          </p>
        </div>
      )}
    </Card>
  );
}

// PLAN_ORDER is the order team plans are offered in.
const PLAN_ORDER = ["team", "business"];

function planRank(name: string): number {
  const i = PLAN_ORDER.indexOf(name);
  return i < 0 ? PLAN_ORDER.length : i;
}

// planLabel is a catalog plan name as the card shows it: its PLAN_LABELS
// name (a personal subscription names personal_pro, shown as "Personal
// Pro"), else the name with its first letter capitalised.
function planLabel(name: string): string {
  if (PLAN_LABELS[name]) return PLAN_LABELS[name];
  return name ? name.charAt(0).toUpperCase() + name.slice(1).replace(/_/g, " ") : "the plan";
}
