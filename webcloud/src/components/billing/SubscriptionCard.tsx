import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { Pill } from "@shared/primitives/Pill";
import { fmtDateTime, fmtShortId } from "@shared/lib/format";
import type { BillingSubscription } from "../../api";
import { dateWithRelative, statusMeta } from "./util";

// SubscriptionCard is Row 3, rendered only when a subscription exists. It
// shows the status, the relevant date for that status, both Paddle ids
// (abbreviated, full value on click-to-copy and in the title), and either
// the hosted-management buttons or the honest receipt-email fallback when
// Paddle has not sent a direct management link.
export function SubscriptionCard({
  sub,
  showResubscribeOffer,
}: {
  sub: BillingSubscription;
  showResubscribeOffer: boolean;
}) {
  const meta = statusMeta(sub.status);
  const dateLine = subscriptionDateLine(sub);

  return (
    <div className="bg-bg-2 border border-line-1 rounded-xl p-5">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-[13px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Subscription
        </h2>
        <Pill variant={meta.variant}>{meta.label}</Pill>
      </div>

      <DefinitionList className="mt-3">
        <DefinitionRow label="Plan" value={`${sub.plan_name} (v${sub.plan_version})`} />
        {dateLine && <DefinitionRow label={dateLine.label} value={dateLine.value} />}
        {sub.status === "canceled" && sub.canceled_at && (
          <DefinitionRow label="Canceled on" value={fmtDateTime(sub.canceled_at)} />
        )}
        <DefinitionRow
          label="Subscription"
          value={
            <CopyOnClick value={sub.subscription_id} title={sub.subscription_id}>
              <span className="font-mono">
                {fmtShortId(sub.subscription_id, 12)}
              </span>
            </CopyOnClick>
          }
        />
        <DefinitionRow
          label="Customer"
          value={
            <CopyOnClick value={sub.customer_id} title={sub.customer_id}>
              <span className="font-mono">
                {fmtShortId(sub.customer_id, 12)}
              </span>
            </CopyOnClick>
          }
        />
      </DefinitionList>

      {!showResubscribeOffer && <ManagementSection sub={sub} />}
    </div>
  );
}

// subscriptionDateLine picks the one date worth surfacing for the
// subscription's current status: when it renews (active/past_due), when the
// trial ends (trialing), or when access actually ends (canceled, and only
// when that end date is still honest to show - a canceled row with no
// current_period_end has nothing to date here).
function subscriptionDateLine(
  sub: BillingSubscription,
): { label: string; value: string } | null {
  if (sub.status === "trialing" && sub.trial_ends_at) {
    return { label: "Trial ends", value: dateWithRelative(sub.trial_ends_at) };
  }
  if (
    (sub.status === "active" || sub.status === "past_due") &&
    sub.current_period_end
  ) {
    return { label: "Renews", value: dateWithRelative(sub.current_period_end) };
  }
  if (sub.status === "canceled" && sub.current_period_end) {
    return {
      label: "Access until",
      value: dateWithRelative(sub.current_period_end),
    };
  }
  return null;
}

// ManagementLinks renders Paddle's hosted payment-method / cancellation
// links when Paddle has sent them, else the honest receipt-email fallback -
// never a dead button.
function ManagementSection({ sub }: { sub: BillingSubscription }) {
  const urls = sub.management_urls;
  if (!urls || (!urls.update_payment_method && !urls.cancel)) {
    return (
      <p className="mt-4 border-t border-line-1 pt-3 text-[11px] text-fg-3">
        Payment method, invoices, plan changes and cancellation are all
        handled on Paddle&apos;s hosted billing pages. A direct management
        link was not included with this subscription&apos;s last update - use
        the receipt email Paddle sent you to reach your billing portal.
      </p>
    );
  }
  return (
    <div className="mt-4 border-t border-line-1 pt-3">
      <p className="text-[11px] text-fg-3">
        Payment method, invoices, plan changes and cancellation are all
        handled on Paddle&apos;s hosted billing pages.
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {urls.update_payment_method && (
          <a
            className="btn btn-sm"
            href={urls.update_payment_method}
            target="_blank"
            rel="noopener"
          >
            Update payment method
          </a>
        )}
        {urls.cancel && (
          <a
            className="btn btn-ghost btn-sm"
            href={urls.cancel}
            target="_blank"
            rel="noopener"
          >
            Cancel subscription
          </a>
        )}
      </div>
    </div>
  );
}
