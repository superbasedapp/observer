import clsx from "clsx";
import { History, Pencil, RefreshCw, Trash2 } from "lucide-react";
import { Button, Callout, Meter, Pill, RowActions } from "@/components/primitives";
import {
  SCOPE_NOTES,
  balanceLabel,
  cardPill,
  cardSourceText,
  cardTitle,
  fmtAmount,
  healthText,
  identityText,
  paceText,
  planName,
  resetText,
  spendLabel,
  windowFrac,
  windowLabel,
  windowTone,
  windowValue,
  type PlanAccount,
  type PlanCard,
  type PlanWindow,
  type Tone,
} from "@/lib/plans";
import { balanceGroups, headlineView, otherSpend } from "@/lib/plansView";
import { ProviderMark } from "./ProviderMark";
import { UsageByDay } from "./UsageByDay";

// PlanCardView: one plan or balance. It leads with what is LEFT (the server's
// headline, worded by lib/plansView.ts), then the windows as meters, the
// other balances and spend as a compact list, and where the numbers came
// from. Nothing truncates: every row wraps, so a long amount or a narrow
// phone never clips a number.

const HEADLINE_TONE: Record<Tone, string> = {
  neutral: "text-fg-0",
  accent: "text-fg-0",
  info: "text-fg-0",
  success: "text-fg-0",
  warn: "text-warn",
  danger: "text-danger",
};

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 text-[12px]">
      <span className="min-w-0 text-fg-2">{label}</span>
      <span className="tabular-nums text-fg-1">{value}</span>
    </div>
  );
}

export function PlanCardView({
  card,
  account,
  onRefresh,
  onEdit,
  onHistory,
  onRemove,
}: {
  card: PlanCard;
  account?: PlanAccount;
  onRefresh: (id: string) => void;
  onEdit: (a: PlanAccount) => void;
  onHistory: (a: PlanAccount) => void;
  onRemove: (id: string) => void;
}) {
  const pill = cardPill(card);
  const identity = identityText(card);
  const plan = planName(card);
  const scopeNote = card.scope_reason ? (SCOPE_NOTES[card.scope_reason] ?? "") : "";
  const source = [cardSourceText(card), healthText(card)].filter(Boolean).join(". ");
  const head = headlineView(card.headline);
  const balances = balanceGroups(card);
  const spend = otherSpend(card);
  const stopped = card.state?.stopped;
  // The plan goes on the line under the name, so the title is the provider
  // plus the name the user typed.
  const title = cardTitle({ ...card, plan_label: undefined, plan_code: undefined });
  const noReading = !card.headline || card.headline.kind === "none";
  const subtitle = [plan ? `${plan} plan` : "", identity].filter(Boolean).join(". ");

  return (
    <section className="flex min-w-0 flex-col gap-4 rounded-3 border border-line-2 bg-bg-2 p-card">
      <header className="flex min-w-0 items-start gap-3">
        <ProviderMark provider={card.provider} size={36} />
        <div className="min-w-0 flex-1">
          <h3 className="break-words text-[14px] font-semibold leading-snug text-fg-0">
            {title}
          </h3>
          {subtitle && <p className="break-words text-[11.5px] text-fg-3">{subtitle}</p>}
        </div>
        {account && (
          <RowActions
            menuLabel={`Actions for ${title}`}
            actions={[
              { id: "refresh", label: "Refresh now", icon: RefreshCw, onSelect: () => onRefresh(account.id) },
              { id: "edit", label: "Edit", icon: Pencil, onSelect: () => onEdit(account) },
              { id: "history", label: "Show history", icon: History, onSelect: () => onHistory(account) },
              {
                id: "remove",
                label: "Remove",
                icon: Trash2,
                destructive: true,
                confirm: { label: "Remove this account", note: "Its saved keys are deleted too." },
                onSelect: () => onRemove(account.id),
              },
            ]}
          />
        )}
      </header>

      {(card.experimental || pill) && (
        <div className="-mt-2 flex flex-wrap gap-1.5">
          {pill && (
            <Pill variant={pill.tone} case="none">
              {pill.label}
            </Pill>
          )}
          {card.experimental && (
            <Pill variant="info" case="none">
              Experimental
            </Pill>
          )}
        </div>
      )}

      {noReading ? (
        <p className="text-[13px] text-fg-2">{emptyCardText(card)}</p>
      ) : (
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className={clsx("break-words text-[26px] font-semibold leading-tight tabular-nums", HEADLINE_TONE[head.tone])}>
            {head.value}
          </span>
          {head.context && <span className="text-[13px] text-fg-2">{head.context}</span>}
        </div>
        {head.leftFrac != null && card.headline?.basis?.startsWith("balance:") && (
          <Meter
            className="mt-2"
            ratio={head.leftFrac}
            tone={head.tone === "neutral" ? "accent" : head.tone}
            label="Share left"
          />
        )}
        {head.also?.map((a) => (
          <p key={a} className="mt-0.5 break-words text-[17px] font-semibold tabular-nums text-fg-1">
            {a}
          </p>
        ))}
        {head.details.length > 0 && (
          <p className="mt-1 break-words text-[12px] tabular-nums text-fg-2">{head.details.join(". ")}</p>
        )}
        {head.note && <p className="mt-1 text-[11.5px] text-fg-3">{head.note}</p>}
      </div>
      )}

      {card.windows.length > 0 && (
        <div className="space-y-3">
          {card.windows.map((w) => {
            const frac = windowFrac(w);
            const reset = resetText(w);
            const pace = paceText(w);
            return (
              <div key={w.key} className="min-w-0 space-y-1">
                <Row label={windowLabel(w.key)} value={windowUsedText(w)} />
                {frac != null && <Meter ratio={Math.min(frac, 1)} tone={windowTone(frac)} label={`${windowLabel(w.key)} used`} />}
                {(reset || pace) && (
                  <div className="flex flex-wrap justify-between gap-x-3 gap-y-0.5 text-[11px] text-fg-3">
                    {reset && <span>{reset}</span>}
                    {pace && <span>{pace}</span>}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {(balances.length > 0 || spend.length > 0) && (
        <div className="space-y-1 border-t border-line-1 pt-3">
          {balances.map((g) => (
            <div key={g.unit} className="space-y-1">
              {g.label && <p className="pt-1 text-[11px] font-medium text-fg-3">{g.label}</p>}
              {g.rows.map((b, i) => (
                <Row key={`${g.unit}${i}`} label={balanceLabel(b.kind)} value={fmtAmount(b.unit, b.amount)} />
              ))}
            </div>
          ))}
          {spend.map((s, i) => (
            <Row key={`s${i}`} label={spendLabel(s)} value={fmtAmount(s.unit, s.amount)} />
          ))}
        </div>
      )}

      {account?.daily_usage && <UsageByDay accountId={account.id} />}

      {stopped && account && (
        <Callout
          tone="warn"
          title="Checks are paused"
          action={
            <Button variant="secondary" size="sm" onClick={() => onEdit(account)}>
              Edit to resume
            </Button>
          }
        >
          Replace the key or sign in to the vendor's tool again, then save the account.
        </Callout>
      )}

      {(source || scopeNote) && (
        <p className="mt-auto break-words border-t border-line-1 pt-2 text-[11px] text-fg-3">
          {[source, scopeNote].filter(Boolean).join(". ")}
        </p>
      )}
    </section>
  );
}

/** windowUsedText: "52% used", "$9.10 of $30.00 used"; a remaining or cap value as is. */
function windowUsedText(w: PlanWindow): string {
  const v = windowValue(w);
  return windowFrac(w) != null || (w.used != null && w.limit != null) ? `${v} used` : v;
}

function emptyCardText(c: PlanCard): string {
  if (c.health === "waiting") return "Waiting for the first reading.";
  if (c.status === "plan_only" || c.status === "unmetered") return "This plan reports no usage limit.";
  return "Not reported by this plan.";
}
