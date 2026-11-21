import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, X } from "lucide-react";
import { useApi } from "@/lib/useApi";
import { Icon, Tooltip } from "@/components/primitives";
import { AnchoredPopover } from "@/components/primitives/AnchoredPopover";
import { pushToast } from "@/components/Toast";
import { getCostDisplayMode } from "@shared/lib/format";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { GatedLink } from "@/components/GatedLink";
import {
  BUDGET_FETCH_ACCOUNT,
  BUDGET_FETCH_TRY_NOW_PATH,
  budgetFetchNotice,
  budgetWarningLabel,
  guardModeLink,
  isExceeded,
  newerBudgetStatus,
  newNotices,
  noticeMessage,
  parseIdList,
  pickBudgetWarning,
  rememberIds,
  type BudgetStatus,
} from "@/lib/budgetWarning";
import { budgetRequestLink } from "@/lib/requestEntry";
import { useBudgetStatusStream } from "@/lib/budgetStatusStream";

// "Ask for a budget increase" (T-522, D-334) opens the Requests form on the
// budget the notice measures (budgetRequestLink: /requests?new=budget&budget=
// <id>, the same stable link the guard's budget deny line uses). The Requests
// page can never be hidden by an org (D-089), so the link always lands.
const ASK_LABEL = "Ask for a budget increase";

// BudgetWarningBanner - the developer-facing ORG budget warning (2026-10-02
// budget-latency arc). Mounted ONCE in the App shell, so it shows on every
// page, Terminals included. Listens to GET /api/budget/status/stream (pushed
// within seconds of the daemon's write, T-206) and polls GET
// /api/budget/status every 15 s as the fallback (paused while the tab is
// hidden - useApi's default), showing whichever was written last; it shows
// the top active notice
// in a slim strip, and raises a one-time toast the first time this browser
// sees a notice id.
//
// Distinct from BudgetBanner (the developer's OWN local [budget] advisory).
// available=false means no org budget warning service wrote here: render
// nothing, never "under budget". The server's `message` is shown as sent in
// dollar mode; when the org chose token usage for developer dashboards
// (CostDisplayGate -> shared/lib/format.ts) a dollar cap's amounts are dropped
// and the share of the budget stays. Decisions live in lib/budgetWarning.ts.

const DISMISS_KEY = "sb_budget_warn_dismissed"; // sessionStorage: per tab session
const TOASTED_KEY = "sb_budget_warn_toasted"; // localStorage: once per browser

// Fallback when localStorage is unavailable, so a blocked store still toasts
// once per page load instead of on every 15 s poll.
const memToasted = new Set<string>();

function readIds(store: () => Storage, key: string): string[] {
  try {
    return parseIdList(store().getItem(key));
  } catch {
    return [];
  }
}

function writeIds(store: () => Storage, key: string, ids: string[]): void {
  try {
    store().setItem(key, JSON.stringify(ids));
  } catch {
    // Storage unavailable - the in-memory state still holds for this load.
  }
}

const session = () => window.sessionStorage;
const local = () => window.localStorage;

export function BudgetWarningBanner() {
  const api = useApi<BudgetStatus>("/api/budget/status", undefined, [], {
    refreshMs: 15000,
  });
  const [dismissed, setDismissed] = useState<Set<string>>(
    () => new Set(readIds(session, DISMISS_KEY)),
  );
  const streamed = useBudgetStatusStream();
  const data = newerBudgetStatus(streamed, api.data);

  // Toast once per notice id per browser. The stored list is re-read on
  // every run, so StrictMode's double effect and several tabs don't repeat.
  useEffect(() => {
    if (!data) return;
    const stored = readIds(local, TOASTED_KEY);
    const seen = new Set([...stored, ...memToasted]);
    const fresh = newNotices(data, seen);
    if (fresh.length === 0) return;
    for (const n of fresh) memToasted.add(n.id);
    writeIds(
      local,
      TOASTED_KEY,
      rememberIds(
        stored,
        fresh.map((n) => n.id),
      ),
    );
    for (const n of fresh.slice(0, 3)) {
      pushToast(
        `${budgetWarningLabel(n)}: ${noticeMessage(n, getCostDisplayMode())}`,
        isExceeded(n) ? "danger" : "warn",
      );
    }
  }, [data]);

  // The "+N more" list is a popover, not a tooltip: each entry carries its
  // own "Ask for a budget increase" link (a tooltip is no place for links).
  const [moreOpen, setMoreOpen] = useState(false);
  const moreRef = useRef<HTMLButtonElement | null>(null);

  const view = pickBudgetWarning(data, dismissed);
  const fetchNotice = budgetFetchNotice(data);
  if (!view) return fetchNotice ? <BudgetFetchStrip text={fetchNotice.text} onTried={api.reload} /> : null;
  const guardLink = guardModeLink(view.top);

  const mode = getCostDisplayMode();
  const danger = view.tone === "danger";
  const dismiss = () => {
    const next = new Set(dismissed);
    next.add(view.top.id);
    writeIds(session, DISMISS_KEY, [...next]);
    setDismissed(next);
  };

  return (
    <div
      data-testid="budget-warning-banner"
      data-level={view.top.level}
      className={
        danger
          ? "flex items-center gap-2 border-b border-danger/30 bg-danger-soft px-4 py-1.5 text-[11.5px] text-fg-2"
          : "flex items-center gap-2 border-b border-warn/30 bg-warn-soft px-4 py-1.5 text-[11.5px] text-fg-2"
      }
    >
      <span
        className={
          danger
            ? "inline-flex shrink-0 items-center gap-1.5 font-semibold text-danger"
            : "inline-flex shrink-0 items-center gap-1.5 font-semibold text-warn"
        }
      >
        <Icon icon={AlertTriangle} size="xs" />
        {view.label}
      </span>
      <span role="status" aria-live="polite" className="min-w-0 truncate">
        {noticeMessage(view.top, mode)}
      </span>
      {view.others.length > 0 && (
        <>
          <button
            ref={moreRef}
            type="button"
            aria-expanded={moreOpen}
            onClick={() => setMoreOpen((o) => !o)}
            className="shrink-0 rounded-pill border border-line-2 bg-bg-2 px-1.5 py-0.5 text-[10.5px] font-medium text-fg-2 hover:bg-bg-3"
          >
            +{view.others.length} more
          </button>
          <AnchoredPopover open={moreOpen} anchorRef={moreRef} onDismiss={() => setMoreOpen(false)} ariaLabel="More budget warnings" width={360}>
            <ul className="flex flex-col divide-y divide-line-1 p-2 text-[11.5px] text-fg-1">
              {view.others.map((n) => (
                <li key={n.id} className="space-y-1 py-1.5">
                  <div>{noticeMessage(n, mode)}</div>
                  <Link
                    to={budgetRequestLink(n.budget_id)}
                    onClick={() => setMoreOpen(false)}
                    className="text-[11px] font-medium text-accent hover:text-accent-strong"
                  >
                    {ASK_LABEL}
                  </Link>
                </li>
              ))}
            </ul>
          </AnchoredPopover>
        </>
      )}
      <div className="flex-1" />
      {guardLink && (
        <GatedLink to={guardLink.href} className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong">
          {guardLink.label}
        </GatedLink>
      )}
      <Link
        to={budgetRequestLink(view.top.budget_id)}
        aria-label={ASK_LABEL}
        className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
      >
        {/* Phones: the short form keeps the strip on one line at 375px. */}
        <span className="hidden sm:inline">{ASK_LABEL}</span>
        <span className="sm:hidden">Ask for more</span>
      </Link>
      <Tooltip content="Dismiss for this session">
        <button
          type="button"
          onClick={dismiss}
          aria-label="Dismiss budget warning"
          className="inline-flex shrink-0 items-center rounded-2 border border-line-2 bg-bg-2 px-1.5 py-1 text-fg-2 hover:bg-bg-3"
        >
          <Icon icon={X} size="xs" />
        </button>
      </Tooltip>
    </div>
  );
}

// BudgetFetchStrip is the failed-pull notice (budget enforce consistency,
// 2026-11-19): this machine could not get its organization's budgets, said
// in words with "Try now" (one rail cycle, POST /api/enrolment/push-now) and
// the place to look (Settings > Account). It is not dismissible: it clears
// itself when the next pull works.
function BudgetFetchStrip({ text, onTried }: { text: string; onTried: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const tryNow = async () => {
    setBusy(true);
    setErr(null);
    try {
      await fetchJSON(BUDGET_FETCH_TRY_NOW_PATH, undefined, { method: "POST", headers: await localConfirmHeaders(), body: "{}" });
      onTried();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div
      data-testid="budget-fetch-strip"
      className="flex items-center gap-2 border-b border-warn/30 bg-warn-soft px-4 py-1.5 text-[11.5px] text-fg-2"
    >
      <span className="inline-flex shrink-0 items-center gap-1.5 font-semibold text-warn">
        <Icon icon={AlertTriangle} size="xs" />
        Budgets not updated
      </span>
      <span role="status" aria-live="polite" className="min-w-0 truncate">
        {err ? `Try now failed: ${err}` : text}
      </span>
      <div className="flex-1" />
      <button
        type="button"
        onClick={() => void tryNow()}
        disabled={busy}
        className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong disabled:opacity-60"
      >
        {busy ? "Trying..." : "Try now"}
      </button>
      <Link to={BUDGET_FETCH_ACCOUNT.href} className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong">
        {BUDGET_FETCH_ACCOUNT.label}
      </Link>
    </div>
  );
}
