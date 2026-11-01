import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { Bell, X } from "lucide-react";
import { Icon, Tooltip } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { dollarsShown, fmtRelative, fmtUSD } from "@/lib/format";
import {
  badgeText,
  bellLabel,
  moneyText,
  severityTone,
  stateRequestInit,
  unreadIds,
  withoutIds,
  type NotificationsResponse,
} from "@/lib/notificationBell";

// NotificationBell - the node dashboard's notification bell in the TopBar
// (D-323), the developer-side sibling of the org dashboard's budget alert
// bell. GET /api/notifications is the daemon's feed (internal/notify/feed):
// budget crossings, access grants and request delivery, guard denials and
// held prompts, critical cache expiry, updates, org announcements and policy
// changes, ingest stalls. The feed already drops anything a section the
// organization hid on this machine owns. Opening the bell marks what it shows
// read; Dismiss removes a row. Both are stored on the daemon, not in this
// browser. The route is owner-local: on a remote view the read is refused and
// the bell renders nothing. The state write echoes the confirm token the feed
// GET minted, like every other owner-local write (T-530).
const TONE_DOT: Record<"danger" | "warn" | "accent", string> = {
  danger: "bg-danger",
  warn: "bg-warn",
  accent: "bg-accent",
};

async function postState(ids: string[], action: "read" | "dismiss", minted?: string): Promise<boolean> {
  if (ids.length === 0) return true;
  try {
    const token = minted || (await localConfirmHeaders())["X-Observer-Confirm"];
    await fetchJSON("/api/notifications/state", undefined, stateRequestInit(ids, action, token));
    return true;
  } catch {
    return false;
  }
}

export function NotificationBell() {
  const feed = useApi<NotificationsResponse>("/api/notifications", undefined, [], { refreshMs: 60000 });
  const [open, setOpen] = useState(false);
  const [dismissed, setDismissed] = useState<string[]>([]);
  const [readNow, setReadNow] = useState(false);
  const rootRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
    };
  }, [open]);

  // A refused read (remote view of an owner-local route) or no feed yet:
  // nothing to show, and no empty bell pretending all is well.
  if (!feed.data) return null;

  const rows = withoutIds(feed.data.notifications ?? [], dismissed);
  const unread = readNow ? 0 : rows.filter((r) => !r.read).length;
  const label = bellLabel(unread);
  const dollars = dollarsShown();

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) {
      const ids = unreadIds(rows);
      if (ids.length > 0) {
        setReadNow(true);
        void postState(ids, "read", feed.data?.confirm_token).then(() => feed.reload());
      }
    } else {
      setReadNow(false);
    }
  };
  const dismiss = (ids: string[]) => {
    setDismissed((d) => [...d, ...ids]);
    void postState(ids, "dismiss", feed.data?.confirm_token).then((ok) => {
      if (!ok) setDismissed((d) => d.filter((x) => !ids.includes(x)));
      feed.reload();
    });
  };

  return (
    <span ref={rootRef} className="relative inline-flex" data-tour="topbar-notifications">
      <Tooltip content={label}>
        <button
          type="button"
          onClick={toggle}
          aria-label={label}
          aria-expanded={open}
          aria-haspopup="dialog"
          className="relative grid h-7 w-7 place-items-center rounded-2 border border-line-2 bg-bg-2 text-fg-3 hover:bg-bg-3 hover:text-fg-0"
        >
          <Icon icon={Bell} size="sm" />
          {badgeText(unread) && (
            <span className="absolute -right-1.5 -top-1.5 min-w-[16px] rounded-full bg-danger px-1 text-center text-[10px] font-semibold leading-4 text-white">
              {badgeText(unread)}
            </span>
          )}
        </button>
      </Tooltip>
      {open && (
        // At phone width the bell sits mid-bar, so a popover anchored to its
        // right edge ran off the left of the screen (T-854 review): there it
        // spans the viewport under the top bar instead.
        <div
          role="dialog"
          aria-label="Notifications"
          className="fixed inset-x-3 top-[calc(var(--header-h)+0.25rem)] z-50 max-h-[calc(100dvh-var(--header-h)-1rem)] overflow-y-auto rounded-3 border border-line-2 bg-bg-1 p-3 text-[12px] shadow-lg sm:absolute sm:inset-x-auto sm:right-0 sm:top-9 sm:w-[24rem] sm:max-w-[calc(100vw-2rem)]"
        >
          <div className="mb-2 flex items-center justify-between gap-2">
            <span className="flex items-center gap-1">
              <b className="text-fg-1">Notifications</b>
              <HelpInd id="glossary.notifications" />
            </span>
            {rows.length > 0 && (
              <button
                type="button"
                onClick={() => dismiss(rows.map((r) => r.id))}
                className="text-[11px] text-fg-3 hover:text-fg-1"
              >
                Dismiss all
              </button>
            )}
          </div>
          {rows.length === 0 ? (
            <p className="text-fg-3">Nothing needs you right now.</p>
          ) : (
            <ul className="flex max-h-[60vh] flex-col gap-2 overflow-y-auto">
              {rows.map((n) => {
                const money = moneyText(n, dollars, (v) => fmtUSD(v));
                return (
                  <li key={n.id} className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1.5">
                    <div className="flex items-start gap-2">
                      <span
                        aria-hidden
                        className={clsx("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", TONE_DOT[severityTone(n.severity)])}
                      />
                      <div className="min-w-0 flex-1">
                        <div className={clsx("break-words", n.read ? "text-fg-2" : "font-medium text-fg-1")}>{n.title}</div>
                        {n.body && <div className="mt-0.5 break-words text-[11px] text-fg-3">{n.body}</div>}
                        <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[11px] text-fg-3">
                          <span>{fmtRelative(n.at)}</span>
                          {money && <span>{money}</span>}
                          {n.link && (
                            <Link to={n.link} onClick={() => setOpen(false)} className="text-accent hover:underline">
                              Open
                            </Link>
                          )}
                        </div>
                      </div>
                      <Tooltip content="Dismiss">
                        <button
                          type="button"
                          onClick={() => dismiss([n.id])}
                          aria-label={`Dismiss: ${n.title}`}
                          className="grid h-5 w-5 shrink-0 place-items-center rounded-1 text-fg-3 hover:bg-bg-3 hover:text-fg-0"
                        >
                          <Icon icon={X} size={11} />
                        </button>
                      </Tooltip>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </span>
  );
}
