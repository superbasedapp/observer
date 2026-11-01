import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { pushToastWith } from "@/components/Toast";
import { useMessagesSummary } from "@/lib/useMessagesSummary";
import { decideToast, initials, threadLink, toastKicker, toastTitle } from "@/lib/adminMessages";

// MessageToast raises the in-dashboard toast when an admin message arrives
// while the dashboard is open (T-854, the "toast" surface). It renders
// nothing itself: the shared ToastViewport draws the toast, with Open and
// Reply actions that land on the conversation. The decision (first poll
// only records, once per message, off when the developer turned the toast
// surface off, never for the thread already on screen) is
// lib/adminMessages.ts decideToast.

// seen survives route changes but not a reload: the first poll of a page
// load records the newest message without announcing it.
let seen = -1;

export function MessageToast() {
  const summary = useMessagesSummary();
  const navigate = useNavigate();
  const { pathname, search } = useLocation();
  const openThread = pathname === "/messages" ? new URLSearchParams(search).get("thread") : null;
  const data = summary.data;

  useEffect(() => {
    const d = decideToast(seen, data, openThread);
    seen = d.seen;
    if (!d.show || !d.message) return;
    const m = d.message;
    pushToastWith({
      kicker: toastKicker(m),
      title: toastTitle(m),
      text: m.require_ack ? "They asked you to acknowledge it." : "Open the conversation to read it and reply.",
      avatar: initials(m.author_name),
      variant: m.kind === "alert" ? "warn" : "info",
      durationMs: 15_000,
      actions: [
        { label: "Open", primary: true, onClick: () => navigate(threadLink(m.thread_id)) },
        { label: "Reply", onClick: () => navigate(threadLink(m.thread_id, true)) },
      ],
    });
    // openThread is read at decision time only; a route change alone must
    // not re-run the decision.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  return null;
}
