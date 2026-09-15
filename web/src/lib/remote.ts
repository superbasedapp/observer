// Remote-vs-local detection for the dashboard SPA.
//
// The owner-trusted dashboard binds loopback only (a non-loopback direct bind
// is refused unless the [remote] substrate is armed, and the tailnet-serve
// backend is itself loopback but reached through the tailnet host). So the SPA
// is being viewed from a REMOTE-paired device exactly when the page's own host
// is NOT a loopback name/IP -- the same distinction the Go browserGuard draws
// server-side (hostIsLoopback). This needs no network round-trip and no new
// endpoint: the terminal-control UX branches on it to decide whether input is
// owner-local (automatic writer) or remote (read-only until an execute
// capability is acquired over the WS acquire-writer frame).

// isLoopbackHost reports whether a bare hostname/IP is a loopback address.
export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  // 127.0.0.0/8
  return /^127(?:\.\d{1,3}){3}$/.test(h);
}

// isRemoteView reports whether the current page is being served to a
// remote-paired device (non-loopback host) rather than the owner-local loopback
// dashboard. Safe in non-browser contexts (returns false when no location).
export function isRemoteView(): boolean {
  if (typeof window === "undefined" || !window.location) return false;
  return !isLoopbackHost(window.location.hostname);
}

// --- Session classification (tags / favorites / notes) remote gate ---
//
// POST /api/session/<id>/tags and POST /api/sessions/tags/manage are registered
// Execute-class (internal/intelligence/dashboard/dashboard.go "/tags" +
// "/api/sessions/tags/manage"). On a paired REMOTE device the fetch layer sends
// X-Remote-CSRF, which only ever proves View; Execute additionally requires a
// single-use X-Remote-Execute capability whose binding is (device session,
// METHOD + " " + PATH) — see remoteController.Principal.
//
// No such capability is obtainable for these routes. The only mint in the
// product is MintTerminalControl(deviceHash, terminalHandle) behind the
// owner-LOCAL /api/remote/approve-execute route: it is bound to a terminal
// handle and consumed by the PTY writer websocket, so it can never satisfy a
// "POST /api/session/<id>/tags" action binding. The generic MintExecute has no
// HTTP surface at all (CLI verb only). A remote classification mutation is
// therefore a guaranteed 403, exactly like the owner-local workspace-layout
// save that WorkspaceGrid already declines to attempt.
//
// So the affordances are disabled up front with copy naming the exact missing
// dependency (the house honest-disabled-control rule), while every READ-ONLY
// classification surface — pills, the tag rollup, tag/favorite filters — stays
// fully functional remotely.
export function canClassifySessions(): boolean {
  return !isRemoteView();
}

// CLASSIFY_REMOTE_BLOCKED_MSG is the tooltip/title shown on every disabled
// classification affordance on a paired remote device.
export const CLASSIFY_REMOTE_BLOCKED_MSG =
  "Tagging from a paired device needs a remote-execute approval, and the only approval SuperBased mints is scoped to one terminal - tags, favorites and notes are read-only here. Use the owner's local dashboard to classify sessions.";

const REMOTE_CSRF_KEY = "sb_remote_csrf";

export function getRemoteCSRF(): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(REMOTE_CSRF_KEY) || "";
}

export function setRemoteCSRF(value: string): void {
  if (typeof window === "undefined") return;
  if (value) {
    window.localStorage.setItem(REMOTE_CSRF_KEY, value);
  } else {
    window.localStorage.removeItem(REMOTE_CSRF_KEY);
  }
}
