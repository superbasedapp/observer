import { useCallback, useEffect, useState } from "react";
import { useApi } from "@/lib/useApi";
import { apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { isRemoteView } from "@/lib/remote";
import {
  CONNECT_CANCEL_PATH,
  CONNECT_POLL_MS,
  CONNECT_PROGRESS_PATH,
  CONNECT_START_PATH,
  connectActive,
  connectCancelInit,
  connectFinished,
  connectReconsentInit,
  connectStartInit,
  accountOf,
  safeOpenURL,
  type Account,
  type ConnectProgress,
} from "@/lib/getStarted";
import { CONNECT_STATUS_PATH, type ConnectStatus } from "@/lib/connect";
import type { EnrolmentStatus } from "@/lib/types";

// useConnectFlow is the one client of the daemon's connect flow
// (lib/getStarted.ts, connect_flow.go): the Get started panel, the top
// bar's Sign in button and Settings > Account all call it, and the shared
// query cache gives them one poll of GET /api/connect/progress between
// them (fast while a flow runs, slow otherwise, so a flow started in one
// place shows in the others).
//
// Opening the approval page: a browser only lets a page open a tab inside
// the click itself, but the approval address arrives a second or two later
// on a progress read. So the click opens an empty tab at once and the hook
// points it at the approval page when the address arrives (and closes it
// if the flow ends first). If the browser blocked even that, the panel's
// "Open approval page" link is the way through.

/** The finished flow every reader was already told about (one refresh each). */
let announcedFinish = "";

/**
 * announceFinish re-reads every card once when a flow ends, so the status
 * chips, the enrolment and the panel all move together.
 */
function announceFinish(p: ConnectProgress | null): void {
  if (!p || !connectFinished(p) || !p.finished_at) return;
  const key = `${p.started_at ?? ""}|${p.finished_at}`;
  if (key === announcedFinish) return;
  const first = announcedFinish === "";
  announcedFinish = key;
  // A flow that had already finished before this page loaded is not news.
  if (first && !sawActive) return;
  window.dispatchEvent(new CustomEvent("dashboard-refresh"));
}

/** This page has seen a flow in flight. */
let sawActive = false;

/** The tab opened inside the click, waiting for the approval address. */
let pendingTab: Window | null = null;

function openPendingTab(): void {
  try {
    pendingTab = window.open("about:blank", "_blank");
    if (pendingTab) pendingTab.opener = null;
  } catch {
    pendingTab = null;
  }
}

function settlePendingTab(p: ConnectProgress | null): void {
  if (!pendingTab) return;
  const url = safeOpenURL(p?.approve_url);
  try {
    if (url) {
      pendingTab.location.href = url;
      pendingTab = null;
    } else if (connectFinished(p) || p?.state === "idle") {
      pendingTab.close();
      pendingTab = null;
    }
  } catch {
    pendingTab = null;
  }
}

export type ConnectFlow = {
  progress: ConnectProgress | null;
  /** A flow is in flight. */
  active: boolean;
  /** This view can start one (the owner's own browser, not a remote view). */
  available: boolean;
  busy: boolean;
  /** The start or cancel request itself failed (409 refusal, 403, ...). */
  error: string | null;
  start: (team?: string) => Promise<void>;
  /** Connect this machine again to the dashboard it already uses, to review
   *  and accept what it now offers (`observer connect --reconsent`). */
  reconsent: () => Promise<void>;
  cancel: () => Promise<void>;
  /** Opens the approval page again (the fallback link). */
  openApproval: () => void;
  reload: () => void;
};

export function useConnectFlow(): ConnectFlow {
  const available = !isRemoteView();
  const [fast, setFast] = useState(false);
  const progress = useApi<ConnectProgress>(available ? CONNECT_PROGRESS_PATH : null, undefined, [], {
    refreshMs: fast ? CONNECT_POLL_MS : 30000,
  });
  const p = progress.data;
  const active = connectActive(p);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setFast(active);
  }, [active]);

  useEffect(() => {
    settlePendingTab(p);
    if (connectActive(p)) sawActive = true;
    announceFinish(p);
  }, [p]);

  const reload = progress.reload;

  const start = useCallback(
    async (team = "") => {
      setError(null);
      setBusy(true);
      openPendingTab();
      try {
        const st = await fetchJSON<ConnectProgress>(CONNECT_START_PATH, undefined, connectStartInit(team, await localConfirmHeaders()));
        settlePendingTab(st);
        setFast(true);
        reload();
      } catch (e) {
        settlePendingTab({ state: "error", running: false });
        setError(apiReason(e));
      } finally {
        setBusy(false);
      }
    },
    [reload],
  );

  const reconsent = useCallback(async () => {
    setError(null);
    setBusy(true);
    openPendingTab();
    try {
      const st = await fetchJSON<ConnectProgress>(CONNECT_START_PATH, undefined, connectReconsentInit(await localConfirmHeaders()));
      settlePendingTab(st);
      setFast(true);
      reload();
    } catch (e) {
      settlePendingTab({ state: "error", running: false });
      setError(apiReason(e));
    } finally {
      setBusy(false);
    }
  }, [reload]);

  const cancel = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      await fetchJSON<ConnectProgress>(CONNECT_CANCEL_PATH, undefined, connectCancelInit(await localConfirmHeaders()));
      reload();
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusy(false);
    }
  }, [reload]);

  const openApproval = useCallback(() => {
    const url = safeOpenURL(p?.approve_url);
    if (url) window.open(url, "_blank", "noopener,noreferrer");
  }, [p?.approve_url]);

  return { progress: p, active, available, busy, error, start, reconsent, cancel, openApproval, reload };
}

/**
 * useAccount is the Account every surface shows (lib/getStarted.ts
 * accountOf): the front door's status, the enrolment and the connect flow,
 * read through the shared query cache so the top bar, the panel and
 * Settings > Account poll each route once between them.
 */
export function useAccount(flow: ConnectFlow): { account: Account | null; enrolment: EnrolmentStatus | null } {
  const status = useApi<ConnectStatus>(CONNECT_STATUS_PATH, undefined, [], { refreshMs: 30000 });
  const enrolment = useApi<EnrolmentStatus>("/api/enrolment/status", undefined, [], { refreshMs: 30000 });
  return {
    account: accountOf(status.data, enrolment.data, flow.progress),
    enrolment: enrolment.data,
  };
}
