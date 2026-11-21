import { useEffect, useState } from "react";
import { useApi } from "@/lib/useApi";
import { CONNECT_STATUS_PATH, type ConnectStatus } from "@/lib/connect";
import {
  HANDOFF_POLL_MS,
  handoffPhase,
  parseHandoff,
  withoutHandoff,
  type Handoff,
  type HandoffPhase,
} from "@/lib/connectHandoff";
import type { Account } from "@/lib/getStarted";
import type { EnrolmentStatus } from "@/lib/types";

// useConnectHandoff is the one reader of the installer's ?connecting=1
// hand-off (lib/connectHandoff.ts decides everything). The query is read once
// per page load, so the Overview card, the top bar and the tour agree for the
// whole visit even after the address is cleaned.
//
// While it waits it reads the status routes every few seconds, also while
// this tab is in the background (the person is on the approval tab). The
// installer restarts the daemon right after connecting, so some reads fail:
// the query cache keeps the last answer and keeps polling, and the phase
// stays "waiting" until a read says connected. Only then is the query
// removed from the address (history.replaceState).

type HandoffVisit = { handoff: Handoff | null; startedAt: number };

let visit: HandoffVisit | null = null;

/** handoffVisit is this page load's hand-off, read from the address once. */
export function handoffVisit(): HandoffVisit {
  if (visit == null) {
    let search = "";
    try {
      search = typeof window === "undefined" ? "" : window.location.search;
    } catch {
      search = "";
    }
    visit = { handoff: parseHandoff(search), startedAt: Date.now() };
  }
  return visit;
}

/** How often the expiry is re-checked while waiting. */
const CLOCK_MS = 15_000;

export function useConnectHandoff(account: Account | null): { handoff: Handoff | null; phase: HandoffPhase } {
  const { handoff, startedAt } = handoffVisit();
  const [now, setNow] = useState(() => Date.now());
  const phase = handoffPhase({ handoff, account, startedAt, now });
  const waiting = phase === "waiting";

  // The same keys useAccount reads: the fastest subscriber sets the shared
  // timer, so the account every surface shows moves at this pace too.
  const pollOpts = { refreshMs: HANDOFF_POLL_MS, refreshWhenHidden: true };
  useApi<ConnectStatus>(waiting ? CONNECT_STATUS_PATH : null, undefined, [], pollOpts);
  useApi<EnrolmentStatus>(waiting ? "/api/enrolment/status" : null, undefined, [], pollOpts);

  useEffect(() => {
    if (!waiting) return;
    const id = window.setInterval(() => setNow(Date.now()), CLOCK_MS);
    return () => window.clearInterval(id);
  }, [waiting]);

  useEffect(() => {
    if (phase !== "connected") return;
    try {
      const next = withoutHandoff(window.location.href);
      if (next !== window.location.pathname + window.location.search + window.location.hash) {
        window.history.replaceState(window.history.state, "", next);
      }
    } catch {
      // Not a browser address: nothing to clean.
    }
  }, [phase]);

  return { handoff, phase };
}
