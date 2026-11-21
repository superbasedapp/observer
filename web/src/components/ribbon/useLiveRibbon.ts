import { useCallback, useSyncExternalStore } from "react";
import { useApi } from "@/lib/useApi";
import { useGovernanceVisibility } from "@/lib/governance";
import { hiddenNavIds } from "@/lib/visibility";
import { isLiveStatus } from "@/lib/launchStatus";
import { useOptionalLaunchDock } from "@/components/LaunchDock";
import {
  RIBBON_PARAMS,
  RIBBON_PATH,
  RIBBON_POLL_MS,
  readMinimised,
  shouldPollDetail,
  writeMinimised,
  type RibbonReceipt,
  type RibbonResponse,
  type RibbonSession,
} from "@/lib/ribbon";
import type { StatusSnapshot } from "@/lib/types";

// useLiveRibbon is the one reader the chip (TopBar), the strip and the
// receipt (LiveRibbon) share. Every request goes through the shared query
// cache, so two readers cost one request:
//
//   - the gate is the nav's own /api/status poll (the Sidebar already polls
//     it every 5 s; selecting live_sessions adds no request);
//   - the detail read GET /api/live?view=ribbon runs once on mount (it also
//     carries the off switch and the receipt) and every 5 s only while the
//     gate says something may be live (lib/ribbon.ts GATE_RULES). useApi
//     pauses it while the tab is hidden.

const selectLive = (s: StatusSnapshot): number | null => s.counts?.live_sessions ?? null;
const selectPerTool = (s: StatusSnapshot) => s.per_tool_last_seen ?? null;

export type LiveRibbonState = {
  /** The ribbon renders nothing: the org hid Live, or it is switched off. */
  off: boolean;
  /** The ribbon read answered (with any shape). */
  answered: boolean;
  /** The daemon knows the ribbon read (an older one does not). */
  supported: boolean;
  /** How many sessions are live right now (0 when not reading). */
  live: number;
  /** The newest live sessions, newest activity first. */
  sessions: RibbonSession[];
  /** The response on screen is current (not a previous one being refreshed). */
  current: boolean;
  receipt: RibbonReceipt | null;
  /** Per-tool activity, for "Start one"'s preselected tool. */
  perTool: StatusSnapshot["per_tool_last_seen"] | null;
};

export function useLiveRibbon(): LiveRibbonState {
  const vis = useGovernanceVisibility();
  // Fails closed while the posture is unknown, like the route guard.
  const liveHidden = vis.posture !== "ready" || hiddenNavIds(vis.gov).includes("live");
  const statusLive =
    useApi<StatusSnapshot, number | null>("/api/status", undefined, [], {
      refreshMs: 5000,
      select: selectLive,
    }).data ?? null;
  const perTool =
    useApi<StatusSnapshot, StatusSnapshot["per_tool_last_seen"] | null>("/api/status", undefined, [], {
      refreshMs: 5000,
      select: selectPerTool,
    }).data ?? null;
  const dock = useOptionalLaunchDock();
  const dockRunning = !!dock?.sessions.some((s) => isLiveStatus(dock.statuses[s.token]));

  // The detail read's own last answer keeps the poll going until it reports
  // nothing live (the nav count can lag ~20 s behind).
  const probe = useApi<RibbonResponse>(liveHidden ? null : RIBBON_PATH, RIBBON_PARAMS, [], {
    refreshMs: 0,
  });
  const supported = probe.data?.view === "ribbon";
  const enabled = probe.data == null ? null : supported ? probe.data.enabled : null;
  const poll = shouldPollDetail({
    liveHidden,
    enabled,
    statusLive,
    dockRunning,
    detailLive: supported ? (probe.data?.active_count ?? 0) : 0,
  });
  const detail = useApi<RibbonResponse>(liveHidden ? null : RIBBON_PATH, RIBBON_PARAMS, [], {
    refreshMs: poll && supported ? RIBBON_POLL_MS : 0,
  });
  const data = supported ? detail.data : null;
  const sessions = poll && data ? data.sessions ?? [] : [];
  return {
    off: liveHidden || enabled === false || (probe.data != null && !supported),
    // Hidden by the org counts as answered (there is nothing to wait for);
    // an unknown posture does not.
    answered: (vis.posture === "ready" && liveHidden) || probe.data != null || probe.error != null,
    supported,
    live: poll && data ? data.active_count : 0,
    sessions,
    current: data != null && !detail.isStale,
    receipt: data?.receipt ?? null,
    perTool,
  };
}

// ---------------------------------------------------------------- minimise

// The strip's "minimised" preference is per browser (a viewing preference),
// read once and shared between the chip and the strip through this store.
let minimised: boolean | null = null;
const listeners = new Set<() => void>();

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

function snapshot(): boolean {
  if (minimised == null) minimised = readMinimised(storage());
  return minimised;
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** useRibbonMinimised is the strip's per-browser fold state. */
export function useRibbonMinimised(): [boolean, (next: boolean) => void] {
  const value = useSyncExternalStore(subscribe, snapshot, () => false);
  const set = useCallback((next: boolean) => {
    minimised = next;
    writeMinimised(storage(), next);
    for (const l of listeners) l();
  }, []);
  return [value, set];
}
