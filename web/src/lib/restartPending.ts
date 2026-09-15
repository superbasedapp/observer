// restartPending — tiny localStorage store tracking config saves the
// daemon hasn't picked up yet (usability arc P1.9 / A7; key-level state
// added by the dashboard-config-management arc, plan §3.3 item 1).
//
// Lifecycle: StructuredConfigSection, SchemaSection and the bespoke forms
// call markRestartPending(section, keys?) after a save whose response said
// restart_required. RestartPendingBanner renders the pending set — naming
// the KEYS when the save reported them, so "3 settings apply on restart:
// dashboard.addr, proxy.port, …" — and auto-clears it once /api/status
// reports a daemon started_at NEWER than the latest save, i.e. the operator
// actually restarted. Manual dismiss also clears (the operator saying "I
// know"). A `live` / `next_spawn` save never marks anything pending.

const KEY = "sb_restart_pending";
// Window event fired on every mutation so the banner re-renders
// without prop-drilling through the Settings tree.
export const RESTART_PENDING_EVENT = "sb-restart-pending-changed";

export type RestartPending = {
  // ISO timestamp of the most recent restart-required save.
  at: string;
  // Distinct section ids saved since the last restart/dismiss.
  sections: string[];
  // Distinct dotted config keys that bind at daemon start, when the save
  // reported them (schema-driven saves do; older bespoke verbs may not).
  keys?: string[];
};

export function getRestartPending(): RestartPending | null {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as RestartPending;
    if (!parsed || typeof parsed.at !== "string" || !Array.isArray(parsed.sections)) {
      return null;
    }
    if (parsed.keys != null && !Array.isArray(parsed.keys)) parsed.keys = undefined;
    return parsed;
  } catch {
    return null;
  }
}

export function markRestartPending(section: string, keys?: string[]): void {
  const cur = getRestartPending();
  const sections = new Set(cur?.sections ?? []);
  sections.add(section);
  const keySet = new Set(cur?.keys ?? []);
  for (const k of keys ?? []) keySet.add(k);
  const next: RestartPending = {
    at: new Date().toISOString(),
    sections: [...sections].sort(),
    keys: keySet.size > 0 ? [...keySet].sort() : undefined,
  };
  try {
    localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    // Storage unavailable (private mode) — the banner just won't
    // persist across reloads; the save itself already showed its
    // inline restart notice.
  }
  window.dispatchEvent(new CustomEvent(RESTART_PENDING_EVENT));
}

export function clearRestartPending(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    // ignore
  }
  window.dispatchEvent(new CustomEvent(RESTART_PENDING_EVENT));
}
