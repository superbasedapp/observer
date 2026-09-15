// keyPlatform — which modifier VOCABULARY the on-screen terminal key bar should
// speak (D13 of the mobile-terminal pass).
//
// THE DEFECT THIS EXISTS FOR (operator-reported, phone, 2026-07-27): "we only
// see Windows-based keyboard options, that too just Ctrl, Alt and what I assume
// are Alt+C and Alt+D buttons". A Mac user reads `Ctrl`/`Alt` as someone else's
// keyboard, and caret notation (`^C`) as `Alt+C`. The bar was PC-only and
// unlabelled by action.
//
// WHAT THIS IS NOT — read before adding a key. This is a LABELLING layer and
// nothing else. A PTY receives BYTES: `Ctrl+C` is 0x03 on macOS, Linux and
// Windows alike; there is no per-OS byte set, so `applySoftMods` / `arrowSeq`
// are platform-independent by construction and must stay that way. And there is
// no ⌘ to add: macOS's Command key never reaches a terminal at all — the
// terminal APPLICATION intercepts it (⌘C is "copy"), which is why a ⌘ button
// would be a control that provably does nothing (the honest-affordance rule).
// The bar therefore carries an honest note instead of a dead key.
//
// WHY AUTO-DETECT ALONE IS WRONG. The labels must describe the machine being
// TYPED INTO, not the machine holding the glass. The dashboard's whole point is
// that the phone in your hand is driving a daemon somewhere else — an Android
// phone can be driving a Mac, and a MacBook can be driving a Linux box. So
// detection is only the DEFAULT, and the operator gets an explicit override that
// persists per-browser, like every other client-side preference in this app
// (`sb_*` localStorage key + a window event so every mounted consumer re-reads,
// the same shape as lib/restartPending.ts).

import { useCallback, useEffect, useState } from "react";
import { fetchJSON } from "@/lib/api";
import type { StatusSnapshot } from "@/lib/types";

/** KeyPlatform is the resolved modifier vocabulary — never a byte-level fact. */
export type KeyPlatform = "mac" | "pc";

/** KeyPlatformPref is what the user chose; "auto" defers to the HOST's OS. */
export type KeyPlatformPref = "auto" | KeyPlatform;

/** Persisted per-browser, alongside sb_theme / sb_win / sb_dock_pos. */
export const KEY_PLATFORM_LS_KEY = "sb_terminal_key_platform";

/** Fired on every override change so every mounted key bar re-reads at once. */
export const KEY_PLATFORM_EVENT = "sb-terminal-key-platform-changed";

// ── The auto signal: the DAEMON's OS, never the browser's ───────────────────
//
// The labels describe the keyboard conventions of the machine whose PTY you
// are typing into. That machine is the daemon's host — and the browser is very
// often a phone that is not it (the whole point of the mobile terminal is
// driving a desktop from a handset). The browser's user-agent was the original
// signal here and was simply the wrong machine; it is gone rather than kept as
// a second source of truth (CLAUDE.md: one owner per piece of state).
//
// `/api/status.host_os` is the daemon's runtime.GOOS. It never changes for a
// running daemon, so it is fetched ONCE per page load (single-flight across
// every mounted key bar) and mirrored into localStorage so a repeat visit
// starts already-resolved and the bar never relabels under the operator's
// thumb.

/** Last-known daemon OS, cached across reloads so nothing flickers on open. */
export const HOST_OS_LS_KEY = "sb_host_os";

/**
 * HOST_OS_UNKNOWN is the honest sentinel for "asked, and the answer carries no
 * OS" — an older daemon whose /api/status predates the field. Distinct from
 * `null`, which means "not asked yet"; BOTH render the fallback vocabulary,
 * but only `null` is retried.
 */
export const HOST_OS_UNKNOWN = "unknown";

/**
 * FALLBACK_PLATFORM is what an unknown host gets: "pc".
 *
 * Deliberately conservative and unchanged from what shipped — `Ctrl`/`Alt` is
 * the label a Linux/Windows operator expects and is also what a Mac operator
 * can still parse (Option is famously stamped "alt"). A speculative "mac"
 * would show ⌃/⌥ to someone who has never owned either glyph.
 */
export const FALLBACK_PLATFORM: KeyPlatform = "pc";

let hostOS: string | null = null;
let hostOSAnswered = false;
let hostOSInflight: Promise<void> | null = null;
const hostOSSubscribers = new Set<(os: string | null) => void>();

function readCachedHostOS(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(HOST_OS_LS_KEY);
  } catch {
    return null; /* storage blocked (private mode) — we just re-ask */
  }
}

function publishHostOS(os: string): void {
  hostOSAnswered = true;
  if (hostOS === os) return;
  hostOS = os;
  try {
    window.localStorage.setItem(HOST_OS_LS_KEY, os);
  } catch {
    /* storage blocked — the value still applies for this page load */
  }
  for (const fn of hostOSSubscribers) fn(os);
}

/**
 * ensureHostOS asks the daemon once per page load.
 *
 * A failed request leaves the question OPEN (no sentinel written), so the next
 * key bar to mount re-asks rather than latching a guess — a dashboard that
 * briefly loses its backend must not permanently mislabel its keys.
 */
function ensureHostOS(): void {
  if (hostOSAnswered || hostOSInflight) return;
  hostOSInflight = fetchJSON<StatusSnapshot>("/api/status")
    .then((s) => {
      const v = typeof s?.host_os === "string" ? s.host_os.trim() : "";
      publishHostOS(v || HOST_OS_UNKNOWN);
    })
    .catch(() => {
      /* offline / 401 / restarting — stay unresolved and retry on next mount */
    })
    .finally(() => {
      hostOSInflight = null;
    });
}

/**
 * hostKeyPlatform maps a runtime.GOOS string onto a modifier vocabulary.
 *
 * Only darwin speaks ⌃/⌥. `null` (not asked yet), "" and "unknown" all take
 * the fallback, so a loading dashboard and an old daemon behave identically.
 */
export function hostKeyPlatform(os: string | null | undefined): KeyPlatform {
  return os === "darwin" ? "mac" : FALLBACK_PLATFORM;
}

/**
 * useHostOS returns the daemon's runtime.GOOS, or null until it is known.
 *
 * Module-level state, not per-hook: every mounted key bar shares ONE answer and
 * ONE request.
 */
export function useHostOS(): string | null {
  const [os, setOS] = useState<string | null>(() => hostOS ?? readCachedHostOS());
  useEffect(() => {
    hostOSSubscribers.add(setOS);
    // Adopt whatever landed between the initial render and this effect.
    if (hostOS !== null) setOS(hostOS);
    ensureHostOS();
    return () => {
      hostOSSubscribers.delete(setOS);
    };
  }, []);
  return os;
}

/** readKeyPlatformPref returns the stored override ("auto" when unset). */
export function readKeyPlatformPref(): KeyPlatformPref {
  if (typeof window === "undefined") return "auto";
  try {
    const v = window.localStorage.getItem(KEY_PLATFORM_LS_KEY);
    if (v === "mac" || v === "pc" || v === "auto") return v;
  } catch {
    /* storage blocked (private mode) — the default is still correct */
  }
  return "auto";
}

/** writeKeyPlatformPref persists the override and notifies every consumer. */
export function writeKeyPlatformPref(pref: KeyPlatformPref): void {
  if (typeof window === "undefined") return;
  try {
    if (pref === "auto") window.localStorage.removeItem(KEY_PLATFORM_LS_KEY);
    else window.localStorage.setItem(KEY_PLATFORM_LS_KEY, pref);
  } catch {
    /* storage blocked — the choice still applies for this tab */
  }
  window.dispatchEvent(new Event(KEY_PLATFORM_EVENT));
}

/**
 * resolveKeyPlatform collapses a preference plus the host's OS into the
 * vocabulary to render. An explicit preference ALWAYS wins — the override is
 * the escape hatch for every case the host OS cannot describe (a Mac keyboard
 * plugged into a Linux box, a remote seat, an operator who simply prefers the
 * words).
 */
export function resolveKeyPlatform(
  pref: KeyPlatformPref,
  hostOS: string | null | undefined,
): KeyPlatform {
  return pref === "auto" ? hostKeyPlatform(hostOS) : pref;
}

/** nextKeyPlatformPref cycles auto -> mac -> pc -> auto (a 3-state toggle). */
export function nextKeyPlatformPref(pref: KeyPlatformPref): KeyPlatformPref {
  return pref === "auto" ? "mac" : pref === "mac" ? "pc" : "auto";
}

// ── The label table (CLAUDE.md #5: a table, not a conditional ladder) ────────
//
// `main` is what the key shows; `sub` is the small second line. Every entry is
// PURELY presentational — the emitted bytes live in TerminalKeyBar's encoders
// and are identical on both rows.
const LABELS: Record<
  KeyPlatform,
  {
    ctrl: { main: string; sub?: string };
    alt: { main: string; sub?: string };
    /** How a Ctrl-chord is spelled on the action keys' sub-label. */
    chord: (letter: string) => string;
    /** Accessible-name stem for the modifier buttons. */
    ctrlName: string;
    altName: string;
  }
> = {
  // PC row is byte-for-byte the labelling that shipped, so a Linux/Windows
  // operator sees no change at all.
  pc: {
    ctrl: { main: "Ctrl" },
    alt: { main: "Alt" },
    chord: (l) => `Ctrl+${l}`,
    ctrlName: "Ctrl",
    altName: "Alt / Opt",
  },
  // Apple: the glyph is the recognisable part, the word is the confirmation.
  // Stacked rather than inline ("⌃ Control") because the bar is a fixed
  // 5-column grid — an inline label does not fit a 66px column at 360px.
  mac: {
    ctrl: { main: "⌃", sub: "Control" },
    alt: { main: "⌥", sub: "Option" },
    chord: (l) => `⌃${l}`,
    ctrlName: "Control (⌃)",
    altName: "Option (⌥)",
  },
};

/** keyLabels returns the presentation table for a resolved platform. */
export function keyLabels(platform: KeyPlatform) {
  return LABELS[platform];
}

/**
 * CMD_NOTE is the honest note shown where a Mac user would look for ⌘.
 *
 * Its absence must read as deliberate, not broken: ⌘ is intercepted by the
 * terminal application (⌘C = copy) and never becomes a byte on the wire, so
 * there is nothing for a button here to send.
 */
export const CMD_NOTE = "⌘ never reaches a terminal - your terminal app keeps it";

/**
 * platformPrefLabel is the ⋯-menu row copy for each preference state.
 *
 * `resolved` is the vocabulary actually on screen (from useKeyPlatform), so
 * the "Auto (…)" row names what the daemon's OS produced rather than
 * re-deriving it.
 */
export function platformPrefLabel(
  pref: KeyPlatformPref,
  resolved: KeyPlatform,
): string {
  if (pref === "auto") {
    return `⌨ Key labels: Auto (${resolved === "mac" ? "Mac ⌃⌥" : "PC Ctrl/Alt"})`;
  }
  return pref === "mac" ? "⌨ Key labels: Mac ⌃⌥" : "⌨ Key labels: PC Ctrl/Alt";
}

/**
 * useKeyPlatform is the ONE owner of the vocabulary decision for a mounted
 * tree: the operator's preference, plus the daemon's OS as the auto signal.
 *
 * LaunchTerminal calls it and passes the RESOLVED platform down to
 * TerminalKeyBar as a plain string, so neither the preference type nor the
 * host OS spreads into the presentation layer (CLAUDE.md #2).
 *
 * On the very first visit of a fresh browser profile the host OS is not yet
 * known when the bar first paints, so it paints the fallback (Ctrl/Alt) and
 * adopts ⌃/⌥ once the answer lands. That window is one request long, happens
 * before the operator can reach the keys, and never recurs: the answer is
 * cached in localStorage, so every later open — and every later terminal in
 * this page — starts already-resolved. The labels then change for exactly two
 * reasons: that first resolution, and an explicit override.
 */
export function useKeyPlatform(): {
  pref: KeyPlatformPref;
  platform: KeyPlatform;
  /** The daemon's runtime.GOOS, or null while it is still unknown. */
  hostOS: string | null;
  setPref: (p: KeyPlatformPref) => void;
  cycle: () => void;
} {
  const hostOS = useHostOS();
  const [pref, setPrefState] = useState<KeyPlatformPref>(() =>
    readKeyPlatformPref(),
  );

  useEffect(() => {
    const sync = () => setPrefState(readKeyPlatformPref());
    window.addEventListener(KEY_PLATFORM_EVENT, sync);
    // `storage` fires for OTHER tabs, so a change made in one dashboard tab
    // reaches the terminal open in another.
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(KEY_PLATFORM_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const setPref = useCallback((p: KeyPlatformPref) => {
    writeKeyPlatformPref(p);
    setPrefState(p);
  }, []);

  const cycle = useCallback(() => {
    setPref(nextKeyPlatformPref(readKeyPlatformPref()));
  }, [setPref]);

  return {
    pref,
    platform: resolveKeyPlatform(pref, hostOS),
    hostOS,
    setPref,
    cycle,
  };
}
