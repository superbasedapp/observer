import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { isRemoteView } from "@/lib/remote";
import { pushToast } from "@/components/Toast";
import { useCompanionRegistry } from "@/components/primitives/companion";
import { Tooltip, TooltipSpan } from "@/components/primitives";
import { useMobileTerminal } from "@/lib/useMediaQuery";
import { platformPrefLabel, useKeyPlatform } from "@/lib/keyPlatform";
import {
  NO_SOFT_MODS,
  TerminalKeyBar,
  applySoftMods,
  clearOneShots,
  softModsActive,
  type SoftMods,
} from "@/components/TerminalKeyBar";
import {
  STANDING_REMEMBER_RISK,
  type TerminalControlDenialReason,
  forgetStandingSecret,
  getStoredStandingSecret,
  storeStandingSecret,
  terminalControlDenialMessage,
} from "@/lib/remoteTerminal";
import {
  clipboardReadAvailable,
  clipboardWriteAvailable,
  decodeOsc52,
  readClipboard,
  writeClipboard,
} from "@/lib/clipboard";

// LaunchTerminal renders the embedded web terminal for a launched session
// (Continue-in… → "Launch <tool> here"). It opens a websocket to
// /ws/launch/<token> — same-origin, so it passes the dashboard's
// browserGuard Host check AND coder/websocket's default cross-origin
// rejection — and bridges it to an xterm.js instance: terminal input rides
// BINARY frames (keystrokes), and a TEXT control frame carries resize
// ({"t":"resize",…}) out and exit ({"t":"exit","code"}) in.
//
// xterm is DYNAMIC-imported so its ~250 KB lands in the lazy `vendor-xterm`
// chunk — a user who never opens a terminal never downloads it (the same
// discipline as the other pinned vendor chunks).

type Props = {
  /** Opaque session handle minted by POST /api/session/<id>/launch. */
  token: string;
  /** Tool label for the header (e.g. "codex"). */
  tool: string;
  /** Kill the process + tear down the panel (destructive). */
  onClose: () => void;
  /** Collapse to the dock, keeping the ws + child process alive. */
  onMinimize: () => void;
  /** Report lifecycle status up to the dock (pill state + beforeunload guard). */
  onStatus?: (s: Status) => void;
  /**
   * Report the node-intervention policy-stop explanation up to the dock, when
   * the exit frame carried one (undefined = clear / nothing to show). Lets
   * the minimized pill surface the same explanation as the expanded modal.
   */
  onPolicyStop?: (info: PolicyStopInfo | undefined) => void;
  /** True while this session is the on-screen (expanded) panel. */
  expanded: boolean;
  /**
   * Fill the parent container instead of the fixed floating-panel height —
   * set by a Terminal Workspace grid tile so drag-resizing the tile actually
   * resizes the terminal (the ResizeObserver then refits the PTY). Additive:
   * existing callers keep the h-[60vh] floating panel.
   */
  fill?: boolean;
  /**
   * When set, the header shows "Add to grid" — one-click docking of this
   * floating terminal onto the Terminals workspace (the session keeps
   * running; the provider reparents the live xterm into a grid tile).
   * Absent for already-docked tiles and non-workspace hosts.
   */
  onAddToGrid?: () => void;
  /**
   * Open the per-terminal project panel (read-only file tree / git view).
   * Wired by the host (TerminalHost / grid tile); the panel itself is owned by
   * LaunchDockProvider. Header-button only — no effect on the ws bridge.
   */
  onOpenFiles?: () => void;
  onOpenGit?: () => void;
  /**
   * Open the per-terminal session cockpit panel (the Session Cockpit — cost,
   * tokens, live activity). Wired by the host (TerminalHost / grid tile); the
   * panel itself is owned by LaunchDockProvider. Header-button only — no
   * effect on the ws bridge.
   */
  onOpenSession?: () => void;
  /**
   * Register/unregister the paste-into-terminal callback for this token while
   * this seat is live + write-capable. The callback routes text through xterm's
   * OWN paste pipeline (`term.paste`) — identical to a manual Ctrl+V — so
   * bracketed-paste mode neutralizes shell metacharacters exactly as a real
   * clipboard paste does. The provider routes it to the token's project panel,
   * which shows its paste items only when a callback is registered (read-only
   * viewers register none).
   */
  registerPaste?: (fn: ((text: string) => void) | null) => void;
  /**
   * False when the run has no resolved project root — the Files/Git buttons
   * render disabled with an honest title. Absent → treated as false.
   */
  projectPanelEnabled?: boolean;
  /**
   * False when this terminal's run can't correlate to an observer session
   * (e.g. a plain shell run with no AI tool attached) — the Session button
   * renders disabled with an honest title. Absent → treated as false.
   */
  sessionPanelEnabled?: boolean;
};

export type Status =
  | "connecting"
  | "open"
  | "reconnecting"
  | "exited"
  | "error";

// PolicyStopInfo is the additive explanation the daemon attaches to a
// terminal's exit event when an org-managed node's OWN node-intervention
// loop stopped this PTY's child (server: internal/intelligence/dashboard
// policystop.go, over the guard_events process_control audit trail). It
// rides the {"t":"exit",…} control frame and GET
// /api/terminal/<handle>/status's `policy_stop` field verbatim — undefined
// means "nothing to show", never a guess.
export type PolicyStopInfo = {
  rule_id: string;
  decision: string;
  reason: string;
  at: string;
};

// policyStopMessage renders the honest, decision-aware sentence a UI surface
// should show — mirrors the server's PolicyStop.DisplayMessage so the
// wording matches regardless of which surface (terminal modal, dock pill,
// status API consumer) renders it. "terminated"/"killed" mean the daemon
// actually stopped the process; any other decision (e.g.
// "policy_unavailable") means the policy check itself failed, so the copy
// must not claim the process was stopped.
export function policyStopMessage(info: PolicyStopInfo): string {
  const stopped = info.decision === "terminated" || info.decision === "killed";
  if (stopped) {
    let msg = "Stopped by organization policy";
    if (info.rule_id) msg += ` (${info.rule_id})`;
    if (info.reason) msg += `: ${info.reason}`;
    return msg;
  }
  let msg = "Organization policy check failed; process was not stopped by the daemon";
  if (info.reason) msg += `: ${info.reason}`;
  return msg;
}

// isLiveStatus is the single predicate for "is this token still live?" — i.e.
// its project can still be browsed and it can still be docked/paste-targeted. A
// policy-rejected/errored socket ("error") is just as dead as an "exited" one
// (P2-3): both must gate the project panel off, close an open panel, and revoke
// the paste writer. Undefined/"connecting" count as live (optimistic, matching
// the pre-existing disabled-gate semantics).
//
// "reconnecting" is LIVE by construction (2026-07-25, mobile terminal-continuity
// arc): the PTY is a server-side object that outlives its viewers — the manager
// removes a viewer WITHOUT killing the process — so a dropped websocket says
// nothing at all about the session. Treating a transport drop as death is what
// made a phone returning from its mail app find every terminal tombstoned.
export function isLiveStatus(s: Status | undefined): boolean {
  return s !== "exited" && s !== "error";
}

// STANDING_REACQUIRE_COOLDOWN_MS bounds the automatic standing re-present that
// answers an expiry demote (review B3). A writer lease ages out on the order of
// minutes, so 5s never suppresses a legitimate re-acquire — it only stops a
// pathological server (or a demote storm) from turning one open socket into a
// stream of argon2 verifies.
const STANDING_REACQUIRE_COOLDOWN_MS = 5000;

// IMMEDIATE_RECONNECT_MIN_MS throttles the backoff-bypassing reconnect that a
// visibilitychange/pageshow triggers. One second is far below any human
// tab-switch cadence, so the intended "come back to the tab, terminal is there"
// flow is untouched.
const IMMEDIATE_RECONNECT_MIN_MS = 1000;

// isPermanentAuthDenial reports whether a control_denied reason is a PERMANENT
// verdict on the presented credential — the only condition under which a saved
// standing secret may be destroyed.
//
// It is deliberately an allow-list rather than "not one of these transient
// ones": a reason this client has never heard of (an older or newer daemon)
// must fall on the safe side, because forgetting the secret is irreversible for
// the user — the owner has to mint and convey a new one — while keeping a
// genuinely dead secret costs nothing but one more denied attempt.
//
// Exactly two reasons qualify:
//   - "auth"          the credential was compared and rejected (wrong/rotated).
//   - "auth_revoked"  standing access was revoked and never re-provisioned, so
//                     the server holds no secret at rest at all. Nothing was
//                     wrong with what this device sent — but nothing can match
//                     it again either, since a re-mint issues a different
//                     secret. Without this reason a revoked-and-forgotten
//                     secret sat in localStorage being retried forever.
//
// Everything else — notably "auth_transient" (standing access momentarily
// disabled with the secret still at rest, rate-limited, or an acquire that
// raced an admin transition) — keeps the secret.
function isPermanentAuthDenial(
  reason: TerminalControlDenialReason | undefined,
): boolean {
  return reason === "auth" || reason === "auth_revoked";
}

// keyboardApi returns the (Chromium-only) Keyboard Lock API surface without
// leaning on lib.dom types that don't yet declare `navigator.keyboard`.
type KeyboardLockApi = {
  lock?: (keys?: string[]) => Promise<void>;
  unlock?: () => void;
};
function keyboardApi(): KeyboardLockApi | undefined {
  return (navigator as unknown as { keyboard?: KeyboardLockApi }).keyboard;
}

// isBrowserReserved reports combos a normal browser tab cannot preventDefault
// (close-tab / new-tab / new-window). When the keyboard is LOCKED (focus mode)
// they DO reach the page, so they stop being reserved and we forward them to
// the TUI. Honest by construction: we never pretend to intercept Ctrl-W/T/N in
// a normal tab.
function isBrowserReserved(e: KeyboardEvent, locked: boolean): boolean {
  if (locked) return false;
  if (!(e.ctrlKey || e.metaKey)) return false;
  const k = e.key.toLowerCase();
  return k === "w" || k === "t" || k === "n";
}

// Control tracks who drives the PTY from THIS client's point of view.
//   - "local"      owner-loopback path: the WS acquires the local writer
//                  automatically (§4.α), so input is always live — no UI.
//   - "viewer"     remote device, read-only: input is dropped server-side
//                  (§4.β) until an execute capability is acquired.
//   - "requesting" an acquire-writer frame was sent; awaiting granted/denied.
//   - "writer"     remote device granted control (control_granted) — input live.
//   - "denied"     acquire was refused (control_denied) — stay a viewer.
//   - "revoked"    control was taken over / revoked (control_revoked) — input
//                  stops; the socket may then close on an admin kill.
export type Control =
  | "local"
  | "viewer"
  | "requesting"
  | "writer"
  | "denied"
  | "revoked";

export function LaunchTerminal({
  token,
  tool,
  onClose,
  onMinimize,
  onStatus,
  onPolicyStop,
  expanded,
  fill,
  onAddToGrid,
  onOpenFiles,
  onOpenGit,
  onOpenSession,
  registerPaste,
  projectPanelEnabled,
  sessionPanelEnabled,
}: Props) {
  const companion = useCompanionRegistry();
  // Touch presentation gate (capability query — coarse pointer AND small
  // viewport). EVERY branch keyed off this is additive: a desktop user, or a
  // desktop user who merely narrows the window, gets the shipped rendering
  // unchanged (CLAUDE.md rule 3).
  const isTouch = useMobileTerminal();
  // D13: which modifier VOCABULARY the on-screen key bar prints — the DAEMON's
  // OS (/api/status.host_os), overridable from the ⋯ menu. The host, not the
  // browser: the browser is often a phone that is not the machine whose PTY
  // this is. ONE owner here; the resolved platform goes down to TerminalKeyBar
  // as a plain string. Labels only — it changes no byte on the wire.
  const keyPlatform = useKeyPlatform();
  // Closure-stable mirror for the setup effect (deps [token, isRemote]) — the
  // clipboard hint names the ⌥/Shift modifier per the SAME resolved vocabulary
  // the key bar prints, and must not go stale when the override changes.
  const keyPlatformRef = useRef(keyPlatform.platform);
  useEffect(() => {
    keyPlatformRef.current = keyPlatform.platform;
  }, [keyPlatform.platform]);
  // Once-per-terminal latch for the "a TUI owns the mouse — Shift-drag to
  // select" hint. A ref, not state: it must never trigger a render, and it
  // resets naturally when the terminal is torn down.
  const selectionHintShownRef = useRef(false);
  // Clipboard verbs, reachable from the setup effect's closure (deps
  // [token, isRemote]) without widening those deps — the same assign-on-render
  // ref pattern reacquireLocalRef uses below.
  const copySelectionRef = useRef<(text: string) => Promise<void>>(
    async () => {},
  );
  const selectionHelpRef = useRef<() => string>(() => "");
  // Right-click Copy/Paste menu. Anchored at the pointer, viewport coordinates.
  const [ctxMenu, setCtxMenu] = useState<{
    x: number;
    y: number;
    hasSelection: boolean;
  } | null>(null);
  const hostRef = useRef<HTMLDivElement | null>(null);
  // Mirrors `expanded` for the ws handlers (closure-stable): only the
  // currently-expanded floating panel may steal focus on socket open — a
  // docked grid tile, a parked pill, or a background rehydrate must not
  // (review H2 residual).
  const expandedRef = useRef(expanded);
  useEffect(() => {
    expandedRef.current = expanded;
  }, [expanded]);
  // The outer panel element (header buttons + xterm host); the focus trap
  // treats anything inside it as a legitimate focus target.
  const rootRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<import("@xterm/xterm").Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [status, setStatus] = useState<Status>("connecting");
  const [exitCode, setExitCode] = useState<number | null>(null);
  // Set from the exit frame's optional policy_stop field (undefined when the
  // daemon has nothing to report — most exits). Lives alongside exitCode and
  // follows the same lifetime (a fresh mount, e.g. a relaunch, starts a new
  // component instance with fresh state).
  const [policyStop, setPolicyStop] = useState<PolicyStopInfo | undefined>(
    undefined,
  );
  const [errMsg, setErrMsg] = useState<string | null>(null);

  // Remote-writer control (§4). A remote-paired device starts read-only and
  // must acquire an execute capability; the owner-local loopback path is always
  // the writer, so it never shows control UI (the existing local UX is intact).
  const isRemote = useMemo(() => isRemoteView(), []);
  const [control, setControl] = useState<Control>(isRemote ? "viewer" : "local");
  // canWrite is read by the (long-lived) xterm onData handler via a ref so it
  // never sends keystrokes while this client is a viewer — the client half of
  // the §4.β server-side drop.
  const canWrite = control === "local" || control === "writer";
  const canWriteRef = useRef(canWrite);
  canWriteRef.current = canWrite;
  // Live status mirror read by the registered paste callback (P2-2): between an
  // exit/error frame flipping `status` and the effect cleanup that unregisters
  // the callback, a stale callback could still term.paste(). This ref is updated
  // synchronously every render so the callback can reject the moment the seat is
  // no longer "open".
  const statusRef = useRef(status);
  statusRef.current = status;

  // ── D3: sticky soft modifiers for the on-screen key bar ─────────────────
  // ONE OWNER (CLAUDE.md #4). The state lives here, not in TerminalKeyBar,
  // because an armed Ctrl must also apply to characters that arrive from the
  // PHONE'S OWN soft keyboard — those land on `term.onData`, below, which is
  // this component's single write seam. TerminalKeyBar owns the encoding table
  // (applySoftMods / arrowSeq) and the presentation; it reads this state and
  // reports changes back. The ref mirror is what the long-lived onData closure
  // reads.
  const [softMods, setSoftMods] = useState<SoftMods>(NO_SOFT_MODS);
  const softModsRef = useRef(softMods);
  softModsRef.current = softMods;
  const setSoftModsBoth = (next: SoftMods) => {
    softModsRef.current = next;
    setSoftMods(next);
  };
  // consumeSoftMods is called from term.onData for EVERY outbound keystroke.
  // With no modifier armed it is the identity function, so the desktop path is
  // byte-for-byte what it was. With one armed it encodes the combination and
  // retires the one-shot (a locked modifier survives).
  const consumeSoftMods = (data: string): string => {
    const m = softModsRef.current;
    if (!softModsActive(m)) return data;
    // ONLY a single printable character counts as "the keystroke this modifier
    // applies to". Everything else must pass through AND leave the armed
    // modifier alone, because onData also fires for
    //   - sequences the key bar already emitted fully formed (an arrow carries
    //     its own CSI modifier parameter), and — the sharp one —
    //   - xterm's AUTO-GENERATED protocol replies to TUI queries (CPR/DA).
    // A machine reply carries no human intent; spending the user's armed Ctrl
    // on it would make the modifier evaporate at random, whenever the TUI
    // happened to ask the terminal a question.
    const code = data.length === 1 ? data.charCodeAt(0) : -1;
    if (code < 0x20 || code > 0x7e) return data;
    const out = applySoftMods(data, m);
    const next = clearOneShots(m);
    if (next.ctrl !== m.ctrl || next.alt !== m.alt) setSoftModsBoth(next);
    return out;
  };

  // Acquire-control form state. The capability + confirm are held ONLY in these
  // inputs, cleared the instant the frame is sent — never persisted, never put
  // in a URL/query (§8.1 #5).
  const [showAcquire, setShowAcquire] = useState(false);
  const [capInput, setCapInput] = useState("");
  const [confirmInput, setConfirmInput] = useState("");
  const [acqErr, setAcqErr] = useState<string | null>(null);
  // Standing terminal-control secret (§B, device side). A device may store a
  // single global standing secret in localStorage so writer control survives a
  // page refresh with NO re-approval. When one is stored we auto-present it on
  // socket open (exactly once per open — never a retry loop). If the server
  // rejects it (revoked/rotated), we clear it and fall back to the one-time
  // flow. With NO stored secret, behaviour is identical to today's single-use
  // flow — nothing is auto-enabled.
  const [standingStored, setStandingStored] = useState<boolean>(
    () => isRemoteView() && getStoredStandingSecret() !== null,
  );
  const [standingInput, setStandingInput] = useState("");
  // Default OFF: remembering the secret in localStorage is an explicit opt-in
  // (it is the risky part — the secret then lives in this browser).
  const [rememberStanding, setRememberStanding] = useState(false);
  // standingAttemptRef marks that the in-flight acquire used a standing secret.
  // Only a PERMANENT credential denial (isPermanentAuthDenial) may then clear
  // the stored secret and show the revoked/rotated fallback; policy/lifecycle
  // denials preserve it.
  const standingAttemptRef = useRef(false);
  // lastStandingReacquireRef throttles the automatic standing re-present that
  // answers an EXPIRY demote (review B3). The socket stays open across an
  // aged-out lease, so `sock.onopen` — where the normal auto-present lives —
  // never re-fires; without this the "silently re-acquire" behaviour the
  // demote was built for did not exist and the user had to tap. A cooldown
  // bounds it to one attempt per window even if a server ever emitted expiry
  // demotes in a tight loop: the re-present is free for the user but costs the
  // server an argon2 verify.
  const lastStandingReacquireRef = useRef(0);
  // wasRevokedRef tracks whether THIS seat has lost control at least once, so a
  // later control_granted reads as REGAINING control (fire the "you have
  // control" toast) rather than a first-ever acquire (silent). Part of the
  // §6-decision-5 "silent takeover + visible toast in both seats" contract.
  const wasRevokedRef = useRef(false);
  // Highest generation observed on control_granted, plus whether this seat
  // still holds that live grant. A revoke for an older generation can arrive
  // after a rapid takeover → re-acquire grant; ignoring it keeps the display
  // aligned with the server's already-correct live writer lease.
  const latestGrantedGenRef = useRef(0);
  const hasLiveGrantRef = useRef(false);
  // The server identifies the requester that superseded this lease so both
  // local and remote seats can describe the handoff accurately.
  const [revokedBy, setRevokedBy] = useState<"local" | "remote" | null>(null);
  // sawActivityRef records whether this socket ever delivered real session
  // activity — an "exit" control frame OR any terminal output byte. It gates the
  // Jump-in race UX (P2-4): the server closes /ws/launch/<handle> with a
  // POLICY-VIOLATION (1008) + "session not found" when the attach handle is gone
  // by the time the socket opens (the child exited between the attach-list fetch
  // and the click). Without this, onclose paints every close as a bare "exited"
  // terminal, hiding that the session ended BEFORE the second seat could join.
  const sawActivityRef = useRef(false);

  // ── Feature A: per-terminal size mode ────────────────────────────────
  // "fit" (default) tracks the container; "original" pins the PTY to the
  // native terminal's launch-time geometry so a TUI that garbled itself on a
  // resize can be restored. Persisted per handle in sessionStorage (never the
  // server). The ref is read inside the long-lived ResizeObserver closure.
  const sizeKey = `sb_term_sizemode_${token}`;
  const [sizeMode, setSizeMode] = useState<"fit" | "original">(() => {
    try {
      return sessionStorage.getItem(sizeKey) === "original" ? "original" : "fit";
    } catch {
      return "fit";
    }
  });
  const sizeModeRef = useRef(sizeMode);
  sizeModeRef.current = sizeMode;
  useEffect(() => {
    try {
      sessionStorage.setItem(sizeKey, sizeMode);
    } catch {
      /* sessionStorage unavailable (private mode) — mode stays in-memory */
    }
  }, [sizeKey, sizeMode]);
  // The native terminal's launch-time geometry, delivered once by the server's
  // {t:"pty_size"} frame right after the bridge starts. 0/unknown → the restore
  // control renders honest-disabled.
  const [initialDims, setInitialDims] = useState<{
    rows: number;
    cols: number;
  } | null>(null);
  const initialDimsRef = useRef<{ rows: number; cols: number } | null>(null);
  // A read-only viewer's target display geometry = the writer's CURRENT PTY
  // dims (the pty_size frame carries both current rows/cols AND initial_*; we
  // prefer current so a writer that resized after launch is reflected, not the
  // stale launch geometry). Distinct from initialDimsRef, which the writer's
  // "original" size-mode legitimately re-pins to the LAUNCH dims.
  const writerGeomRef = useRef<{ rows: number; cols: number } | null>(null);
  // Hoisted so the size-mode buttons (outside the setup effect) can refit.
  const fitRef = useRef<import("@xterm/addon-fit").FitAddon | null>(null);

  // ── Feature B: local re-acquire after a native-terminal reclaim ──────
  const controlRef = useRef(control);
  controlRef.current = control;
  // Assigned each render so the long-lived onData/onMouseDown closures can call
  // the latest version (wsRef is stable; this only needs a live target).
  const reacquireLocalRef = useRef<() => void>(() => {});
  // Presentation-only downscale for a read-only remote viewer (Change 2b): set
  // inside the setup effect, called from the control-sync effect below so a
  // grant/revoke recomputes the scale without re-running the whole effect.
  const applyViewerScaleRef = useRef<() => void>(() => {});

  // ── Feature C: focus mode (fullscreen + Keyboard Lock, Chromium-only) ─
  const [focusMode, setFocusMode] = useState(false);
  const keyboardLockedRef = useRef(false);
  const focusModeSupported = useMemo(
    () =>
      typeof document !== "undefined" &&
      !!document.fullscreenEnabled &&
      typeof navigator !== "undefined" &&
      !!keyboardApi()?.lock,
    [],
  );

  useEffect(() => {
    let disposed = false;
    let ws: WebSocket | null = null;
    let term: import("@xterm/xterm").Terminal | null = null;
    let fit: import("@xterm/addon-fit").FitAddon | null = null;
    let ro: ResizeObserver | null = null;
    // Raw DOM listeners bound to the xterm HOST element (not to xterm itself),
    // so term.dispose() does not take them with it — collected here and undone
    // explicitly in the cleanup below.
    const hostCleanup: Array<() => void> = [];

    // ── Reconnect state (2026-07-25, mobile terminal-continuity arc) ────────
    // The server keeps the PTY alive across a viewer disconnect (termsession
    // Unsubscribe removes the viewer WITHOUT killing the child, and idle reaping
    // is off by default), so a closed socket is a TRANSPORT event, not a session
    // end. We therefore retry indefinitely while this component is mounted.
    // Two states are the exceptions where retrying would be wrong:
    //   ptyExited   — an authoritative {"t":"exit"} frame arrived: the child is
    //                 genuinely gone, there is nothing to reconnect to.
    //   sessionGone — a connect attempt was REJECTED with policy-violation 1008
    //                 having delivered nothing: the handle no longer exists.
    // Everything else backs off and tries again.
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    // Timestamp of the last backoff-BYPASSING reconnect (the visibility/pageshow
    // path), used to throttle it — see reconnectNow.
    let lastImmediateReconnect = 0;
    let ptyExited = false;
    let sessionGone = false;
    // Assigned once the terminal is mounted; the visibility handler below is
    // registered synchronously (so its removal in cleanup is unconditional) and
    // is simply inert until then.
    let reconnectNow: (() => void) | null = null;

    // Returning to a backgrounded tab must restore the terminal IMMEDIATELY,
    // bypassing whatever backoff delay is pending — this is the operator's exact
    // flow (leave to copy a code from the mail app, come back). Mobile browsers
    // FREEZE a backgrounded tab, so the socket is usually already dead by the
    // time we get here. pageshow covers the iOS/Safari bfcache restore, which
    // does not always fire visibilitychange.
    const onVisible = () => {
      if (disposed) return;
      if (document.visibilityState !== "visible") return;
      reconnectNow?.();
    };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("pageshow", onVisible);

    (async () => {
      // Lazy chunk: JS + CSS only load when a terminal is actually opened.
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import("@xterm/xterm"),
        import("@xterm/addon-fit"),
        import("@xterm/xterm/css/xterm.css"),
      ]);
      if (disposed || !hostRef.current) return;

      term = new Terminal({
        convertEol: false, // the PTY already emits CRLF
        cursorBlink: true,
        fontFamily:
          'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
        fontSize: 12,
        theme: { background: "#0b0b0f", foreground: "#e6e6e6" },
        // A full-screen TUI (opencode, claude-code 2.1.220+, etc.) turns on
        // DECSET mouse-tracking (?1000/1002/1003/1006h) so it can receive
        // clicks/drags itself. xterm couples that 1:1 to its OWN selection
        // engine: Terminal.ts disables SelectionService entirely for as long
        // as ANY mouse-tracking mode is active, so a plain click-drag no
        // longer produces a local text selection — the drag goes to the app
        // instead. xterm's shipped escape hatch is a modifier-held drag
        // forcing local selection regardless of mouse-tracking
        // (SelectionService.shouldForceSelection): Shift on Windows/Linux,
        // which is xterm's default and needs no config here — but on macOS
        // it instead checks Option, gated behind this option, whose default
        // is `false`. Without this, Mac users have no drag-to-select
        // fallback at all while a TUI owns the mouse. This is a terminal-
        // capability fix, not a per-tool one: every full-screen TUI trips it.
        macOptionClickForcesSelection: true,
      });
      fit = new FitAddon();
      term.loadAddon(fit);
      fitRef.current = fit;
      term.open(hostRef.current);
      termRef.current = term;

      // ── OSC 52: let a TUI put text on the SYSTEM clipboard ────────────────
      // THE root cause of "copy doesn't work in opencode" (and in vim, tmux,
      // helix, lazygit, claude-code — every TUI that offers its own copy verb).
      // A full-screen app owns the mouse (DECSET ?1000-?1003), so it renders
      // its OWN selection and, when you press its copy key, it does NOT put
      // anything in xterm's selection buffer — it emits
      //   ESC ] 52 ; c ; <base64 of the text> BEL
      // which is the terminal protocol's ONLY way for an application to reach
      // the system clipboard. xterm.js ships no handler for OSC 52 (that lives
      // in the separate @xterm/addon-clipboard package), and an unhandled OSC
      // is silently DISCARDED — so the copy appeared to work inside the TUI and
      // nothing ever landed on the clipboard. This is a terminal-capability
      // gap, not a per-tool bug: registering the handler fixes every TUI at
      // once.
      //
      // WRITE ONLY, NEVER READ. decodeOsc52 returns null for the `?` payload
      // (the clipboard *read* request) so we never answer one: replying would
      // hand the operator's clipboard to whatever is running in the terminal —
      // including a command an agent was talked into running. xterm ships the
      // read side disabled for exactly this reason.
      //
      // Returning `true` marks the sequence consumed either way, so a refused
      // read is not re-emitted as garbage into the grid.
      term.parser.registerOscHandler(52, (payload) => {
        const text = decodeOsc52(payload);
        if (text == null) return true;
        void writeClipboard(text).then((res) => {
          if (res === "failed") {
            pushToast(
              clipboardWriteAvailable()
                ? "The app tried to copy, but the browser refused clipboard access"
                : "The app tried to copy - the clipboard needs an https (or localhost) connection",
              "warn",
            );
            return;
          }
          // Confirm the write: the TUI has no way to tell the operator whether
          // the sequence actually reached the clipboard, so the terminal does.
          pushToast("Copied to clipboard", "success");
        });
        return true;
      });

      // ── Selection discoverability while a TUI owns the mouse ──────────────
      // With mouse-tracking on, xterm disables its selection engine outright,
      // so a plain click-drag selects NOTHING and reads as "copy is broken".
      // The escape hatch (Shift-drag, ⌥-drag on a Mac) is real but invisible.
      // Say it once per terminal, and only after a DRAG actually came up empty
      // — never as a pre-emptive nag, and never on a plain click-to-focus,
      // which is why the pointer travel is measured rather than just watching
      // for mouseup. 8px is comfortably past a hand tremor and well under any
      // deliberate text drag.
      let dragFrom: { x: number; y: number } | null = null;
      const onHostMouseDown = (e: MouseEvent) => {
        dragFrom = e.button === 0 ? { x: e.clientX, y: e.clientY } : null;
      };
      const onHostMouseUp = (e: MouseEvent) => {
        const from = dragFrom;
        dragFrom = null;
        if (!from) return;
        const moved = Math.hypot(e.clientX - from.x, e.clientY - from.y);
        if (moved < 8) return;
        if (selectionHintShownRef.current) return;
        const t = termRef.current;
        if (!t || t.hasSelection()) return;
        if (t.modes.mouseTrackingMode === "none") return;
        selectionHintShownRef.current = true;
        pushToast(
          keyPlatformRef.current === "mac"
            ? "This app is using the mouse - hold ⌥ Option and drag to select text, or right-click for Copy/Paste"
            : "This app is using the mouse - hold Shift and drag to select text, or right-click for Copy/Paste",
          "info",
        );
      };
      const hostEl = hostRef.current;
      hostEl.addEventListener("mousedown", onHostMouseDown);
      hostEl.addEventListener("mouseup", onHostMouseUp);
      hostCleanup.push(() => {
        hostEl.removeEventListener("mousedown", onHostMouseDown);
        hostEl.removeEventListener("mouseup", onHostMouseUp);
      });

      // ── Right-click Copy / Paste ──────────────────────────────────────────
      // The second half of the mouse-tracking problem. While a TUI has mouse
      // reporting on, xterm forwards the right-click to the app and cancels the
      // browser's own context menu, so the operator loses the ONE paste
      // affordance that needs no keyboard and no memorised chord. We render our
      // own menu instead.
      //
      // BUBBLE phase, preventDefault only: the app still receives the
      // right-click (xterm reports it from `mousedown`, which we do not touch);
      // all we take is the browser's default menu, which was not going to
      // appear anyway. SHIFT+right-click is the documented escape hatch — it
      // skips our menu and gives the browser's back.
      const onHostContextMenu = (e: MouseEvent) => {
        if (e.shiftKey) return;
        e.preventDefault();
        setCtxMenu({
          x: e.clientX,
          y: e.clientY,
          hasSelection: !!termRef.current?.hasSelection(),
        });
      };
      hostEl.addEventListener("contextmenu", onHostContextMenu);
      hostCleanup.push(() =>
        hostEl.removeEventListener("contextmenu", onHostContextMenu),
      );

      // STT/dictation note: no paste bridge lives here — none is needed. The
      // real defect was xterm swallowing plain Ctrl+V (mapped to \x16 and the
      // keydown cancelled), so the browser paste never fired and dictation
      // tools’ delayed fallback paste delivered a stale clipboard. The fix is
      // in the custom key handler below (return false for the paste combos):
      // the native paste then fires immediately and xterm’s own paste handler
      // forwards the clipboard, which still holds the transcription at that
      // instant — exactly like any regular input field.

      // Change 2b — presentation-only downscale for a read-only remote viewer.
      // A viewer renders the WRITER's PTY geometry (e.g. 120 cols); on a narrow
      // phone that overflows the container and is clipped by the root's
      // overflow-hidden. A viewer MUST NOT fit()/resize() the PTY (that reflows
      // the writer's TUI), so instead we visually scale the GRID (.xterm-screen)
      // down to the container width with transform-origin top-left. Writers
      // (local or granted remote) keep the untouched fit() path — this resets
      // any transform for them.
      const applyViewerScale = () => {
        const host = hostRef.current;
        if (!host) return;
        const xtermEl = host.querySelector<HTMLElement>(".xterm");
        if (!xtermEl) return;
        // Scale the GRID element, not the .xterm root: the root is a block that
        // fills the host (offsetWidth == host width), so measuring/scaling it
        // yields k≈1 and never shrinks an over-wide grid. .xterm-screen carries
        // the true cols×cellWidth pixel width. Fall back to the root only if the
        // screen layer isn't mounted yet.
        const screenEl = xtermEl.querySelector<HTMLElement>(".xterm-screen");
        const scaleEl = screenEl ?? xtermEl;
        // Not a read-only viewer → clear any prior scale and defer to fit().
        if (!(isRemote && !canWriteRef.current)) {
          scaleEl.style.transform = "";
          scaleEl.style.transformOrigin = "";
          // Clear any transform a prior seat left on the other element too.
          xtermEl.style.transform = "";
          xtermEl.style.transformOrigin = "";
          return;
        }
        // Render at the WRITER's CURRENT geometry (not the viewer's own
        // host-fitted size) so a 120-col writer TUI doesn't rewrap/scroll inside
        // a phone-sized 40-col viewer terminal. This is a CLIENT-DISPLAY-ONLY
        // resize — it never reaches the PTY (no sendResize/sendResizeNow here),
        // so it cannot reflow the writer's session.
        const writerDims = writerGeomRef.current ?? initialDimsRef.current;
        if (
          writerDims &&
          writerDims.cols > 0 &&
          writerDims.rows > 0 &&
          termRef.current &&
          (termRef.current.cols !== writerDims.cols ||
            termRef.current.rows !== writerDims.rows)
        ) {
          try {
            termRef.current.resize(writerDims.cols, writerDims.rows);
          } catch {
            /* ignore */
          }
        }
        const cs = getComputedStyle(host);
        const padX =
          (parseFloat(cs.paddingLeft) || 0) + (parseFloat(cs.paddingRight) || 0);
        const avail = host.clientWidth - padX;
        const rendered = scaleEl.offsetWidth; // layout width, unaffected by transform
        if (avail <= 0 || rendered <= 0) return;
        let k = avail / rendered;
        if (k > 1) k = 1; // presentation-only downscale; never upscale
        scaleEl.style.transformOrigin = "top left";
        scaleEl.style.transform = k < 1 ? `scale(${k})` : "";
      };
      applyViewerScaleRef.current = applyViewerScale;

      // Feature C1: route modified key combos to the TUI instead of the
      // browser/page where interception is possible; keep copy/paste native.
      term.attachCustomKeyEventHandler((e) => {
        if (e.type !== "keydown") return true;
        // Take-back gesture (Feature B): a REAL keyboard event in a revoked
        // local seat re-acquires control. This lives here — a trusted DOM
        // keydown — and deliberately NOT in term.onData: xterm also emits
        // onData for the protocol replies it auto-generates while parsing TUI
        // output (CPR/DA answers), and reclaiming on those would steal control
        // back from the native terminal with nobody at this keyboard — the
        // exact machine-reply hazard the server's ESC fence exists for.
        // Modifier-only presses don't count as intent.
        if (
          !isRemote &&
          controlRef.current === "revoked" &&
          !["Control", "Shift", "Alt", "Meta", "CapsLock"].includes(e.key)
        ) {
          reacquireLocalRef.current();
        }
        // Push-to-talk chords (Ctrl+Alt+*) / AltGr text: never touch.
        if (e.ctrlKey && e.altKey) return true;
        const mod = e.ctrlKey || e.metaKey;
        if (!mod) return true;
        // Ctrl+Shift+C — the terminal-standard EXPLICIT copy, and the only copy
        // gesture that is unambiguous while a TUI owns Ctrl+C as "interrupt".
        // Handled programmatically rather than left to the browser: Chrome maps
        // Ctrl+Shift+C to "inspect element", so a native copy never fires here,
        // and the selection may have been made with Shift-drag while xterm's
        // selection engine is otherwise disabled by mouse-tracking.
        //
        // Swallowed in BOTH branches (preventDefault + return false), the way
        // every real terminal emulator claims this chord — notably including
        // the no-selection branch, where sending xterm's ^C would turn a failed
        // copy into an interrupt.
        if (
          e.ctrlKey &&
          e.shiftKey &&
          !e.altKey &&
          (e.key === "c" || e.key === "C")
        ) {
          e.preventDefault();
          e.stopPropagation();
          const sel = termRef.current?.getSelection() ?? "";
          if (sel) void copySelectionRef.current(sel);
          else pushToast(selectionHelpRef.current(), "info");
          return false;
        }
        // Copy WITH a selection stays a native browser copy (don't send ^C).
        // The browser's copy event reaches xterm's own handler, which writes the
        // selection via ClipboardEvent.clipboardData — no `navigator.clipboard`
        // and so no secure-context requirement. That is why plain Ctrl+C copy
        // keeps working on a plain-http origin where the async API is absent.
        if (
          !e.altKey &&
          !e.shiftKey &&
          (e.key === "c" || e.key === "C") &&
          termRef.current?.hasSelection()
        ) {
          return false;
        }
        // Paste MUST bypass xterm's key processing entirely (return false):
        // xterm maps plain Ctrl+V to the control byte \x16 and CANCELS the
        // keydown (Keyboard.ts keyCode 86 → _keyDown cancel), so the browser
        // paste never fires. That silently ate the primary paste of
        // STT/dictation tools (Wispr Flow injects Ctrl+V; its eventual
        // Shift+Insert-style fallback pasted only AFTER the tool had restored
        // the previous clipboard — delivering the OLD clipboard, the
        // 2026-07-22/23 bug). Returning false skips xterm's handling and no
        // cancel happens, so Ctrl+V / Ctrl+Shift+V / Cmd+V all become the
        // browser's native immediate paste, which xterm's own paste handler
        // forwards to the PTY. Cost: a literal ^V can no longer be typed —
        // same trade-off as VS Code's integrated terminal on Windows.
        if (e.key === "v" || e.key === "V") return false;
        // Browser-reserved combos (Ctrl/Cmd-W/T/N): in a normal tab the browser
        // acts no matter what we do — return FALSE so xterm doesn't ALSO
        // transmit the sequence before the tab closes. Under an active focus-
        // mode keyboard lock they reach the page like any other combo and flow
        // to the TUI below.
        if (isBrowserReserved(e, keyboardLockedRef.current)) return false;
        // Ctrl combos (Ctrl-A, -E, -K, -., …): swallow the page default so the
        // control byte reaches the TUI.
        if (e.ctrlKey) {
          e.preventDefault();
          e.stopPropagation();
          return true;
        }
        // Cmd combos on macOS: xterm does NOT map Meta to terminal Ctrl, so
        // claiming these would break native browser behavior (Cmd-A select-all
        // etc.) without ever delivering a ^X to the TUI. Leave them alone.
        return true;
      });

      try {
        fit.fit();
      } catch {
        /* container not laid out yet — the ResizeObserver will fit shortly */
      }

      // A remote device is a read-only viewer until control is granted, so make
      // the terminal visually read-only up front (keystrokes are ALSO dropped
      // server-side; this is the client-side half + honest affordance).
      if (isRemote) term.options.disableStdin = true;

      const sendResize = () => {
        if (!ws || ws.readyState !== WebSocket.OPEN || !term) return;
        ws.send(
          JSON.stringify({ t: "resize", rows: term.rows, cols: term.cols }),
        );
      };

      // scheduleReconnect arms the next attempt with exponential backoff +
      // jitter (~1s → 15s cap), retrying for as long as the tab is open. The
      // jitter keeps a grid of terminals from reconnecting in lockstep after a
      // daemon restart. Mirrors the disposed-guard shape of useTerminalStatuses.
      const scheduleReconnect = () => {
        if (disposed || ptyExited || sessionGone || reconnectTimer) return;
        attempt += 1;
        const backoff = Math.min(15000, 1000 * 2 ** (attempt - 1));
        const delay = Math.round(backoff * (0.7 + Math.random() * 0.6));
        setStatus((s) => (s === "exited" || s === "error" ? s : "reconnecting"));
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          connect();
        }, delay);
      };

      const connect = () => {
        if (disposed || ptyExited || sessionGone) return;
        if (reconnectTimer) {
          clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
        // Single-socket invariant: whoever calls connect() supersedes any
        // existing socket, so close it rather than orphaning it (its handlers
        // already no-op via the ws !== sock guard, but the connection itself
        // would otherwise leak).
        if (ws && ws.readyState !== WebSocket.CLOSED) {
          const stale = ws;
          ws = null; // suppress the stale socket's onclose retry
          try {
            stale.close();
          } catch {
            /* ignore */
          }
        }
        const proto = window.location.protocol === "https:" ? "wss" : "ws";
        const sock = new WebSocket(
          `${proto}://${window.location.host}/ws/launch/${token}`,
        );
        sock.binaryType = "arraybuffer";
        ws = sock;
        wsRef.current = sock;
        // Per-SOCKET activity, not per-mount: the 1008 "session not found"
        // discrimination below has to hold for a reconnect attempt too, and a
        // reconnect to a live session always replays the output ring.
        sawActivityRef.current = false;
        // Every handler below guards `ws !== sock` so a superseded socket's late
        // event can never mutate state that belongs to the current one.
        wireSocket(sock, scheduleReconnect);
      };

      // reconnectNow is the bypass the visibility/pageshow handler calls: drop
      // any pending backoff and reconnect on the spot, but only when the socket
      // is genuinely not usable (a still-OPEN or in-flight CONNECTING socket is
      // left alone).
      reconnectNow = () => {
        if (disposed || ptyExited || sessionGone) return;
        if (
          ws &&
          (ws.readyState === WebSocket.OPEN ||
            ws.readyState === WebSocket.CONNECTING)
        ) {
          return;
        }
        // Backoff-bypass throttle. Returning to the tab resets `attempt`, which
        // is right for the human flow (one return, one immediate retry) but
        // means repeated visibility flips against a DOWN server could each buy
        // an immediate connect and hold the backoff at zero. The OPEN/CONNECTING
        // guard above already makes that self-limiting (a flip during an
        // in-flight attempt is a no-op), so this is belt-and-braces: at most one
        // bypass per second, and a flip inside that window falls back to the
        // normal exponential schedule rather than doing nothing.
        const nowMs = Date.now();
        if (nowMs - lastImmediateReconnect < IMMEDIATE_RECONNECT_MIN_MS) {
          scheduleReconnect();
          return;
        }
        lastImmediateReconnect = nowMs;
        if (reconnectTimer) {
          clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
        attempt = 0; // a deliberate return to the tab is not a failure streak
        connect();
      };

      function wireSocket(sock: WebSocket, onDrop: () => void) {
        sock.onopen = () => {
          if (disposed || ws !== sock) return;
          attempt = 0;
          setStatus("open");
          setErrMsg(null);
          // A read-only remote viewer must NEVER fit()/resize the PTY — only a
          // writer tracks the container via fit() (Change 2b). The viewer's
          // display geometry instead follows the writer's own dims once the
          // pty_size frame arrives (applyViewerScale, below).
          if (!(isRemote && !canWriteRef.current)) {
            try {
              fit?.fit();
            } catch {
              /* ignore */
            }
            sendResize();
          }
          // Initial size frame: a read-only viewer scales to fit rather than
          // riding the fit() geometry (Change 2b). The writer geometry may not
          // be known yet — the pty_size handler below re-triggers this once it
          // arrives.
          applyViewerScale();
          if (expandedRef.current) term?.focus();
          // Standing-access auto-acquire (§B): on a remote device with a stored
          // standing secret, present it ONCE now (confirm empty — the server
          // routes it by its `standing.` prefix). This is the whole point of
          // standing access: control is re-acquired on every fresh socket with no
          // owner round-trip. Exactly one attempt per open — never a retry loop;
          // a rejection (revoked/rotated) is handled in onmessage below.
          //
          // This lives in onopen, which is wired per-SOCKET, so it re-runs on
          // every RECONNECT as well as the first mount — that is what regains
          // write control after a background/foreground round-trip with no user
          // action at all.
          if (isRemote && sock.readyState === WebSocket.OPEN) {
            const stored = getStoredStandingSecret();
            if (stored) {
              standingAttemptRef.current = true;
              sock.send(
                JSON.stringify({ t: "acquire-writer", cap: stored, confirm: "" }),
              );
              setControl("requesting");
            }
          }
        };

        sock.onmessage = (ev: MessageEvent) => {
          if (!term || ws !== sock) return;
          if (typeof ev.data === "string") {
            // Text frame = control message.
            try {
              const m = JSON.parse(ev.data) as {
                t?: string;
                code?: number;
                rows?: number;
                cols?: number;
                initial_rows?: number;
                initial_cols?: number;
                gen?: number;
                by?: "local" | "remote";
                expiry?: boolean;
                reason?: TerminalControlDenialReason;
                policy_stop?: PolicyStopInfo;
              };
              if (m.t === "exit") {
                // The AUTHORITATIVE "really exited" signal — the only thing that
                // proves the child is gone. Latch it so the close that follows is
                // not mistaken for a transport drop and retried forever.
                sawActivityRef.current = true;
                ptyExited = true;
                setExitCode(typeof m.code === "number" ? m.code : 0);
                setPolicyStop(m.policy_stop);
                setStatus("exited");
              } else if (m.t === "pty_size") {
                // Feature A / Feature 2: the server's geometry frame (sent on open
                // and re-sent on each control transition). It carries BOTH the
                // writer's CURRENT dims (rows/cols) and the LAUNCH dims
                // (initial_rows/initial_cols) — each may be 0/unknown.
                const ir = m.initial_rows;
                const ic = m.initial_cols;
                if (typeof ir === "number" && typeof ic === "number" && ir > 0 && ic > 0) {
                  const dims = { rows: ir, cols: ic };
                  initialDimsRef.current = dims;
                  setInitialDims(dims);
                  // Persisted "original" from a prior mount: apply now that the
                  // geometry is known (open-time fit already ran in fit mode).
                  if (sizeModeRef.current === "original" && termRef.current) {
                    try {
                      termRef.current.resize(ic, ir);
                    } catch {
                      /* ignore */
                    }
                    // A read-only viewer must never push a resize to the PTY
                    // (that's a writer-only operation) — but it still resizes
                    // its own display below, via applyViewerScale.
                    if (!(isRemote && !canWriteRef.current)) {
                      sendResizeNow(ir, ic);
                    }
                  }
                }
                // Track the writer's CURRENT geometry for the viewer downscale,
                // preferring the live rows/cols over the launch dims so a writer
                // that resized after launch is reflected (not the stale launch
                // size). Falls back to initial when current is absent/zero.
                const cr = typeof m.rows === "number" && m.rows > 0 ? m.rows : ir;
                const cc = typeof m.cols === "number" && m.cols > 0 ? m.cols : ic;
                if (
                  typeof cr === "number" &&
                  typeof cc === "number" &&
                  cr > 0 &&
                  cc > 0
                ) {
                  writerGeomRef.current = { rows: cr, cols: cc };
                }
                // The writer's geometry is now known — recompute the viewer
                // downscale (Change 2b). onopen ran before this frame arrived, so
                // this is the actual trigger that renders a viewer at the writer's
                // size.
                applyViewerScale();
              } else if (m.t === "control_granted") {
                const grantGen =
                  typeof m.gen === "number" &&
                  Number.isSafeInteger(m.gen) &&
                  m.gen > 0
                    ? m.gen
                    : 0;
                if (grantGen > 0) {
                  latestGrantedGenRef.current = Math.max(
                    latestGrantedGenRef.current,
                    grantGen,
                  );
                  hasLiveGrantRef.current = true;
                }
                standingAttemptRef.current = false;
                setRevokedBy(null);
                // Regaining control after a prior revoke → surface it in this
                // seat (§6 decision 5). A first-ever acquire stays silent.
                if (wasRevokedRef.current) {
                  wasRevokedRef.current = false;
                  pushToast("You have terminal control", "success");
                }
                // Remote seats become the explicit "writer"; a local loopback seat
                // returns to its always-on "local" writer state (Feature B).
                setControl(isRemote ? "writer" : "local");
                setShowAcquire(false);
                setAcqErr(null);
                // Re-assert THIS seat's geometry now that its resizes are
                // unfenced: while demoted, every ResizeObserver resize was
                // dropped server-side, so the PTY still carries the other seat's
                // dims (e.g. the native terminal's after a reclaim). Original
                // mode re-pins the launch dims; fit mode re-fits the container.
                if (sizeModeRef.current === "original" && initialDimsRef.current) {
                  const d = initialDimsRef.current;
                  try {
                    term.resize(d.cols, d.rows);
                  } catch {
                    /* ignore */
                  }
                  sendResizeNow(d.rows, d.cols);
                } else {
                  try {
                    fit?.fit();
                  } catch {
                    /* ignore */
                  }
                  sendResize();
                }
              } else if (m.t === "control_denied") {
                hasLiveGrantRef.current = false;
                const usedStanding = standingAttemptRef.current;
                standingAttemptRef.current = false;
                if (usedStanding && isPermanentAuthDenial(m.reason)) {
                  // The stored/entered standing secret is permanently dead:
                  // either it was JUDGED and rejected ("auth" — revoked or
                  // rotated), or the server holds no standing secret at rest at
                  // all ("auth_revoked" — revoked and never re-provisioned, so
                  // nothing can match it again). Clear it and fall back to the
                  // one-time flow with an honest message. We do NOT retry (one
                  // attempt per socket open / per expiry demote).
                  //
                  // Destroying the user's saved secret is irreversible for them
                  // (the owner must mint a new one), so it is gated on the two
                  // reasons that PROVE the credential can never work again.
                  // Every transient refusal — standing access momentarily
                  // disabled with the secret still at rest, a rate-limited
                  // attempt, an acquire that raced an admin transition, a
                  // server too old to distinguish them — reports something else
                  // and leaves the secret in place.
                  forgetStandingSecret();
                  setStandingStored(false);
                }
                setControl("denied");
                setAcqErr(terminalControlDenialMessage(m.reason, usedStanding));
              } else if (m.t === "control_revoked") {
                const revokeGen =
                  typeof m.gen === "number" &&
                  Number.isSafeInteger(m.gen) &&
                  m.gen > 0
                    ? m.gen
                    : 0;
                // Equality is the revoke of the currently granted lease and must
                // demote. Only a STRICTLY older generation is stale; missing gen
                // keeps the legacy demotion behaviour.
                if (
                  hasLiveGrantRef.current &&
                  revokeGen > 0 &&
                  revokeGen < latestGrantedGenRef.current
                ) {
                  return;
                }
                hasLiveGrantRef.current = false;
                // EXPIRY-DEMOTE (server sets expiry:true): the writer lease
                // merely aged out — idle lifetime or hard cap — and the server
                // deliberately kept the socket open instead of closing it. The
                // device is not in doubt, so a seat holding a standing secret
                // re-presents it here and carries on. This is the ONLY place
                // that can do it: the normal auto-present lives in
                // `sock.onopen`, which never re-fires while the socket stays
                // up, so before this the promised "silently re-acquire" meant
                // "tap the button again".
                //
                // Never on a takeover or a trust-withdrawing revoke (expiry is
                // absent there): the owner or another device just took control,
                // and auto-re-acquiring would fight them.
                if (isRemote && m.expiry === true) {
                  const stored = getStoredStandingSecret();
                  const nowMs = Date.now();
                  if (
                    stored &&
                    sock.readyState === WebSocket.OPEN &&
                    nowMs - lastStandingReacquireRef.current >
                      STANDING_REACQUIRE_COOLDOWN_MS
                  ) {
                    lastStandingReacquireRef.current = nowMs;
                    standingAttemptRef.current = true;
                    sock.send(
                      JSON.stringify({
                        t: "acquire-writer",
                        cap: stored,
                        confirm: "",
                      }),
                    );
                    // No toast and no wasRevokedRef arming: an aged-out lease
                    // answered by a stored secret is invisible maintenance, not
                    // an event the user needs told about. A denial still
                    // surfaces through the normal control_denied path.
                    setControl("requesting");
                    return;
                  }
                }
                // Taken over by another viewer, the owner/admin, OR — new daemon
                // feature — the NATIVE terminal reclaiming its own session (fires
                // for LOCAL seats too now). Input stops; toast it in this seat (§6
                // decision 5) and arm the regain toast for the next grant. A local
                // seat can take it back with a click/keystroke (Feature B).
                wasRevokedRef.current = true;
                const by = m.by === "local" || m.by === "remote" ? m.by : null;
                setRevokedBy(by);
                pushToast(
                  m.expiry === true
                    ? // An age-out, with no standing secret to answer it: say
                      // so honestly rather than implying somebody took control.
                      "Terminal control timed out - ask for control again"
                    : isRemote
                      ? by === "local"
                        ? "The owner took terminal control"
                        : by === "remote"
                          ? "Another remote device took terminal control"
                          : "Terminal control ended"
                      : by === "remote"
                        ? "A remote device took terminal control"
                        : "The native terminal reclaimed control",
                  "warn",
                );
                setControl("revoked");
              }
            } catch {
              /* ignore malformed control frame */
            }
            return;
          }
          sawActivityRef.current = true;
          term.write(new Uint8Array(ev.data as ArrayBuffer));
        };

        // No onerror handler by design. A websocket `error` is ALWAYS followed
        // by a `close`, and onclose below owns the whole retry-vs-give-up
        // decision; painting "error" here would flip the tile to a tombstone
        // for the one frame before the reconnect is armed. (Until 2026-07-25
        // this was an empty guard-and-return handler — dead code that read as
        // if it did something.)
        sock.onclose = (ev: CloseEvent) => {
          if (disposed || ws !== sock) return;
          wsRef.current = null;
          // A policy-violation close (1008) with NO activity on THIS socket means
          // the server refused the join outright — the handle was already gone
          // (the child exited in the fetch→click race) or the session was never
          // joinable. Surface that honestly instead of a bare "exited" terminal
          // the user might read as "my agent just quit" (P2-4). Copy is
          // workflow-NEUTRAL (F7): LaunchTerminal is shared by Jump-in, fresh,
          // handoff, setup, and resume, so it must not claim every failed launch
          // was "Jump in".
          //
          // This is ALSO the "is the PTY really gone?" discriminator for a
          // RECONNECT attempt: a reconnect to a live session always replays the
          // output ring, so a 1008 that delivered nothing is the server telling us
          // the handle no longer exists. Only then do we stop retrying and show
          // the dead state.
          if (ev.code === 1008 && !sawActivityRef.current) {
            sessionGone = true;
            setStatus((s) => (s === "exited" ? s : "error"));
            setErrMsg("Session ended before the terminal could connect - it was no longer running.");
            return;
          }
          // An authoritative exit frame already arrived — the child is gone.
          if (ptyExited) {
            setStatus("exited");
            return;
          }
          // Everything else is a TRANSPORT drop. The PTY is server-side and
          // survives it, so hold the seat and reconnect. A remote seat drops back
          // to read-only meanwhile (the server released its writer lease with the
          // socket); the standing-secret auto-present in onopen re-acquires it on
          // the next successful connect with no user action.
          if (isRemote) setControl("viewer");
          onDrop();
        };
      }

      // Keystrokes → binary frames. Gated on canWriteRef so a read-only remote
      // viewer never even transmits input (it would be dropped server-side by
      // §4.β regardless — this is the honest client-side half).
      term.onData((data) => {
        if (!canWriteRef.current) {
          // Dropped silently. NOTE: take-back intent is deliberately NOT
          // inferred here — onData also fires for xterm's auto-generated
          // protocol replies to TUI queries (CPR/DA), which carry no human
          // intent. The take-back triggers are real DOM gestures only: the
          // custom key handler's keydown, the terminal-body mousedown, and the
          // warn-bar click.
          return;
        }
        if (ws && ws.readyState === WebSocket.OPEN) {
          // D3: apply any armed on-screen modifier. Identity when none is
          // armed, so this is a no-op for every desktop keystroke.
          ws.send(new TextEncoder().encode(consumeSoftMods(data)));
        }
      });

      // Refit + notify the PTY on any container size change — UNLESS the size
      // mode is pinned to "original" (Feature A), in which case every RO tick is
      // inert so the fixed geometry never gets refit out from under the TUI.
      ro = new ResizeObserver(() => {
        // A read-only remote viewer must NOT fit()/resize the PTY (it would
        // reflow the writer's TUI mid-stream). Recompute the presentation-only
        // downscale instead (Change 2b) — checked BEFORE the "original"-mode
        // early return, because a viewer never rides the fixed-geometry fit
        // path, so it must still re-scale on rotate/resize even while a stale
        // "original" size mode is pinned from a prior writer seat.
        if (isRemote && !canWriteRef.current) {
          applyViewerScale();
          return;
        }
        // Writer, size mode pinned to "original" (Feature A): every RO tick is
        // inert so the fixed geometry never gets refit out from under the TUI.
        if (sizeModeRef.current === "original") return;
        try {
          fit?.fit();
        } catch {
          /* ignore */
        }
        sendResize();
      });
      ro.observe(hostRef.current);

      // Open the first socket only once every handler + observer is wired, so a
      // fast local connect can't deliver bytes before the terminal is ready.
      connect();
    })().catch((e) => {
      if (!disposed) {
        setErrMsg(e instanceof Error ? e.message : String(e));
        setStatus("error");
      }
    });

    return () => {
      // Deliberate teardown (unmount / token change): set disposed FIRST so the
      // close this triggers is not mistaken for a transport drop and retried.
      disposed = true;
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("pageshow", onVisible);
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      ro?.disconnect();
      for (const undo of hostCleanup) {
        try {
          undo();
        } catch {
          /* the host element may already be gone */
        }
      }
      hostCleanup.length = 0;
      try {
        ws?.close();
      } catch {
        /* ignore */
      }
      term?.dispose();
      termRef.current = null;
      wsRef.current = null;
      fitRef.current = null;
    };
  }, [token, isRemote]);

  // ── D2: touch scrolling that survives TUI mouse tracking ───────────────────
  //
  // THE DEFECT. xterm.js registers the ONLY touch-scroll path behind a gate:
  //
  //   addDisposableDomListener(el, "touchstart", e => {
  //     if (!this.coreMouseService.areMouseEventsActive) { … }
  //   })
  //   addDisposableDomListener(el, "touchmove",  e => {
  //     if (!this.coreMouseService.areMouseEventsActive) { … }
  //   }, {passive:false})
  //
  // The moment a TUI enables mouse reporting (`ESC[?1000h ESC[?1002h
  // ESC[?1006h` — which Claude Code, codex and any full-screen app do on
  // startup) that gate closes and touch scrolling is simply gone. And there is
  // no fallback: `.xterm-viewport` and `.xterm-screen` are SIBLINGS, never
  // ancestor/descendant, so native scroll chaining from the touched element can
  // never reach the scrollable viewport either. Measured at 393x852 with an
  // identical 150px drag: mouse mode off -> scrollTop delta -30; mouse mode on
  // -> delta 0; off again -> -30. This is presentation-independent, which is
  // why full-viewport/focus-mode layout work does not fix it.
  //
  // THE FIX. Own the gesture ourselves, in the CAPTURE phase on the host (an
  // ancestor of xterm's own listener target), and drive `term.scrollLines()`
  // directly — a public API with no coreMouseService dependency.
  //
  // Claiming is deliberately conservative, because a TUI that asked for
  // touch-as-mouse must still receive taps: we claim only when the gesture is
  // predominantly VERTICAL *and* the buffer is genuinely scrollable (normal
  // buffer with scrollback above the viewport). A tap never moves, so it is
  // never claimed and falls through to xterm's mouse encoding unchanged. When
  // we DO claim we stopPropagation, so xterm's own handler cannot double-scroll
  // in the mouse-mode-off case.
  //
  // Gated on the touch capability query: a desktop terminal registers nothing.
  useEffect(() => {
    if (!isTouch) return;
    const host = hostRef.current;
    if (!host) return;

    // Minimum travel before the vertical/horizontal verdict is taken. Small
    // enough that at most a sub-row amount of movement reaches xterm first.
    const DECIDE_PX = 4;
    // Momentum cutoffs (px/ms and friction per frame at ~60fps).
    const FLING_MIN_V = 0.25;
    const FLING_FRICTION = 0.94;
    const FLING_STOP_V = 0.02;

    let startX = 0;
    let startY = 0;
    let lastX = 0;
    let lastY = 0;
    let lastT = 0;
    let velocity = 0; // px/ms, positive = finger moving down
    let tracking = false;
    // The verdict, taken once per gesture at DECIDE_PX of travel:
    //   null      undecided
    //   "scroll"  ours — drive term.scrollLines() and swallow the event
    //   "swallow" not ours to act on, but the BROWSER must not have it either
    //             (D14: an unclaimed horizontal swipe became back-navigation)
    //   "pass"    genuinely not ours — let it through untouched
    let verdict: "scroll" | "wheel" | "swallow" | "pass" | null = null;
    let residual = 0; // sub-row pixels carried between moves
    let flingRaf = 0;

    // D14 — SWIPE-LEFT USED TO DESTROY THE PAGE (operator-reported, phone,
    // 2026-07-27). The rule below declined every horizontal gesture with the
    // comment "horizontal swipe / no scrollback: not ours". Declining means not
    // calling preventDefault, so the gesture reached the browser — which treats
    // a horizontal drag near the edge as BACK-NAVIGATION and unloaded the whole
    // dashboard, live PTY and all. Not-ours must not mean not-handled.
    //
    // Three layers, because no single one covers every engine:
    //   1. `touch-action: pan-y` on the header + key bar — the browser never
    //      starts a horizontal gesture that begins there at all.
    //   2. `overscroll-behavior-x: contain` on the panel, the backdrop and (via
    //      LaunchDock, while the mobile panel is up) the document element —
    //      this is what governs Chrome's overscroll-to-navigate.
    //   3. THIS: an explicit preventDefault on the first horizontal touchmove
    //      over the terminal body, which is where the operator actually swiped.
    //      The body cannot use layer 1 because `overflow-x-auto` is load-bearing
    //      there (original-size mode is genuinely wider than a phone), so the
    //      swallow is conditional: when the host really can scroll sideways the
    //      gesture is left to it and layer 2 stops the chain at the end.
    //
    // NOT VERIFIED ON REAL HARDWARE: iOS Safari's interactive-pop starts as a
    // system gesture when the touch begins within ~20px of the left edge, and
    // no amount of preventDefault reclaims it. Layers 1-3 are what a page can
    // do; the residual iOS edge case is documented, not fixed.
    const hostScrollsX = () => host.scrollWidth > host.clientWidth + 1;

    const stopFling = () => {
      if (flingRaf) cancelAnimationFrame(flingRaf);
      flingRaf = 0;
    };

    // rowPx derives the pixel height of one terminal row from the LAID-OUT
    // grid, so it tracks font-size/zoom without reaching into xterm internals.
    const rowPx = (term: import("@xterm/xterm").Terminal): number => {
      const screen = host.querySelector<HTMLElement>(".xterm-screen");
      if (screen && term.rows > 0) {
        const h = screen.clientHeight / term.rows;
        if (h > 1) return h;
      }
      return 17;
    };

    // scrollable reports whether there is anything above the viewport to scroll
    // back to. The ALTERNATE buffer (full-screen TUI) has no scrollback at all,
    // so a drag there is left to the application.
    const scrollable = (term: import("@xterm/xterm").Terminal): boolean => {
      const b = term.buffer.active;
      return b.type === "normal" && b.baseY > 0;
    };

    // ── D17: the ALTERNATE-buffer scroll path (touch → wheel) ────────────────
    //
    // A full-screen TUI switches to the alternate buffer, which by definition
    // has NO scrollback — so `scrollable()` is false for every drag and the
    // gesture used to be handed to the application untouched. That was correct
    // as far as it went and still left the user stuck, because of a mismatch
    // measured against a live `claude` 2.1.220 PTY:
    //
    //   on entering its TUI it sets ?1049h (alternate buffer) together with
    //   ?1000h ?1002h ?1003h ?1006h (click, drag, ANY-motion, SGR), and it
    //   scrolls its own view on WHEEL events. Writing SGR wheel into its PTY
    //   redraws; writing a button-0 press/motion/release makes it react
    //   (3022 bytes) but never scrolls — it reads a drag as a drag.
    //
    // A desktop mouse has a wheel, so this works there and the defect is
    // mobile-only. A finger has no wheel, and nothing was synthesizing one.
    //
    // So: convert vertical finger travel into wheel events. We dispatch a
    // synthetic WheelEvent and let XTERM do the encoding rather than writing
    // SGR ourselves — xterm already knows which mouse encoding is active
    // (1006 / 1015 / default) and where the cell boundaries are, and it routes
    // the bytes through the same onData path every other input takes, so the
    // writer-lease gate applies without a second code path to keep in sync.
    const alternateBuffer = (term: import("@xterm/xterm").Terminal): boolean =>
      term.buffer.active.type === "alternate";

    // xterm binds its wheel handling on the .xterm root; dispatching on the
    // grid with bubbles:true reaches it from wherever the finger actually is.
    const wheelTarget = (): HTMLElement | null =>
      host.querySelector<HTMLElement>(".xterm-screen") ??
      host.querySelector<HTMLElement>(".xterm");

    let wheelResidual = 0; // sub-row pixels carried between moves

    // wheelByPixels converts accumulated finger travel into whole-row wheel
    // deltas. Finger DOWN (positive dy) means "show me earlier output", which
    // is wheel UP, which is a NEGATIVE deltaY — the same sign convention a
    // desktop wheel produces for the same intent.
    const wheelByPixels = (
      term: import("@xterm/xterm").Terminal,
      dy: number,
      x: number,
      y: number,
    ) => {
      const el = wheelTarget();
      if (!el) return;
      wheelResidual += dy;
      const px = rowPx(term);
      const rows = Math.trunc(wheelResidual / px);
      if (rows === 0) return;
      wheelResidual -= rows * px;
      // deltaMode 0 = pixels. Handing xterm a delta that is a whole number of
      // row heights lets its own px→lines conversion decide the line count,
      // so this tracks font-size and zoom without a second copy of that math.
      el.dispatchEvent(
        new WheelEvent("wheel", {
          deltaY: -rows * px,
          deltaMode: 0,
          clientX: x,
          clientY: y,
          bubbles: true,
          cancelable: true,
        }),
      );
    };

    // scrollByPixels converts accumulated finger travel into whole rows and
    // moves the viewport. Finger down (positive dy) scrolls BACK, so the
    // content follows the finger — the platform convention on every phone.
    const scrollByPixels = (term: import("@xterm/xterm").Terminal, dy: number) => {
      residual += dy;
      const px = rowPx(term);
      const rows = Math.trunc(residual / px);
      if (rows === 0) return;
      residual -= rows * px;
      term.scrollLines(-rows);
    };

    const onTouchStart = (e: TouchEvent) => {
      stopFling();
      tracking = false;
      verdict = null;
      residual = 0;
      wheelResidual = 0;
      velocity = 0;
      if (e.touches.length !== 1) return; // pinch/zoom is the browser's
      const t = e.touches[0];
      startX = t.clientX;
      startY = t.clientY;
      lastX = t.clientX;
      lastY = t.clientY;
      lastT = e.timeStamp;
      tracking = true;
    };

    const onTouchMove = (e: TouchEvent) => {
      const term = termRef.current;
      if (!tracking || !term || e.touches.length !== 1) return;
      const t = e.touches[0];
      const totalX = t.clientX - startX;
      const totalY = t.clientY - startY;

      if (verdict === null) {
        if (Math.abs(totalX) < DECIDE_PX && Math.abs(totalY) < DECIDE_PX) return;
        if (Math.abs(totalY) > Math.abs(totalX)) {
          // Vertical. Ours when there is scrollback to reach (normal buffer).
          if (scrollable(term)) {
            verdict = "scroll";
          } else if (alternateBuffer(term) && canWriteRef.current) {
            // A full-screen TUI owns its own scroll and expects WHEEL events
            // (D17). Gated on canWrite so a read-only remote viewer still
            // sends zero frames — its story is the presentation-only downscale
            // (Change 2b), not synthesized input.
            verdict = "wheel";
          } else {
            verdict = "pass";
          }
        } else {
          // Horizontal (D14). Never ours to act on — but only "pass" when the
          // host can genuinely scroll sideways, because otherwise the browser
          // takes it as back-navigation and the dashboard unloads.
          verdict = hostScrollsX() ? "pass" : "swallow";
        }
      }
      if (verdict === "swallow") {
        // Cancel the browser's default gesture (overscroll-to-navigate,
        // rubber-band) without touching xterm: no stopPropagation, so a TUI in
        // mouse-reporting mode still sees the move it asked for.
        if (e.cancelable) e.preventDefault();
        return;
      }
      if (verdict !== "scroll" && verdict !== "wheel") return;

      // Ours: keep the page from rubber-banding and keep xterm's own (possibly
      // ungated) handler from scrolling the same gesture a second time. For
      // the wheel path stopPropagation matters for a second reason — it stops
      // xterm reporting the same gesture to the TUI as a mouse DRAG, which is
      // what a full-screen app would otherwise read as a selection.
      e.preventDefault();
      e.stopPropagation();

      const dy = t.clientY - lastY;
      const dt = e.timeStamp - lastT;
      if (dt > 0) {
        // Light exponential smoothing so one jittery sample can't fling.
        velocity = 0.7 * (dy / dt) + 0.3 * velocity;
      }
      lastX = t.clientX;
      lastY = t.clientY;
      lastT = e.timeStamp;
      if (verdict === "wheel") wheelByPixels(term, dy, t.clientX, t.clientY);
      else scrollByPixels(term, dy);
    };

    const onTouchEnd = (e: TouchEvent) => {
      const term = termRef.current;
      const claimed = verdict === "scroll" || verdict === "wheel";
      const wasWheel = verdict === "wheel";
      const endX = lastX;
      const endY = lastY;
      tracking = false;
      verdict = null;
      if (!claimed || !term) return;
      e.stopPropagation();
      // Momentum. xterm's own handler quantises to whole rows with no inertia
      // (a 150px drag moved 30px), which is why scrolling felt broken even when
      // it worked at all. Decay the last measured velocity over rAF frames.
      if (Math.abs(velocity) < FLING_MIN_V) return;
      let v = velocity;
      const step = () => {
        v *= FLING_FRICTION;
        if (Math.abs(v) < FLING_STOP_V) {
          flingRaf = 0;
          return;
        }
        // ~16ms worth of travel per frame.
        if (wasWheel) wheelByPixels(term, v * 16, endX, endY);
        else scrollByPixels(term, v * 16);
        flingRaf = requestAnimationFrame(step);
      };
      flingRaf = requestAnimationFrame(step);
    };

    // Capture phase: xterm's listeners live on a DESCENDANT of the host, so
    // capturing here lets us decide before it sees the event. passive:false is
    // required — a passive listener may not preventDefault.
    const opts: AddEventListenerOptions = { capture: true, passive: false };
    host.addEventListener("touchstart", onTouchStart, opts);
    host.addEventListener("touchmove", onTouchMove, opts);
    host.addEventListener("touchend", onTouchEnd, opts);
    host.addEventListener("touchcancel", onTouchEnd, opts);
    return () => {
      stopFling();
      host.removeEventListener("touchstart", onTouchStart, opts);
      host.removeEventListener("touchmove", onTouchMove, opts);
      host.removeEventListener("touchend", onTouchEnd, opts);
      host.removeEventListener("touchcancel", onTouchEnd, opts);
    };
  }, [isTouch]);

  // Keep the xterm read-only state in sync with control: enable stdin + focus
  // when this client holds the writer, disable it otherwise. Local sessions are
  // always writers, so this only ever restricts a remote viewer.
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    // Remote viewers are hard read-only (disableStdin). A LOCAL seat keeps stdin
    // ENABLED even when its lease was reclaimed, so a keystroke can trigger
    // take-back (Feature B) — the actual send is still gated by canWriteRef, so
    // no bytes (nor xterm's TUI-query auto-replies) reach the PTY meanwhile.
    term.options.disableStdin = isRemote ? !canWrite : false;
    if (canWrite && expanded) term.focus();
  }, [canWrite, expanded, isRemote]);

  // Recompute the read-only-viewer downscale (Change 2b) whenever control or
  // visibility flips: a grant/revoke changes viewer↔writer, and expanding
  // relays out the host. A frame later so xterm has settled the new geometry.
  // For a writer this call is a no-op that clears any leftover transform.
  useEffect(() => {
    const id = requestAnimationFrame(() => applyViewerScaleRef.current());
    return () => cancelAnimationFrame(id);
  }, [canWrite, expanded, isRemote]);

  // acquireControl sends the §4.δ acquire-writer frame with the owner-conveyed
  // capability + confirm over the ALREADY-open, cookie-authed, Origin-checked
  // websocket — the only channel that carries them (never a URL/query/header).
  // The inputs are cleared immediately so the secrets do not linger in state.
  function acquireControl() {
    const ws = wsRef.current;
    const cap = capInput.trim();
    const confirm = confirmInput.trim();
    if (!cap || !confirm) {
      setAcqErr("Paste both the capability and the confirm code the owner gave you.");
      return;
    }
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setAcqErr("Not connected - reopen the terminal and try again.");
      return;
    }
    ws.send(JSON.stringify({ t: "acquire-writer", cap, confirm }));
    setControl("requesting");
    setAcqErr(null);
    setCapInput("");
    setConfirmInput("");
  }

  // acquireStanding sends the acquire-writer frame with a STANDING secret in the
  // cap field (confirm empty — the server routes it by its `standing.` prefix).
  // If "Remember on this device" is checked, the secret is persisted to
  // localStorage so control survives future refreshes (see the risk copy). The
  // input is cleared immediately either way. standingAttemptRef is set so a
  // genuine credential rejection can clear the (possibly just-stored) secret;
  // non-auth denials leave it intact.
  function acquireStanding() {
    const ws = wsRef.current;
    const secret = standingInput.trim();
    if (!secret) {
      setAcqErr("Paste the standing secret the owner gave you.");
      return;
    }
    if (!secret.startsWith("standing.")) {
      setAcqErr('That is not a standing secret - it should start with "standing.". Use the capability + confirm fields above for a one-time approval.');
      return;
    }
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setAcqErr("Not connected - reopen the terminal and try again.");
      return;
    }
    if (rememberStanding) {
      storeStandingSecret(secret);
      setStandingStored(true);
    }
    standingAttemptRef.current = true;
    ws.send(JSON.stringify({ t: "acquire-writer", cap: secret, confirm: "" }));
    setControl("requesting");
    setAcqErr(null);
    setStandingInput("");
  }

  // forgetStandingDevice removes the browser-stored standing secret so this
  // device stops auto-acquiring control on refresh. It does not affect the live
  // lease (still held until the socket closes) — it only stops future auto-use.
  function forgetStandingDevice() {
    forgetStandingSecret();
    setStandingStored(false);
  }

  // Grab focus when this session becomes the on-screen panel (launch, or
  // restore from the dock) so the user can type immediately without an extra
  // click.
  useEffect(() => {
    if (expanded) termRef.current?.focus();
  }, [expanded]);

  // Focus trap (defense-in-depth). While this terminal is the on-screen
  // (expanded) modal, an opaque full-screen backdrop covers the app, so the
  // ONLY legitimate focus targets are inside this panel (the xterm textarea,
  // Minimize, Stop — all under rootRef). If focus lands anywhere OUTSIDE the
  // panel it was stolen by a background re-render (the root cause was fixed in
  // SlideOver, but any future stealer is caught here), so redirect it back.
  // Document-level `focusin` fires whatever the stealer's relatedTarget is —
  // the failure mode of the earlier relatedTarget-null-only watchdog.
  useEffect(() => {
    if (!expanded) return;
    const onFocusIn = (e: FocusEvent) => {
      const root = rootRef.current;
      const target = e.target as Node | null;
      if (!root || !target || root.contains(target)) return;
      // Focus landing inside a registered terminal-companion surface (a
      // floating project panel or its context menu) is legitimate coexistence,
      // not a stealer — leave it. Membership is tested against the provider's
      // set of EXACT registered root nodes (not a self-asserted selector any
      // element could spoof). The trap keeps redirecting every other outside
      // focus.
      if (companion?.contains(target)) return;
      termRef.current?.focus();
    };
    document.addEventListener("focusin", onFocusIn, true);
    return () => document.removeEventListener("focusin", onFocusIn, true);
  }, [expanded, companion]);

  // Register the paste-into-terminal callback while this seat is live AND
  // write-capable. A read-only viewer registers nothing, so a project panel
  // structurally hides its paste items. The callback re-checks canWrite at call
  // time so a mid-flight revoke can't leak bytes.
  useEffect(() => {
    if (!registerPaste) return;
    if (status !== "open" || !canWrite) {
      registerPaste(null);
      return;
    }
    registerPaste((text) => {
      // Route paste through xterm's OWN paste pipeline — IDENTICAL to a manual
      // Ctrl+V. term.paste triggers the same onData → ws.send path (so the
      // canWriteRef + ws-open gating in that handler still applies) AND wraps
      // the text in bracketed-paste markers (ESC[200~…ESC[201~) when the
      // running app enabled that mode — which is exactly what neutralizes shell
      // metacharacters in real shells. We deliberately do NOT hand-quote for a
      // guessed shell: that matches Ctrl+V semantics.
      //
      // Caveat (documented, intentional): cmd.exe has no bracketed paste, so on
      // a raw cmd.exe prompt a metachar path is literal-but-unquoted — the same
      // result a manual paste gives — and it never auto-executes because
      // control bytes (incl. newline) were already stripped in sanitizePastePath.
      // Gate on the LIVE status too, not just canWriteRef (P2-2): a stale
      // callback firing after an exit/error frame but before this effect's
      // cleanup must not paste into a dead seat.
      if (statusRef.current !== "open" || !canWriteRef.current) return;
      termRef.current?.paste(text);
    });
    return () => registerPaste(null);
  }, [status, canWrite, registerPaste]);

  // Bubble lifecycle status up to the dock (drives the pill state and the
  // beforeunload guard). Idempotent — safe to fire on every status change.
  useEffect(() => {
    onStatus?.(status);
  }, [status, onStatus]);

  // Bubble the policy-stop explanation up to the dock so a minimized pill
  // can surface the same reason as the expanded modal.
  useEffect(() => {
    onPolicyStop?.(policyStop);
  }, [policyStop, onPolicyStop]);

  // Closing kills the child process tree (ws teardown → server reap), so
  // confirm when it's still live. Minimize is the non-destructive exit.
  function requestClose() {
    // A reconnecting seat is still backed by a LIVE process (only the transport
    // dropped), so it must get the same destructive confirmation as an open one.
    if (
      (status === "open" || status === "reconnecting") &&
      !window.confirm(`Stop the running ${tool} session? This ends the process.`)
    ) {
      return;
    }
    onClose();
  }

  // ── D10: copy off a touch device ───────────────────────────────────────
  // xterm.css sets `.xterm { user-select: none }` and xterm's own selection is
  // mouse-drag based, so a long-press selects nothing and an error message
  // cannot be copied off a phone at all. This reads the buffer directly rather
  // than fighting xterm's selection layer (a `user-select` override would put
  // the browser's native selection in contention with xterm's own).
  //
  // Honest scope, hence the label: it copies the CURRENT SELECTION when there
  // is one, otherwise exactly the rows on screen — not the whole scrollback.
  async function copyVisible() {
    const term = termRef.current;
    if (!term) return;
    let text = term.getSelection();
    if (!text) {
      const buf = term.buffer.active;
      const lines: string[] = [];
      for (let i = 0; i < term.rows; i++) {
        const line = buf.getLine(buf.viewportY + i);
        // trimRight: the grid is space-padded to `cols`.
        lines.push(line ? line.translateToString(true) : "");
      }
      while (lines.length && lines[lines.length - 1] === "") lines.pop();
      text = lines.join("\n");
    }
    if (!text) {
      pushToast("Nothing on screen to copy", "info");
      return;
    }
    // Goes through the shared clipboard seam, which falls back to the legacy
    // execCommand path on a plain-http origin (where `navigator.clipboard` is
    // undefined outright, not merely rejecting) — the case that used to make
    // this button a dead control on a non-localhost, non-TLS dashboard.
    const res = await writeClipboard(text);
    if (res === "failed") {
      pushToast(clipboardFailureMessage(), "warn");
      return;
    }
    pushToast("Copied the visible terminal output", "success");
  }

  // ── Clipboard verbs (Task 10) ────────────────────────────────────────────
  // Assigned every render so the setup effect's closure always calls the
  // current implementation without widening its [token, isRemote] deps.

  copySelectionRef.current = async (text: string) => {
    const res = await writeClipboard(text);
    if (res === "failed") {
      pushToast(clipboardFailureMessage(), "warn");
      return;
    }
    pushToast("Copied the selection", "success");
  };

  selectionHelpRef.current = () =>
    keyPlatformRef.current === "mac"
      ? "Nothing selected - drag to select (hold ⌥ Option if the app is using the mouse)"
      : "Nothing selected - drag to select (hold Shift if the app is using the mouse)";

  /**
   * pasteFromClipboard is the right-click Paste verb. It reads the clipboard
   * programmatically and hands the text to xterm's OWN paste pipeline, so
   * bracketed-paste wrapping is applied exactly as it is for a manual Ctrl+V
   * (the shell therefore neutralises metacharacters the same way, and nothing
   * auto-executes).
   *
   * When the read is refused or unavailable — an insecure origin has no
   * `readText` at all, and even a secure one lets the user deny
   * `clipboard-read` — it does NOT fail silently: it names the working
   * alternative. Ctrl+V is not merely a nicer path, it is a DIFFERENT
   * mechanism (a native `paste` ClipboardEvent) that needs no permission and
   * works on every origin, which is why it stays the primary paste gesture and
   * why this menu item is the convenience, not the contract.
   */
  async function pasteFromClipboard() {
    if (!canWrite) {
      pushToast("This terminal is read-only - you don't have control", "warn");
      return;
    }
    const res = await readClipboard();
    if (!res.ok) {
      pushToast(
        res.reason === "unsupported"
          ? "Reading the clipboard needs an https (or localhost) connection - press Ctrl+V to paste instead"
          : "The browser blocked clipboard access - press Ctrl+V to paste instead",
        "warn",
      );
      return;
    }
    if (!res.text) {
      pushToast("The clipboard is empty", "info");
      return;
    }
    termRef.current?.paste(res.text);
    termRef.current?.focus();
  }

  /**
   * clipboardFailureMessage names the ACTUAL dependency that failed, rather
   * than always blaming TLS: on an insecure origin the async API is missing
   * (and the legacy fallback has now also failed), whereas on a secure one the
   * browser refused the write.
   */
  function clipboardFailureMessage(): string {
    return clipboardWriteAvailable()
      ? "Could not copy - the browser refused clipboard access"
      : "Could not copy - the clipboard needs an https (or localhost) connection";
  }

  // sendResizeNow tells the PTY to adopt explicit dims over the control channel
  // (wsRef is stable, so this is safe to call from the setup-effect closure).
  function sendResizeNow(rows: number, cols: number) {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ t: "resize", rows, cols }));
    }
  }

  // enterOriginalSize (Feature A) pins the viewport to the native launch
  // geometry and stops the ResizeObserver from refitting (guarded by
  // sizeModeRef). The container is unchanged, so there's no RO feedback — and
  // any RO tick while in "original" is inert.
  function enterOriginalSize() {
    const term = termRef.current;
    const dims = initialDimsRef.current;
    if (!term || !dims) return;
    sizeModeRef.current = "original";
    setSizeMode("original");
    try {
      term.resize(dims.cols, dims.rows);
    } catch {
      /* ignore */
    }
    sendResizeNow(dims.rows, dims.cols);
  }

  // enterFitSize re-enables container-tracking and refits + resends at once.
  function enterFitSize() {
    sizeModeRef.current = "fit";
    setSizeMode("fit");
    const term = termRef.current;
    try {
      fitRef.current?.fit();
    } catch {
      /* ignore */
    }
    if (term) sendResizeNow(term.rows, term.cols);
  }

  // reacquireLocal (Feature B) re-takes the writer lease for a LOCAL seat after
  // native reclaim or an authenticated remote takeover. The loopback path
  // auto-grants on connect; re-acquire mirrors that with an acquire-writer frame
  // carrying an empty capability (the server routes a loopback request without
  // one).
  reacquireLocalRef.current = () => {
    const ws = wsRef.current;
    if (isRemote || !ws || ws.readyState !== WebSocket.OPEN) return;
    if (controlRef.current !== "revoked") return;
    ws.send(JSON.stringify({ t: "acquire-writer", cap: "", confirm: "" }));
    setControl("requesting");
  };

  // enterFocusMode (Feature C4) fullscreens the WHOLE panel (chrome stays
  // visible so the exit button is reachable) and, on Chromium, locks the
  // keyboard so browser-reserved combos (Ctrl-W/T/N) reach the page → the TUI.
  async function enterFocusMode() {
    const el = rootRef.current;
    if (!el) return;
    try {
      await el.requestFullscreen();
    } catch {
      return;
    }
    try {
      await keyboardApi()?.lock?.();
      keyboardLockedRef.current = true;
    } catch {
      /* lock rejected — fullscreen still helps; reserved keys stay reserved */
    }
    setFocusMode(true);
  }

  // exitFocusMode releases the lock and leaves fullscreen. Escape is captured
  // by the lock, so this button is the primary exit affordance.
  async function exitFocusMode() {
    try {
      keyboardApi()?.unlock?.();
    } catch {
      /* ignore */
    }
    keyboardLockedRef.current = false;
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
    } catch {
      /* ignore */
    }
    setFocusMode(false);
  }

  // Exiting fullscreen by ANY means (browser UI, OS chord) must release the
  // keyboard lock and clear focus-mode state.
  useEffect(() => {
    function onFsChange() {
      if (document.fullscreenElement) return;
      if (keyboardLockedRef.current) {
        try {
          keyboardApi()?.unlock?.();
        } catch {
          /* ignore */
        }
        keyboardLockedRef.current = false;
      }
      setFocusMode(false);
    }
    document.addEventListener("fullscreenchange", onFsChange);
    return () => document.removeEventListener("fullscreenchange", onFsChange);
  }, []);

  return (
    <div
      ref={rootRef}
      className={
        fill
          ? "flex min-h-0 w-full flex-1 flex-col overflow-hidden rounded-2 border bg-[#0b0b0f]"
          : "flex h-[60vh] min-h-[360px] flex-col overflow-hidden rounded-2 border bg-[#0b0b0f]"
      }
    >
      {/* D9: the desktop header carries EIGHT always-on actions in one 33px
          row. At 393px that wrapped to 2 rows and at 360px to 3 (~90px of a
          640px screen) — a desktop action budget on a phone. Below the touch
          breakpoint the six secondary actions collapse into one ⋯ menu, the
          two lifecycle actions stay inline, and the row padding drops to zero
          so the 44px tap targets don't cost more height than the old wrap did.
          Desktop keeps the exact shipped class string. */}
      <div
        className={
          "flex items-center justify-between gap-x-2 gap-y-1 border-b border-white/10 bg-[#14141a] " +
          // Touch: NEVER wrap (D15). The header budget is what forced minimize
          // down to a glyph; making the row structurally un-wrappable buys the
          // space back the honest way — the identity span on the left is the
          // one thing allowed to shrink, and it truncates. `touch-action: pan-y`
          // additionally refuses a horizontal pan starting on the header, which
          // is what Chrome's edge-swipe-back rides on (D14).
          (isTouch
            ? "flex-nowrap px-2 py-0 [touch-action:pan-y]"
            : "flex-wrap px-3 py-1.5")
        }
        data-testid="terminal-header"
      >
        <span
          className={
            "flex min-w-0 items-center gap-2 text-[11px] text-white/60 " +
            (isTouch ? "flex-nowrap overflow-hidden" : "flex-wrap")
          }
        >
          {/* Literal palette, not theme tokens: this header is hardcoded
              bg-[#14141a] (terminal chrome is always dark, independent of
              sb_theme), so text-fg-1/text-fg-2 resolve LIGHT under the light
              theme and render near-invisible on it. */}
          <span
            className={
              "font-mono text-white/85" + (isTouch ? " min-w-0 truncate" : "")
            }
          >
            {tool}
          </span>
          <StatusPill status={status} exitCode={exitCode} />
          {errMsg && (
            <span
              className={
                "text-[10.5px] text-danger" + (isTouch ? " min-w-0 truncate" : "")
              }
              title={errMsg}
            >
              {errMsg}
            </span>
          )}
        </span>
        <span
          className={
            "flex items-center justify-end gap-1 " +
            (isTouch ? "flex-nowrap shrink-0" : "flex-wrap")
          }
        >
          {/* Touch: the six secondary actions, one ⋯ menu (D9) + "Copy
              visible" (D10, which has no desktop counterpart because a mouse
              can already drag-select). */}
          {isTouch && (
            <TerminalOverflowMenu
              items={[
                onOpenFiles && {
                  label: "▤ Files",
                  onSelect: onOpenFiles,
                  disabled: !projectPanelEnabled || !isLiveStatus(status),
                  disabledTitle: !isLiveStatus(status)
                    ? "This session is no longer running - its project can no longer be browsed"
                    : "This terminal has no directory on this machine to browse",
                },
                onOpenGit && {
                  label: "⎇ Git",
                  onSelect: onOpenGit,
                  disabled: !projectPanelEnabled || !isLiveStatus(status),
                  disabledTitle: !isLiveStatus(status)
                    ? "This session is no longer running - its project can no longer be browsed"
                    : "This terminal has no directory on this machine to browse",
                },
                onOpenSession && {
                  label: "⊙ Session",
                  onSelect: onOpenSession,
                  disabled: !sessionPanelEnabled || !isLiveStatus(status),
                  disabledTitle: !isLiveStatus(status)
                    ? "This session is no longer running - its activity can no longer be shown"
                    : "No AI tool running in this terminal",
                },
                { label: "⧉ Copy visible", onSelect: () => void copyVisible() },
                // D13: the key-label override. It lives here rather than in the
                // key bar because a control in the bar would have to clear the
                // 44px tap floor and would cost a whole extra row of a phone's
                // screen — and this is a set-once preference, not a key.
                // Auto -> Mac -> PC -> Auto; auto names the vocabulary the
                // DAEMON's OS produced, and the override stays the escape
                // hatch for anything that fact cannot describe.
                canWrite && {
                  label: platformPrefLabel(keyPlatform.pref, keyPlatform.platform),
                  onSelect: keyPlatform.cycle,
                },
                canWrite && {
                  label: sizeMode === "original" ? "⤢ Fit" : "↺ Original size",
                  onSelect: sizeMode === "original" ? enterFitSize : enterOriginalSize,
                  disabled: sizeMode !== "original" && !initialDims,
                  disabledTitle: "Original size unknown for this session",
                },
                {
                  label: focusMode ? "⤢ Exit focus" : "⤢ Focus mode",
                  onSelect: focusMode ? exitFocusMode : enterFocusMode,
                  disabled: !focusModeSupported,
                  disabledTitle: FOCUS_MODE_UNSUPPORTED,
                },
                onAddToGrid && { label: "⊞ Add to grid", onSelect: onAddToGrid },
              ]}
            />
          )}
          {/* Project panel: read-only file tree + git view rooted at this
              terminal's project root. Disabled (honest title) when the run has
              no resolved root. Header buttons only — the panel is provider-owned
              and this never touches the ws bridge. */}
          {!isTouch && onOpenFiles && (
            <ProjectPanelButton
              label="▤ Files"
              enabled={!!projectPanelEnabled && isLiveStatus(status)}
              onClick={onOpenFiles}
              enabledTitle="Browse this terminal's files"
              disabledTitle={
                !isLiveStatus(status)
                  ? "This session is no longer running - its project can no longer be browsed"
                  : undefined
              }
            />
          )}
          {!isTouch && onOpenGit && (
            <ProjectPanelButton
              label="⎇ Git"
              enabled={!!projectPanelEnabled && isLiveStatus(status)}
              onClick={onOpenGit}
              enabledTitle="Show git status, changes, and history for this terminal's directory"
              disabledTitle={
                !isLiveStatus(status)
                  ? "This session is no longer running - its project can no longer be browsed"
                  : undefined
              }
            />
          )}
          {/* Session details: opens the FULL session slide-over over the
              terminal workspace (Task 9) — the same panel the Sessions page
              uses, plus a live hero band (context used / limit headroom /
              next-turn cost / process·network·memory). The small floating
              vitals cockpit is still one click away from inside it, and is what
              an UNCORRELATED run falls back to. Disabled (honest title) for a
              run-shape that can never correlate to an observer session (a plain
              shell run) or once the session is no longer live. Header button
              only — the modal is provider-owned and this never touches the ws
              bridge. */}
          {!isTouch && onOpenSession && (
            <ProjectPanelButton
              label="⊙ Session"
              enabled={!!sessionPanelEnabled && isLiveStatus(status)}
              onClick={onOpenSession}
              enabledTitle="Open this session's full details - context and limit headroom, next-message cost, messages, cache and system"
              disabledTitle={
                !isLiveStatus(status)
                  ? "This session is no longer running - its activity can no longer be shown"
                  : "No AI tool running in this terminal"
              }
            />
          )}
          {/* Feature A: size-mode control. Resizing is a writer capability, so
              this hides for read-only remote viewers (mirrors the RemoteControlBar
              gating) and honest-disables when the original geometry is unknown. */}
          {!isTouch && canWrite && (
            <SizeModeControl
              mode={sizeMode}
              hasOriginal={!!initialDims}
              onOriginal={enterOriginalSize}
              onFit={enterFitSize}
            />
          )}
          {/* Feature C4: focus mode. Fullscreen + Keyboard Lock; the lock API is
              Chromium-only AND secure-context-only, so on Safari (any platform,
              incl. every iPhone) or over a plain-http remote origin the
              dependency is simply absent. It used to VANISH there, which reads
              as "this build doesn't have focus mode". Per the honest-disabled
              convention it now renders disabled, naming the missing dependency
              — the button is a bonus (keyboard capture), not the only usable
              view, so its absence must not look like a bug. */}
          {!isTouch &&
            (focusModeSupported ? (
              <Tooltip
                maxWidth={320}
                content={
                  focusMode
                    ? "Exit focus mode - release keyboard capture and leave fullscreen"
                    : "Focus mode - fullscreen + capture browser shortcuts (Ctrl-W/T/N) so they reach the TUI. Chromium only; exit with this button (Esc is captured)."
                }
              >
                <button
                  type="button"
                  onClick={focusMode ? exitFocusMode : enterFocusMode}
                  className={
                    "rounded-2 px-2 py-0.5 text-[11px] focus:outline-none " +
                    (focusMode
                      ? "bg-accent/20 text-accent hover:bg-accent/30"
                      : "text-fg-3 hover:bg-white/10 hover:text-fg-1")
                  }
                >
                  {focusMode ? "⤢ Exit focus" : "⤢ Focus mode"}
                </button>
              </Tooltip>
            ) : (
              <TooltipSpan content={FOCUS_MODE_UNSUPPORTED}>
                <button
                  type="button"
                  disabled
                  aria-label={FOCUS_MODE_UNSUPPORTED}
                  className="cursor-not-allowed rounded-2 px-2 py-0.5 text-[11px] text-fg-4 opacity-60"
                >
                  ⤢ Focus mode
                </button>
              </TooltipSpan>
            ))}
          {!isTouch && onAddToGrid && (
            <Tooltip content="Add to grid - dock this terminal on the Terminals workspace. The session keeps running.">
              <button
                type="button"
                onClick={onAddToGrid}
                className="rounded-2 px-2 py-0.5 text-[11px] text-fg-3 hover:bg-white/10 hover:text-fg-1 focus:outline-none"
              >
                ⊞ Add to grid
              </button>
            </Tooltip>
          )}
          <Tooltip content="Minimize - keeps the session running; restore it from the dock">
            <button
              type="button"
              onClick={onMinimize}
              // D15 (operator-reported, 2026-07-27). This used to be a bare "▾"
              // on touch — "icon-only to buy the header row back, so the
              // accessible name has to carry the meaning the label used to".
              // That reasoning was the bug: an accessible name is invisible to a
              // sighted thumb, and "▾" beside "✕" reads as a dropdown chevron.
              // The operator concluded there was NO minimize and that the only
              // way out was the destructive ✕ — and minimize's other two doors
              // are both shut on a phone (Escape needs a hardware key; the
              // backdrop-click needs a backdrop, which a full-viewport panel
              // does not have). So the word is back, and the header row is
              // bought instead by refusing to wrap: the identity span on the
              // left truncates and this action cluster never shrinks.
              // Filled rather than ghosted, so the SAFE exit is the one that
              // catches the eye first.
              aria-label={
                isTouch
                  ? "Minimize - keeps the session running; restore it from the dock"
                  : undefined
              }
              className={
                "rounded-2 px-2 py-0.5 text-[11px] focus:outline-none " +
                (isTouch
                  ? TOUCH_TARGET +
                    " shrink-0 whitespace-nowrap bg-white/10 text-white/90 hover:bg-white/20"
                  : "text-fg-3 hover:bg-white/10 hover:text-fg-1")
              }
            >
              ▾ Minimize
            </button>
          </Tooltip>
          <Tooltip
            content={
              status === "open" || status === "reconnecting"
                ? "Stop the running process and close"
                : "Close"
            }
          >
            <button
              type="button"
              onClick={requestClose}
              aria-label={
                isTouch
                  ? status === "open" || status === "reconnecting"
                    ? "Stop the running process and close"
                    : "Close terminal"
                  : undefined
              }
              // Touch: this is the DESTRUCTIVE action sitting next to Minimize
              // at 19px in the measured layout. It gets the 44px floor, an
              // extra gap from its neighbour, and a danger tint so a thumb
              // aiming at Minimize has both distance and colour to go on.
              className={
                "rounded-2 px-2 py-0.5 text-[11px] focus:outline-none " +
                (isTouch
                  ? TOUCH_TARGET + " ml-2 text-danger hover:bg-danger/15"
                  : "text-fg-3 hover:bg-white/10 hover:text-fg-1")
              }
            >
              {isTouch
                ? "✕"
                : status === "open" || status === "reconnecting"
                  ? "✕ Stop & close"
                  : "✕ Close"}
            </button>
          </Tooltip>
        </span>
      </div>
      {status === "exited" && policyStop && (
        <div
          className={
            "border-b px-3 py-1.5 text-[11px] leading-relaxed " +
            (policyStop.decision === "terminated" || policyStop.decision === "killed"
              ? "border-danger/40 bg-danger/10 text-danger"
              : "border-warn/40 bg-warn/10 text-warn")
          }
          title={policyStopMessage(policyStop)}
        >
          {policyStopMessage(policyStop)}
        </div>
      )}
      {isRemote && (
        <RemoteControlBar
          touch={isTouch}
          control={control}
          showAcquire={showAcquire}
          onToggleAcquire={() => {
            setShowAcquire((v) => !v);
            setAcqErr(null);
          }}
          cap={capInput}
          confirm={confirmInput}
          onCap={setCapInput}
          onConfirm={setConfirmInput}
          onAcquire={acquireControl}
          acqErr={acqErr}
          revokedBy={revokedBy}
          standingStored={standingStored}
          standingInput={standingInput}
          rememberStanding={rememberStanding}
          onStandingInput={setStandingInput}
          onRememberStanding={setRememberStanding}
          onAcquireStanding={acquireStanding}
          onForgetStanding={forgetStandingDevice}
        />
      )}
      {/* Feature B: local seat demoted by native reclaim or remote takeover. */}
      {!isRemote && control === "revoked" && (
        <button
          type="button"
          onClick={() => reacquireLocalRef.current()}
          className="flex w-full items-center gap-2 border-b border-white/10 bg-warn/10 px-3 py-1.5 text-left text-[11px] text-warn hover:bg-warn/15"
        >
          <span className="rounded-full bg-warn/20 px-1.5 py-0.5 text-[9.5px] font-medium uppercase tracking-[0.05em]">
            read-only
          </span>
          <span>
            {revokedBy === "remote"
              ? "A remote device took control - click to take back."
              : "Control returned to the native terminal - click to take back."}
          </span>
        </button>
      )}
      {!isRemote && control === "requesting" && (
        <div className="border-b border-white/10 bg-bg-1 px-3 py-1.5 text-[11px] text-fg-3">
          Taking back control…
        </div>
      )}
      <div
        ref={hostRef}
        // D11: `overscroll-behavior: contain` stops a drag that runs past the
        // top/bottom of the scrollback from chaining into the page behind the
        // panel (the phone rubber-band that made the whole dashboard lurch).
        className={
          "min-h-0 flex-1 overflow-x-auto p-2" +
          (isTouch ? " overscroll-contain" : "")
        }
        onMouseDown={() => {
          // Click-to-focus for the padding/letterbox area a docked grid tile's
          // xterm canvas doesn't cover (Feature C5); also the click half of the
          // local take-back path (Feature B).
          if (!isRemote && controlRef.current === "revoked") {
            reacquireLocalRef.current();
          }
          termRef.current?.focus();
        }}
      />
      {/* D3: the on-screen modifier row. Rendered BELOW the terminal (the host
          is flex-1, so this pins to the bottom edge) because that is where a
          thumb rests and where the soft keyboard's own top row would sit —
          putting it under the header would place it at the far end of the
          reach arc. Only for a touch seat that can actually write: a read-only
          viewer gets no key bar at all, which is the first of the three gates
          on the write path (the other two — canWriteRef in onData and xterm's
          own disableStdin — still hold). */}
      {isTouch && canWrite && (
        <TerminalKeyBar
          mods={softMods}
          onMods={setSoftModsBoth}
          onSend={(seq) => {
            // THE one write seam: term.input -> coreService.triggerDataEvent ->
            // onData -> canWriteRef gate -> ws.send. No second path.
            termRef.current?.input(seq, true);
          }}
          // DECCKM is flipped by PTY output with no React render in between, so
          // it must be read at press time rather than passed as a prop.
          appCursorKeys={() =>
            !!termRef.current?.modes.applicationCursorKeysMode
          }
          // Labelling only (D13) — the encoders below it are byte-identical on
          // both settings.
          platform={keyPlatform.platform}
        />
      )}
      {ctxMenu && (
        <TerminalContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          hasSelection={ctxMenu.hasSelection}
          canWrite={canWrite}
          canReadClipboard={clipboardReadAvailable()}
          onCopy={() => {
            const sel = termRef.current?.getSelection() ?? "";
            if (sel) void copySelectionRef.current(sel);
          }}
          onPaste={() => void pasteFromClipboard()}
          onCopyVisible={() => void copyVisible()}
          onClose={() => {
            setCtxMenu(null);
            termRef.current?.focus();
          }}
        />
      )}
    </div>
  );
}

// TerminalContextMenu — the right-click Copy/Paste menu for the embedded
// terminal (Task 10). It exists because a full-screen TUI turns on DECSET
// mouse-tracking, xterm forwards the right-click to the app and cancels the
// browser's own context menu, and the operator is left with no pointer-driven
// clipboard affordance at all.
//
// Rendered into a portal at z-200 — above the expanded-terminal backdrop
// (z-80), the floating panel band ([90,110]) and the session slide-over
// (z-112/114), matching the z-200 the dock's layering note already reserves
// for context menus. A portal, not an in-tree absolute box, because the
// terminal panel is `overflow-hidden` and a menu opened near the bottom edge
// would otherwise be clipped.
//
// HONEST DISABLING. "Paste" is not shown as an ordinary item when it cannot
// work: with no write control it is disabled with the reason; with no
// clipboard-read permission path it is disabled and points at Ctrl+V, which is
// a different mechanism that still works. A control that silently does nothing
// is the thing this repo's convention forbids.
function TerminalContextMenu({
  x,
  y,
  hasSelection,
  canWrite,
  canReadClipboard,
  onCopy,
  onPaste,
  onCopyVisible,
  onClose,
}: {
  x: number;
  y: number;
  hasSelection: boolean;
  canWrite: boolean;
  canReadClipboard: boolean;
  onCopy: () => void;
  onPaste: () => void;
  onCopyVisible: () => void;
  onClose: () => void;
}) {
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState({ x, y });

  // Flip the menu back inside the viewport when it was opened near an edge.
  // Measured after mount (the size depends on which items rendered), so this
  // is a layout effect's job — but a one-frame settle is invisible here and
  // useEffect keeps the component SSR-safe like the rest of the file.
  useEffect(() => {
    const el = menuRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const nx = x + r.width > window.innerWidth - 8 ? Math.max(8, x - r.width) : x;
    const ny = y + r.height > window.innerHeight - 8 ? Math.max(8, y - r.height) : y;
    if (nx !== x || ny !== y) setPos({ x: nx, y: ny });
  }, [x, y]);

  // Dismiss on anything that means "I'm done with this menu". `pointerdown` in
  // the CAPTURE phase so the click that dismisses does not also land in the
  // terminal underneath; `scroll` captured too, since the scroller is an
  // ancestor and scroll does not bubble.
  useEffect(() => {
    const onPointerDown = (e: PointerEvent) => {
      if (menuRef.current?.contains(e.target as Node)) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("pointerdown", onPointerDown, true);
    document.addEventListener("keydown", onKey, true);
    window.addEventListener("scroll", onClose, true);
    window.addEventListener("blur", onClose);
    window.addEventListener("resize", onClose);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown, true);
      document.removeEventListener("keydown", onKey, true);
      window.removeEventListener("scroll", onClose, true);
      window.removeEventListener("blur", onClose);
      window.removeEventListener("resize", onClose);
    };
  }, [onClose]);

  const pasteReason = !canWrite
    ? "This terminal is read-only"
    : !canReadClipboard
      ? "Needs an https (or localhost) connection - press Ctrl+V instead"
      : undefined;

  return createPortal(
    <div
      ref={menuRef}
      role="menu"
      data-testid="terminal-context-menu"
      style={{ top: pos.y, left: pos.x }}
      // Terminal chrome is always dark in both themes (same reasoning as
      // TerminalKeyBar), so this uses literal dark surfaces rather than theme
      // tokens that would resolve light.
      className="fixed z-[200] min-w-[190px] overflow-hidden rounded-2 border border-white/12 bg-[#14141a] py-1 text-[12px] text-white/90 shadow-drawer"
      onContextMenu={(e) => e.preventDefault()}
    >
      <MenuItem
        label="Copy"
        hint="Ctrl+Shift+C"
        disabled={!hasSelection}
        disabledReason="Nothing selected"
        onSelect={() => {
          onCopy();
          onClose();
        }}
      />
      <MenuItem
        label="Paste"
        hint="Ctrl+V"
        disabled={Boolean(pasteReason)}
        disabledReason={pasteReason}
        onSelect={() => {
          onPaste();
          onClose();
        }}
      />
      <div className="my-1 border-t border-white/10" />
      <MenuItem
        label="Copy visible output"
        onSelect={() => {
          onCopyVisible();
          onClose();
        }}
      />
    </div>,
    document.body,
  );
}

function MenuItem({
  label,
  hint,
  disabled,
  disabledReason,
  onSelect,
}: {
  label: string;
  hint?: string;
  disabled?: boolean;
  disabledReason?: string;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      disabled={disabled}
      title={disabled ? disabledReason : undefined}
      // Keep xterm's helper textarea focused through the press so a Paste lands
      // in a still-focused terminal.
      onMouseDown={(e) => e.preventDefault()}
      onClick={onSelect}
      className={
        "flex w-full items-center justify-between gap-4 px-3 py-1.5 text-left " +
        (disabled
          ? "cursor-not-allowed text-white/30"
          : "text-white/90 hover:bg-white/10")
      }
    >
      <span>{label}</span>
      {hint && <span className="shrink-0 text-[10px] text-white/40">{hint}</span>}
    </button>
  );
}

// FOCUS_MODE_UNSUPPORTED names the EXACT missing dependency (honest-disabled
// convention). Focus mode needs document.fullscreenEnabled AND
// navigator.keyboard.lock — the latter is Chromium-only and secure-context-only,
// so it is absent in every Safari (including all iPhones) and over a plain-http
// remote origin.
const FOCUS_MODE_UNSUPPORTED =
  "Focus mode needs keyboard capture - a Chromium browser over HTTPS (or localhost). This browser doesn't provide it.";

// TOUCH_TARGET is the tap-target floor applied below the touch breakpoint.
// Apple HIG asks 44pt and Android 48dp; 44px is the binding minimum. Measured
// before this pass, the panel's controls were 19-21px tall.
const TOUCH_TARGET = "min-h-[44px] min-w-[44px]";

type OverflowItem = {
  label: string;
  onSelect: () => void;
  disabled?: boolean;
  /** Honest reason shown (and announced) when disabled. */
  disabledTitle?: string;
};

/**
 * TerminalOverflowMenu is the touch-only ⋯ menu that carries the header's
 * secondary actions (D9). It exists so the header stays ONE row on a phone; on
 * desktop the same actions render inline exactly as they always have, and this
 * component is never mounted.
 *
 * Falsy entries are accepted and dropped so callers can build the list with the
 * same `onOpenFiles && {…}` conditionals the inline buttons use.
 */
function TerminalOverflowMenu({
  items,
}: {
  items: Array<OverflowItem | false | undefined | null>;
}) {
  const [open, setOpen] = useState(false);
  const live = items.filter((i): i is OverflowItem => !!i);
  return (
    <span className="relative">
      <button
        type="button"
        aria-label="More terminal actions"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className={`${TOUCH_TARGET} rounded-2 px-2 text-[15px] leading-none text-white/70 hover:bg-white/10 hover:text-white focus:outline-none`}
      >
        ⋯
      </button>
      {open && (
        <>
          {/* Tap-away closes. Sits under the menu, over everything else. */}
          <span
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
            aria-hidden="true"
          />
          <span
            data-testid="terminal-overflow-menu"
            // Terminal chrome is always dark (the panel hardcodes #0b0b0f /
            // #14141a rather than theme tokens). `bg-bg-1`/`text-fg-2` resolve
            // to WHITE-on-dark-grey under the light theme, so this surface uses
            // the same literal palette as the header it drops out of.
            className="absolute right-0 top-full z-50 mt-1 flex w-56 flex-col overflow-hidden rounded-2 border border-white/15 bg-[#1b1b23] shadow-lg"
          >
            {live.map((item) => (
              <button
                key={item.label}
                type="button"
                disabled={item.disabled}
                aria-label={
                  item.disabled ? (item.disabledTitle ?? item.label) : undefined
                }
                title={item.disabled ? item.disabledTitle : undefined}
                onClick={() => {
                  setOpen(false);
                  item.onSelect();
                }}
                className={
                  `${TOUCH_TARGET} flex items-center px-3 text-left text-[13px] ` +
                  (item.disabled
                    ? "cursor-not-allowed text-white/35"
                    : "text-white/85 hover:bg-white/10 hover:text-white")
                }
              >
                {item.label}
              </button>
            ))}
          </span>
        </>
      )}
    </span>
  );
}

// ProjectPanelButton is a small chrome button (Files / Git) that opens the
// per-terminal project panel. Enabled for every dashboard-launched terminal
// that has a directory on this machine: an allow-listed project root when the
// launch requested one, otherwise the terminal's own working directory (the
// panel header says which). Honest-disabled only when there is genuinely
// nothing local to browse, e.g. an SSH terminal whose files live on the remote
// host (per the honest-disabled-copy convention).
function ProjectPanelButton({
  label,
  enabled,
  onClick,
  enabledTitle,
  disabledTitle = "This terminal has no directory on this machine to browse",
}: {
  label: string;
  enabled: boolean;
  onClick: () => void;
  enabledTitle: string;
  disabledTitle?: string;
}) {
  const tip = enabled ? enabledTitle : disabledTitle;
  const btn = (
    <button
      type="button"
      disabled={!enabled}
      onClick={onClick}
      // Enabled: accessible name stays the visible glyph+word label
      // ("▤ Files" / "⊙ Session"). Disabled: a disabled control can't
      // carry a title tooltip a screen reader announces, so surface the
      // honest reason as the accessible name (the 417 e2e asserts this).
      aria-label={enabled ? undefined : tip}
      className={
        "rounded-2 px-2 py-0.5 text-[11px] focus:outline-none " +
        (enabled
          ? "text-fg-3 hover:bg-white/10 hover:text-fg-1"
          : "cursor-not-allowed text-fg-4 opacity-60")
      }
    >
      {label}
    </button>
  );
  // A disabled <button> swallows pointer events, so hover would never
  // fire on it directly — wrap the disabled case in TooltipSpan (a
  // focusable/hoverable span reference) so the honest tooltip still
  // shows. The enabled button is its own hover/focus reference.
  return enabled ? (
    <Tooltip content={tip}>{btn}</Tooltip>
  ) : (
    <TooltipSpan content={tip}>{btn}</TooltipSpan>
  );
}

// SizeModeControl is the Feature-A size-mode toggle shown in the terminal
// chrome. In "fit" it offers "↺ Original size" (honest-disabled when the native
// geometry is unknown); in "original" it shows an active "⤢ Fit" to return to
// container-tracking. Writer-gated by its caller.
function SizeModeControl({
  mode,
  hasOriginal,
  onOriginal,
  onFit,
}: {
  mode: "fit" | "original";
  hasOriginal: boolean;
  onOriginal: () => void;
  onFit: () => void;
}) {
  if (mode === "original") {
    return (
      <Tooltip content="Pinned to the native terminal's original size - click to refit to the panel.">
        <button
          type="button"
          onClick={onFit}
          className="rounded-2 bg-accent/20 px-2 py-0.5 text-[11px] text-accent hover:bg-accent/30 focus:outline-none"
        >
          ⤢ Fit
        </button>
      </Tooltip>
    );
  }
  if (!hasOriginal) {
    // Disabled button swallows pointer events — TooltipSpan keeps the
    // honest hover hint reachable.
    return (
      <TooltipSpan content="Original size unknown for this session">
        <button
          type="button"
          disabled
          className="cursor-not-allowed rounded-2 px-2 py-0.5 text-[11px] text-fg-4 opacity-60"
        >
          ↺ Original size
        </button>
      </TooltipSpan>
    );
  }
  return (
    <Tooltip
      maxWidth={320}
      content="Restore the native terminal's original size - fixes a TUI that garbled after a resize. Stops auto-refit until you switch back to Fit."
    >
      <button
        type="button"
        onClick={onOriginal}
        className="rounded-2 px-2 py-0.5 text-[11px] text-fg-3 hover:bg-white/10 hover:text-fg-1 focus:outline-none"
      >
        ↺ Original size
      </button>
    </Tooltip>
  );
}

// RemoteControlBar is the remote-device terminal-control strip (§4, deliverable
// 2). It renders ONLY on a remote-paired device: input is read-only until the
// user pastes the owner-conveyed capability + confirm and acquires control over
// the websocket. It reacts to control_granted / control_denied / control_revoked
// surfaced through the `control` prop.
function RemoteControlBar({
  touch,
  control,
  showAcquire,
  onToggleAcquire,
  cap,
  confirm,
  onCap,
  onConfirm,
  onAcquire,
  acqErr,
  revokedBy,
  standingStored,
  standingInput,
  rememberStanding,
  onStandingInput,
  onRememberStanding,
  onAcquireStanding,
  onForgetStanding,
}: {
  /** Apply the 44px tap-target floor (touch breakpoint). Desktop: unchanged. */
  touch: boolean;
  control: Control;
  showAcquire: boolean;
  onToggleAcquire: () => void;
  cap: string;
  confirm: string;
  onCap: (v: string) => void;
  onConfirm: (v: string) => void;
  onAcquire: () => void;
  acqErr: string | null;
  revokedBy: "local" | "remote" | null;
  standingStored: boolean;
  standingInput: string;
  rememberStanding: boolean;
  onStandingInput: (v: string) => void;
  onRememberStanding: (v: boolean) => void;
  onAcquireStanding: () => void;
  onForgetStanding: () => void;
}) {
  const writer = control === "writer";
  const requesting = control === "requesting";
  const label =
    control === "writer"
      ? "You have control"
      : control === "requesting"
        ? "Requesting control…"
        : control === "revoked"
          ? revokedBy === "local"
            ? "The owner took control - you are viewing read-only"
            : revokedBy === "remote"
              ? "Another remote device took control - you are viewing read-only"
              : "Control ended - you are viewing read-only"
          : control === "denied"
            ? "Read-only - control was denied"
            : "Read-only view";
  const pillCls = writer
    ? "bg-ok/20 text-ok"
    : requesting
      ? "bg-white/10 text-fg-3"
      : "bg-warn/20 text-warn";
  return (
    <div className="border-b border-white/10 bg-[#101017] px-3 py-1.5 text-[11px]">
      <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
        <span className="flex min-w-0 flex-wrap items-center gap-2">
          <span
            className={`rounded-full px-1.5 py-0.5 text-[9.5px] font-medium uppercase tracking-[0.05em] ${pillCls}`}
          >
            {label}
          </span>
          {!writer && !requesting && (
            <span className="text-fg-3">
              Ask the owner to “Grant control”, then paste the capability + confirm code they send you.
            </span>
          )}
        </span>
        {!writer && (
          <button
            type="button"
            onClick={onToggleAcquire}
            className={
              "rounded-2 border border-accent/50 bg-accent/15 px-2 py-0.5 text-[11px] font-medium text-accent hover:bg-accent/25" +
              (touch ? " " + TOUCH_TARGET : "")
            }
          >
            {showAcquire ? "Cancel" : control === "revoked" ? "Re-acquire control" : "Acquire control"}
          </button>
        )}
      </div>
      {standingStored && (
        <div className="mt-1.5 flex flex-wrap items-center justify-between gap-2 rounded-2 border border-line-2 bg-bg-1 px-2 py-1">
          <span className="text-[10.5px] text-fg-3">
            Standing access is saved on this device - control is re-acquired automatically on refresh.
          </span>
          <Tooltip content="Remove the saved standing secret from this browser (stops auto-acquiring on refresh)">
            <button
              type="button"
              onClick={onForgetStanding}
              className={
                "shrink-0 rounded-2 border border-danger/40 bg-danger/10 px-2 py-0.5 text-[10.5px] text-danger hover:bg-danger/20" +
                (touch ? " " + TOUCH_TARGET : "")
              }
            >
              Forget standing secret on this device
            </button>
          </Tooltip>
        </div>
      )}
      {showAcquire && !writer && (
        <div className="mt-2 space-y-2 rounded-2 border border-line-2 bg-bg-1 p-2">
          <label className="block">
            <span className="mb-0.5 block text-[10px] uppercase tracking-wide text-fg-3">
              capability
            </span>
            <input
              value={cap}
              onChange={(e) => onCap(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="paste the capability the owner sent"
              className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 outline-none focus:border-accent"
            />
          </label>
          <label className="block">
            <span className="mb-0.5 block text-[10px] uppercase tracking-wide text-fg-3">
              confirm code
            </span>
            <input
              value={confirm}
              onChange={(e) => onConfirm(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="paste the confirm code"
              className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 outline-none focus:border-accent"
              onKeyDown={(e) => {
                if (e.key === "Enter") onAcquire();
              }}
            />
          </label>
          {acqErr && <div className="text-[11px] text-danger">{acqErr}</div>}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onAcquire}
              disabled={requesting}
              className={
                "rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[11px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50" +
                (touch ? " " + TOUCH_TARGET : "")
              }
            >
              {requesting ? "requesting…" : "Take control"}
            </button>
            <span className="text-[10px] text-fg-3">
              Sent over the encrypted session only - never stored or put in the URL.
            </span>
          </div>

          {/* Standing-secret alternative (§B, advanced). A single reusable
              secret that grants control of every terminal and can be remembered
              on this device so control survives refreshes. Off unless the user
              pastes one — the one-time capability above stays the default. */}
          <div className="mt-1 border-t border-line-2 pt-2">
            <div className="mb-1 text-[10px] uppercase tracking-wide text-fg-3">
              or use a standing secret (advanced)
            </div>
            <input
              value={standingInput}
              onChange={(e) => onStandingInput(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="paste the standing secret (starts with standing.)"
              className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 outline-none focus:border-accent"
              onKeyDown={(e) => {
                if (e.key === "Enter") onAcquireStanding();
              }}
            />
            <label className="mt-1.5 flex items-start gap-1.5">
              <input
                type="checkbox"
                checked={rememberStanding}
                onChange={(e) => onRememberStanding(e.target.checked)}
                className="mt-0.5"
              />
              <span className="text-[10px] text-fg-3">
                <span className="font-medium text-fg-2">Remember on this device (localStorage). </span>
                {STANDING_REMEMBER_RISK}
              </span>
            </label>
            <button
              type="button"
              onClick={onAcquireStanding}
              className={
                "mt-1.5 rounded-2 border border-warn/50 bg-warn/10 px-3 py-1 text-[11px] font-medium text-warn hover:bg-warn/20" +
                (touch ? " " + TOUCH_TARGET : "")
              }
            >
              Use standing secret
            </button>
          </div>
        </div>
      )}
      {acqErr && !showAcquire && <div className="mt-1 text-[11px] text-danger">{acqErr}</div>}
    </div>
  );
}

function StatusPill({
  status,
  exitCode,
}: {
  status: Status;
  exitCode: number | null;
}) {
  const map: Record<Status, { label: string; cls: string }> = {
    connecting: { label: "connecting…", cls: "bg-white/10 text-fg-3" },
    open: { label: "live", cls: "bg-ok/20 text-ok" },
    // The session is still running server-side — only this browser's transport
    // dropped. Warn-coloured (something is off) but never "exited".
    reconnecting: { label: "reconnecting…", cls: "bg-warn/20 text-warn" },
    exited: {
      label: exitCode === null ? "exited" : `exited (${exitCode})`,
      cls: "bg-white/10 text-fg-3",
    },
    error: { label: "error", cls: "bg-danger/20 text-danger" },
  };
  const { label, cls } = map[status];
  return (
    <span
      // shrink-0: in the touch header the identity row never wraps, so the
      // pill must keep its full width and let the tool NAME be the thing that
      // truncates — a half-clipped "reconnecting…" says nothing.
      className={`shrink-0 whitespace-nowrap rounded-full px-1.5 py-0.5 text-[9.5px] font-medium uppercase tracking-[0.05em] ${cls}`}
    >
      {label}
    </span>
  );
}
