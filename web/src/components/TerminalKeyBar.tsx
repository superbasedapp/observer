// TerminalKeyBar — the on-screen modifier/navigation key row for the embedded
// terminal on a touch device (D3 of the mobile-terminal interaction pass).
//
// WHY IT EXISTS. A phone's soft keyboard has letters, digits and Return. It has
// no Esc, no Tab, no arrows and no Ctrl — so every TUI the dashboard can launch
// (Claude Code, codex, a shell) is undrivable from a phone: you cannot dismiss a
// prompt, cycle a completion, walk history, or interrupt a runaway command.
//
// WHY IT WRITES THROUGH `term.input(seq, true)` AND NOTHING ELSE (CLAUDE.md #2 —
// one seam per integration point). LaunchTerminal has exactly ONE path to the
// PTY: `term.onData` -> `canWriteRef` gate -> `ws.send(TextEncoder…)`.
// `term.input()` calls `coreService.triggerDataEvent`, which
//   (a) early-returns when `options.disableStdin` is set — and LaunchTerminal
//       sets `disableStdin = isRemote ? !canWrite : false`, so a read-only
//       remote viewer's taps are dropped by the SAME gate as its keystrokes; and
//   (b) fires `onData`, so the canWrite + socket-open checks there still apply.
// The bar therefore adds a CALL SITE, not a second write path. `wasUserInput:
// true` additionally gives scroll-to-bottom-on-input for free.
//
// WHY NOT `term.paste()`. Paste applies bracketed-paste wrapping whenever the
// running app has enabled mode 2004 — it would wrap `\x1b` and `\x03` in
// `ESC[200~ … ESC[201~` and the TUI would receive literal text instead of a
// control byte.
//
// WHY THERE IS NO Cmd BUTTON. The PTY on the other end is a Linux/WSL process;
// there is no `Cmd` modifier in a terminal at all, and LaunchTerminal's own key
// handler already documents that xterm does not map Meta to terminal Ctrl (so a
// Cmd button could never deliver a control byte). macOS `Opt` IS `Alt` — the ESC
// prefix — which is the `Alt` button below. Shipping a `Cmd` key would be a
// control that provably does nothing, which this repo's honest-affordance
// convention forbids. The bar carries a one-line NOTE saying so, so that a Mac
// user reads the absence as deliberate rather than as a missing feature.
//
// D13 — WHAT THE LABELS SAY (2026-07-27, operator on a phone). Two changes,
// both purely presentational:
//   * The modifier vocabulary follows `lib/keyPlatform` — `Ctrl`/`Alt` on a PC,
//     `⌃ Control` / `⌥ Option` on a Mac. The auto signal is the DAEMON's OS
//     (`/api/status.host_os`), not the browser's user-agent: the labels describe
//     the machine whose PTY this is, and the browser is often a phone driving a
//     daemon on a different OS (which is the product's whole premise). A manual
//     override remains for everything the host OS cannot describe.
//   * `^C` / `^D` are labelled by ACTION ("Interrupt" / "End input") with the
//     caret notation demoted to a sub-label. Caret notation did not land: the
//     operator read `^C` as `Alt+C`.
// NEITHER changes a byte. `applySoftMods` and `arrowSeq` below are
// platform-independent and stay that way — a PTY takes bytes, and Ctrl+C is
// 0x03 everywhere.

import { CMD_NOTE, keyLabels, type KeyPlatform } from "@/lib/keyPlatform";

export type ModState = "off" | "once" | "lock";

export type SoftMods = {
  ctrl: ModState;
  alt: ModState;
};

export const NO_SOFT_MODS: SoftMods = { ctrl: "off", alt: "off" };

/** softModsActive reports whether any modifier is armed (one-shot or locked). */
export function softModsActive(m: SoftMods): boolean {
  return m.ctrl !== "off" || m.alt !== "off";
}

/** cycleMod advances a sticky modifier: off -> one-shot -> locked -> off. */
export function cycleMod(s: ModState): ModState {
  return s === "off" ? "once" : s === "once" ? "lock" : "off";
}

/** clearOneShots drops "once" modifiers (a locked modifier survives). */
export function clearOneShots(m: SoftMods): SoftMods {
  return {
    ctrl: m.ctrl === "once" ? "off" : m.ctrl,
    alt: m.alt === "once" ? "off" : m.alt,
  };
}

/**
 * applySoftMods encodes an armed Ctrl/Alt onto a SINGLE PRINTABLE character —
 * the soft-keyboard case ("tap Ctrl, then type l" -> `\x0c`).
 *
 * It deliberately transforms nothing else. Multi-byte data is either an escape
 * sequence this bar already emitted fully-formed (arrows carry their own
 * modifier parameter) or a paste/IME burst, and re-encoding either would corrupt
 * it. Returning the input unchanged is the safe identity.
 *
 *   Ctrl+<char> = char.toUpperCase() - 64   (C0 control byte, e.g. l -> 0x0C)
 *   Alt+<char>  = ESC + char                (the terminal Meta convention)
 *   Ctrl+Alt+<char> = ESC + the Ctrl byte
 */
export function applySoftMods(data: string, mods: SoftMods): string {
  if (data.length !== 1) return data;
  const code = data.charCodeAt(0);
  // Printable ASCII only. A control byte is already the product of a modifier.
  if (code < 0x20 || code > 0x7e) return data;
  let out = data;
  if (mods.ctrl !== "off") {
    const c = data.toUpperCase().charCodeAt(0) - 64;
    // Ctrl is only defined for @ A-Z [ \ ] ^ _ (0x40-0x5F) and, by convention,
    // ? -> 0x7F. Anything else has no control byte; leave the character alone
    // rather than transmitting a garbage byte.
    if (c >= 0 && c <= 31) out = String.fromCharCode(c);
    else if (data === "?") out = "\x7f";
  }
  if (mods.alt !== "off") out = "\x1b" + out;
  return out;
}

/**
 * arrowSeq returns the byte sequence for an arrow key.
 *
 * `appCursor` is DEC private mode DECCKM (`term.modes.applicationCursorKeysMode`)
 * — read off the live terminal by the caller rather than hardcoded, because
 * full-screen TUIs flip it at runtime and an app in application-cursor mode
 * expects `ESC O A`, not `ESC [ A`.
 *
 * A MODIFIED arrow always uses the CSI form with a modifier parameter
 * (`ESC [ 1 ; m A`) — the SS3 form has no parameter slot at all, so there is no
 * "application-mode Ctrl+Up" to emit. Modifier param per the xterm convention:
 * 1 + 1(Shift) + 2(Alt) + 4(Ctrl), i.e. Alt=3, Ctrl=5, Ctrl+Alt=7.
 */
export function arrowSeq(
  dir: "up" | "down" | "left" | "right",
  appCursor: boolean,
  mods: SoftMods,
): string {
  // CSI final byte: A=Up, B=Down, C=Right, D=Left (ECMA-48 CUU/CUD/CUF/CUB).
  const final = { up: "A", down: "B", right: "C", left: "D" }[dir];
  const mod = 1 + (mods.alt !== "off" ? 2 : 0) + (mods.ctrl !== "off" ? 4 : 0);
  if (mod > 1) return `\x1b[1;${mod}${final}`;
  return appCursor ? `\x1bO${final}` : `\x1b[${final}`;
}

// Touch-target floor. Apple HIG asks 44pt, Android 48dp; 44px is the binding
// minimum and keeps the bar inside a phone's bottom third.
const TAP = "min-h-[44px] min-w-[44px]";

type Props = {
  /** Current sticky-modifier state (owned by LaunchTerminal — see below). */
  mods: SoftMods;
  /** Replace the modifier state (toggle a modifier / consume a one-shot). */
  onMods: (next: SoftMods) => void;
  /** The ONE write seam: LaunchTerminal calls `term.input(seq, true)`. */
  onSend: (seq: string) => void;
  /**
   * Live read of DECCKM off the terminal. A getter, not a boolean prop, because
   * the mode flips from PTY output with no React render in between.
   */
  appCursorKeys: () => boolean;
  /**
   * Which modifier VOCABULARY to print (D13). Resolved by LaunchTerminal from
   * `useKeyPlatform()` — the daemon's OS plus the operator's override — and
   * passed down as a plain string so neither the preference type nor the host
   * OS reaches the presentation layer.
   *
   * PURELY A LABEL. The emitted bytes are identical on both settings: a PTY
   * takes bytes, and `Ctrl+C` is 0x03 on every OS. Absent -> "pc", which is
   * exactly the labelling that shipped.
   */
  platform?: KeyPlatform;
};

/**
 * TerminalKeyBar renders the touch key row. The sticky modifier STATE lives in
 * LaunchTerminal (one owner, CLAUDE.md #4) because the soft keyboard's own
 * characters arrive on `term.onData` and must be modified there; this component
 * owns the ENCODING TABLE (the exported pure helpers above) and the presentation.
 */
export function TerminalKeyBar({
  mods,
  onMods,
  onSend,
  appCursorKeys,
  platform = "pc",
}: Props) {
  const L = keyLabels(platform);

  // Emit a fully-formed sequence and retire any one-shot modifier.
  function press(seq: string) {
    onSend(seq);
    onMods(clearOneShots(mods));
  }

  // Terminal chrome is ALWAYS dark (the panel hardcodes #0b0b0f / #14141a
  // rather than theme tokens, because a terminal is dark in both themes). So
  // the key bar uses white-alpha + literal accent hexes too: `text-fg-2` /
  // `text-accent` resolve to DARK values under the light theme and would be
  // near-invisible on this surface.
  // ARMED and LOCKED must be tellable apart at a glance — "this applies to my
  // next key" and "this applies until I turn it off" are different promises,
  // and a two-step alpha ramp was not enough to distinguish them (verified on
  // the captured screenshots). Locked is a SOLID fill with dark text; armed is
  // an outline. The label also gains a lock glyph, so the distinction does not
  // rest on colour alone.
  const modCls = (s: ModState) =>
    s === "lock"
      ? "border-[#7c9eff] bg-[#7c9eff] text-[#0b0b0f]"
      : s === "once"
        ? "border-[#7c9eff] bg-transparent text-[#a9c0ff]"
        : "border-white/10 text-white/85";
  const modLabel = (base: string, s: ModState) =>
    s === "lock" ? `${base} ⇩` : base;

  return (
    <div
      data-testid="terminal-key-bar"
      // `touch-action: pan-y` (was `manipulation`): both kill the 300ms
      // double-tap-zoom delay so a double-tap on Ctrl reads as "lock" rather
      // than a page zoom, but pan-y ALSO refuses horizontal panning that starts
      // here — which is what Chrome's edge-swipe-back gesture rides on (D14).
      className="shrink-0 border-t border-white/10 bg-[#14141a] px-1.5 py-1 [touch-action:pan-y]"
      // Keep the xterm helper textarea focused: a blur would dismiss the soft
      // keyboard on every key-bar tap. Preventing the default of the pointer-down
      // stops the focus transfer while still letting the click through.
      onMouseDown={(e) => e.preventDefault()}
    >
      {/* A 5-column GRID, not a wrapping flex row: ten keys of equal width in
          two even rows at any phone width. (Flex-wrap left an orphan row of
          three stretched keys, which reads as broken layout.) A key may carry a
          second, smaller line — the 44px floor already leaves room for it, so
          the bar's height is unchanged. */}
      <div className="grid grid-cols-5 gap-1">
        {/* Row 1 — modifiers and the two signals a stuck agent needs most. */}
        <Key label="Esc" title="Escape" onPress={() => press("\x1b")} />
        <Key label="Tab" title="Tab" onPress={() => press("\t")} />
        <Key
          label={modLabel(L.ctrl.main, mods.ctrl)}
          sub={L.ctrl.sub}
          title={`${L.ctrlName} - tap to arm for the next key, double-tap to lock`}
          pressed={mods.ctrl !== "off"}
          state={mods.ctrl}
          cls={modCls(mods.ctrl)}
          onPress={() => onMods({ ...mods, ctrl: cycleMod(mods.ctrl) })}
        />
        <Key
          label={modLabel(L.alt.main, mods.alt)}
          sub={L.alt.sub}
          // macOS Opt IS Alt (the ESC prefix) — see the Cmd note at the top.
          title={`${L.altName} - tap to arm for the next key, double-tap to lock`}
          pressed={mods.alt !== "off"}
          state={mods.alt}
          cls={modCls(mods.alt)}
          onPress={() => onMods({ ...mods, alt: cycleMod(mods.alt) })}
        />
        {/* LABELLED BY ACTION, notation demoted (D13). The operator read `^C`
            as "Alt+C" — caret notation is a convention, not a word, and at 3am
            what you want is "stop this". The accessible names are UNCHANGED
            (they already said "interrupt" / "end of input"), and so are the
            bytes: \x03 / \x04. */}
        <Key
          label="Interrupt"
          sub={L.chord("C")}
          wordLabel
          title="Ctrl+C - interrupt"
          onPress={() => press("\x03")}
        />
        {/* Row 2 — navigation kept together, in the ← ↓ ↑ → order every mobile
            terminal app uses, so the cluster reads as one control. */}
        <Key
          label="End input"
          sub={L.chord("D")}
          wordLabel
          title="Ctrl+D - end of input"
          onPress={() => press("\x04")}
        />
        <Key
          label="←"
          title="Left arrow"
          onPress={() => press(arrowSeq("left", appCursorKeys(), mods))}
        />
        <Key
          label="↓"
          title="Down arrow"
          onPress={() => press(arrowSeq("down", appCursorKeys(), mods))}
        />
        <Key
          label="↑"
          title="Up arrow"
          onPress={() => press(arrowSeq("up", appCursorKeys(), mods))}
        />
        <Key
          label="→"
          title="Right arrow"
          onPress={() => press(arrowSeq("right", appCursorKeys(), mods))}
        />
      </div>
      {/* The footnote. On the Apple vocabulary it answers the question the bar
          provokes ("where is ⌘?") with the honest reason there is no such key;
          on the PC vocabulary it just names the current setting so the override
          is discoverable. NOT a button — a control here would have to clear the
          44px tap floor and would cost a whole extra row; the switch itself
          lives in the header's ⋯ menu, which is already the touch home for
          secondary actions. */}
      <p className="mt-1 truncate text-center text-[10px] leading-[14px] text-white/40">
        {platform === "mac" ? CMD_NOTE : "PC keys (Ctrl/Alt) · Mac labels under ⋯"}
      </p>
    </div>
  );
}

function Key({
  label,
  sub,
  title,
  onPress,
  pressed,
  cls,
  state,
  wordLabel,
}: {
  label: string;
  /** Optional smaller second line (the demoted notation / the Apple word). */
  sub?: string;
  title: string;
  onPress: () => void;
  pressed?: boolean;
  cls?: string;
  /** Modifier keys expose their sticky state for the regression specs. */
  state?: ModState;
  /**
   * A whole WORD rather than a glyph or a 3-4 char abbreviation. Word labels
   * drop a size so "Interrupt" / "End input" fit a 66px column at 360px, which
   * is the narrowest phone the layout pins.
   */
  wordLabel?: boolean;
}) {
  return (
    <button
      type="button"
      // The bar must never take focus from the terminal (see the container's
      // mousedown guard); it is reachable by tap, which is its whole point.
      tabIndex={-1}
      aria-label={title}
      aria-pressed={pressed}
      data-mod-state={state}
      title={title}
      onClick={onPress}
      className={
        `${TAP} flex flex-col items-center justify-center rounded-2 border px-0.5 font-medium leading-tight ` +
        "focus:outline-none active:bg-white/25 " +
        (cls ?? "border-white/10 text-white/85 hover:bg-white/10")
      }
    >
      <span
        className={
          "max-w-full truncate " + (wordLabel ? "text-[11px]" : "text-[13px]")
        }
      >
        {label}
      </span>
      {sub && (
        <span className="max-w-full truncate text-[9px] font-normal opacity-60">
          {sub}
        </span>
      )}
    </button>
  );
}
