// clipboard — ONE seam for reading from / writing to the system clipboard, with
// an honest report of *why* an operation could not happen (CLAUDE.md #2: one
// seam per integration point; the repo's honest-affordance convention: never
// show a control that silently does nothing).
//
// WHY THIS EXISTS AS A MODULE. Three call sites now need clipboard access with
// different failure tolerances — the embedded terminal's OSC 52 handler, its
// context-menu Copy/Paste, and its "copy visible output" button — and the
// browser exposes THREE different clipboard mechanisms with three different
// preconditions:
//
//   1. `navigator.clipboard.writeText` — async, needs a SECURE CONTEXT
//      (https:, or http://localhost / 127.0.0.1, which the browser treats as
//      trustworthy). Absent entirely on a plain-http LAN/IP origin: on such an
//      origin `navigator.clipboard` is `undefined`, not merely rejecting.
//   2. `document.execCommand("copy")` over a transient <textarea> — synchronous,
//      deprecated, but works on INSECURE origins and is the only write path
//      there. Requires a user-gesture-adjacent call stack in some browsers.
//   3. `navigator.clipboard.readText` — secure context AND an explicit
//      `clipboard-read` permission the user can deny. There is deliberately NO
//      fallback for READ: `execCommand("paste")` was removed from every engine
//      for the obvious reason, so a page cannot read the clipboard without the
//      user either granting permission or performing a real paste gesture
//      (Ctrl+V), which delivers the data through a `paste` ClipboardEvent
//      instead. Callers must degrade to "press Ctrl+V" rather than pretend.
//
// Every function here is side-effect-honest: it returns what happened, and the
// caller decides what to tell the operator. Nothing throws.

/** ClipboardWriteResult reports how (or whether) a write reached the clipboard. */
export type ClipboardWriteResult =
  /** Written via the async Clipboard API (secure context). */
  | "ok"
  /** Written via the execCommand fallback (works on an insecure origin). */
  | "ok-fallback"
  /** Nothing was written — no mechanism succeeded. */
  | "failed";

/** ClipboardReadResult is a read outcome: the text, or the reason there is none. */
export type ClipboardReadResult =
  | { ok: true; text: string }
  /** No `navigator.clipboard.readText` at all — insecure origin or old engine. */
  | { ok: false; reason: "unsupported" }
  /** The API exists but the read was refused (permission denied / not focused). */
  | { ok: false; reason: "denied" };

/**
 * clipboardWriteAvailable reports whether the ASYNC clipboard write path exists.
 *
 * False does NOT mean copying is impossible — `writeClipboard` still has the
 * execCommand fallback. It means the page is not in a secure context, which is
 * the fact worth naming in operator-facing copy.
 */
export function clipboardWriteAvailable(): boolean {
  return typeof navigator !== "undefined" && !!navigator.clipboard?.writeText;
}

/**
 * clipboardReadAvailable reports whether programmatic clipboard READ is even
 * offered by this browser/origin. When false, the only way to get clipboard
 * data into the page is a real paste gesture — say so rather than offering a
 * Paste control that cannot work.
 */
export function clipboardReadAvailable(): boolean {
  return typeof navigator !== "undefined" && !!navigator.clipboard?.readText;
}

/**
 * writeClipboard puts `text` on the system clipboard, preferring the async
 * Clipboard API and falling back to a transient-textarea `execCommand("copy")`
 * on origins where the async API is absent (plain-http LAN, a reverse proxy
 * without TLS, an old engine).
 *
 * Empty input is a no-op reported as "failed" — writing an empty string would
 * silently destroy whatever the operator had on their clipboard.
 *
 * FOCUS IS RESTORED. The fallback must focus a throwaway <textarea> to select
 * its contents; in the embedded terminal that would otherwise steal focus from
 * xterm's helper textarea and leave the terminal deaf to the keyboard. The
 * previously-focused element is captured and re-focused before returning.
 */
export async function writeClipboard(text: string): Promise<ClipboardWriteResult> {
  if (!text) return "failed";
  if (clipboardWriteAvailable()) {
    try {
      await navigator.clipboard.writeText(text);
      return "ok";
    } catch {
      // Permission denied, document not focused, or a transient engine error —
      // fall through to the legacy path, which is often still allowed.
    }
  }
  return writeClipboardFallback(text);
}

/**
 * writeClipboardFallback is the insecure-origin write path: select a detached
 * <textarea> and ask the document to copy the selection. Exported for tests and
 * for callers that must stay strictly synchronous inside a user gesture.
 */
export function writeClipboardFallback(text: string): ClipboardWriteResult {
  if (!text || typeof document === "undefined") return "failed";
  const active = document.activeElement as HTMLElement | null;
  const ta = document.createElement("textarea");
  ta.value = text;
  // Off-screen but NOT `display:none` / `hidden` — an unrendered element cannot
  // hold a selection, so the copy would be a no-op. `readOnly` keeps a mobile
  // soft keyboard from popping up during the round-trip.
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "-9999px";
  ta.style.left = "-9999px";
  ta.style.opacity = "0";
  ta.style.pointerEvents = "none";
  document.body.appendChild(ta);
  let ok = false;
  try {
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  } finally {
    ta.remove();
    // Give the keyboard back to whatever had it (the terminal, in practice).
    try {
      active?.focus?.();
    } catch {
      /* the previous element may have been removed — nothing to restore */
    }
  }
  return ok ? "ok-fallback" : "failed";
}

/**
 * readClipboard returns the clipboard's text, or the honest reason it cannot be
 * read. There is no fallback by design (see the module note) — a caller that
 * gets `unsupported`/`denied` should tell the operator to press Ctrl+V, which
 * routes the data through a native `paste` event instead and needs no
 * permission at all.
 */
export async function readClipboard(): Promise<ClipboardReadResult> {
  if (!clipboardReadAvailable()) return { ok: false, reason: "unsupported" };
  try {
    const text = await navigator.clipboard.readText();
    return { ok: true, text };
  } catch {
    return { ok: false, reason: "denied" };
  }
}

/**
 * decodeOsc52 turns an OSC 52 payload into the text a terminal application
 * asked to place on the clipboard, or null when the payload is not a clipboard
 * WRITE we should honour.
 *
 * Payload grammar (xterm / OSC 52, `ESC ] 52 ; <targets> ; <base64> BEL`):
 *   - `<targets>` selects the clipboard(s): c = CLIPBOARD, p = PRIMARY, s =
 *     "select", plus the numbered cut-buffers 0-7. Empty means "s0".
 *   - `<base64>` is the base64 of the UTF-8 bytes to store.
 *
 * TWO PAYLOADS ARE DELIBERATELY REFUSED (null):
 *   - `?` — a clipboard *read* request. Answering it would let any program
 *     running in the terminal (including one an agent was tricked into running)
 *     exfiltrate the operator's clipboard into its own stdin. xterm ships this
 *     disabled for the same reason; we never answer.
 *   - anything that is not valid base64 / not decodable as UTF-8.
 */
export function decodeOsc52(payload: string): string | null {
  const semi = payload.indexOf(";");
  if (semi < 0) return null;
  // Some emitters wrap long payloads; atob rejects any whitespace, so strip it
  // rather than dropping an otherwise-valid copy on the floor.
  const b64 = payload.slice(semi + 1).replace(/\s+/g, "");
  // Empty payload = a clipboard CLEAR request. Ignored deliberately: silently
  // wiping the operator's clipboard is not something a program in the terminal
  // gets to do.
  if (!b64 || b64 === "?") return null;
  try {
    // atob yields a binary string (one char per byte); re-assemble the original
    // UTF-8 bytes and decode, so non-ASCII copied text survives the round-trip.
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}
