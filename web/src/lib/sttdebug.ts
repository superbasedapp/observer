// sttdebug: a development-only input-event trace overlay.
//
// Passively records the complete input-event pipeline for whatever
// field is focused on the page. It is the tool that diagnosed the
// 2026-07-23 dictation-paste bug (Wispr Flow's clipboard set -> Ctrl+V ->
// clipboard restore delivered the OLD clipboard into the xterm terminal
// but worked in the dashboard's Search box; docs/session-handoff.md "STT /
// dictation into terminals"), kept so a regression in terminal paste can
// be traced the same way.
//
// Dev builds only: main.tsx loads it behind `import.meta.env.DEV`, so
// production bundles (and the embedded dashboard) do not contain it.
//
// Enable with `?sttdebug=1` in the URL, or
// `localStorage.setItem("sbo_sttdebug", "1")`. No-op otherwise.
//
// Observation only: listeners are CAPTURE-phase on window (the terminal
// component calls stopPropagation on paste at an inner element, and
// window-capture fires before that). We never call preventDefault or
// stopPropagation.

let started = false;

/**
 * initSttDebug installs the diagnostic overlay + capture-phase event
 * listeners when enabled via query string or localStorage. It is a
 * no-op when disabled and idempotent when called more than once.
 */
export function initSttDebug(): void {
  if (started) return;
  if (typeof window === "undefined" || typeof document === "undefined") return;

  let enabled = false;
  try {
    enabled =
      new URLSearchParams(window.location.search).get("sttdebug") === "1" ||
      window.localStorage.getItem("sbo_sttdebug") === "1";
  } catch {
    enabled = false;
  }
  if (!enabled) return;
  started = true;

  const t0 = performance.now();
  const lines: string[] = [];

  const ts = (): string => ((performance.now() - t0) / 1).toFixed(1);

  // Excerpt: first 60 chars, JSON.stringify-escaped, plus total length
  // when truncated. e.g. '"hello wor…" (len 240)'.
  const excerpt = (v: unknown): string => {
    if (v === null || v === undefined) return String(v);
    const s = String(v);
    const head = s.slice(0, 60);
    let out = JSON.stringify(head);
    if (s.length > 60) {
      // Replace the closing quote with an ellipsis + closing quote.
      out = out.slice(0, -1) + "…\"";
      out += ` (len ${s.length})`;
    }
    return out;
  };

  const descriptor = (target: EventTarget | null): string => {
    const el = target as (Element & { tagName?: string }) | null;
    if (!el || typeof el.tagName !== "string") {
      return el ? String((el as unknown as { constructor?: { name?: string } }).constructor?.name ?? "?") : "null";
    }
    let d = el.tagName;
    if (el.id) d += "#" + el.id;
    else if (el.classList && el.classList.length > 0) d += "." + el.classList[0];
    return d;
  };

  const isTextField = (
    target: EventTarget | null,
  ): target is HTMLInputElement | HTMLTextAreaElement => {
    const el = target as Element | null;
    return (
      !!el &&
      (el.tagName === "INPUT" || el.tagName === "TEXTAREA")
    );
  };

  // ---- log sink + rendering ----------------------------------------

  let logEl: HTMLDivElement | null = null;
  let autoScroll = true;

  const render = (): void => {
    if (!logEl) return;
    const view = lines.slice(-200).join("\n");
    logEl.textContent = view;
    if (autoScroll) logEl.scrollTop = logEl.scrollHeight;
  };

  // Cap the backing buffer so a long-lived tab can't accumulate unbounded
  // captured input (codex review 2026-07-23, finding 3).
  const MAX_LINES = 5000;

  const log = (msg: string): void => {
    lines.push(`${ts()}  ${msg}`);
    if (lines.length > MAX_LINES) lines.splice(0, lines.length - MAX_LINES);
    render();
  };

  // ---- event handlers ----------------------------------------------

  const onKeydown = (e: KeyboardEvent): void => {
    if (!(e.ctrlKey || e.metaKey || e.key === "Insert")) return;
    const mods = [
      e.ctrlKey ? "ctrl" : "",
      e.metaKey ? "meta" : "",
      e.shiftKey ? "shift" : "",
      e.altKey ? "alt" : "",
    ]
      .filter(Boolean)
      .join("+");
    log(
      `keydown key=${JSON.stringify(e.key)} mods=[${mods}] tgt=${descriptor(e.target)}`,
    );
  };

  const onPaste = (e: ClipboardEvent): void => {
    let text = "";
    try {
      text = e.clipboardData?.getData("text/plain") ?? "";
    } catch {
      text = "<unavailable>";
    }
    log(`paste tgt=${descriptor(e.target)} text=${excerpt(text)}`);
  };

  const onBeforeInput = (e: InputEvent): void => {
    let sel = "";
    if (isTextField(e.target)) {
      sel = ` sel=[${e.target.selectionStart},${e.target.selectionEnd}]`;
    }
    log(
      `beforeinput type=${e.inputType} data=${excerpt(e.data)} comp=${e.isComposing} tgt=${descriptor(e.target)}${sel}`,
    );
  };

  const onInput = (e: Event): void => {
    const ie = e as InputEvent;
    let val = "";
    if (isTextField(e.target)) {
      val = ` val=${excerpt(e.target.value)} vlen=${e.target.value.length}`;
    }
    log(
      `input type=${ie.inputType} data=${excerpt(ie.data)} comp=${ie.isComposing} tgt=${descriptor(e.target)}${val}`,
    );
  };

  const onCompositionStart = (e: CompositionEvent): void => {
    log(`compositionstart data=${excerpt(e.data)} tgt=${descriptor(e.target)}`);
  };
  const onCompositionUpdate = (e: CompositionEvent): void => {
    log(`compositionupdate data=${excerpt(e.data)} tgt=${descriptor(e.target)}`);
  };
  const onCompositionEnd = (e: CompositionEvent): void => {
    log(`compositionend data=${excerpt(e.data)} tgt=${descriptor(e.target)}`);
  };

  const onFocusIn = (e: FocusEvent): void => {
    log(`focusin tgt=${descriptor(e.target)}`);
  };

  const cap = { capture: true } as const;
  window.addEventListener("keydown", onKeydown, cap);
  window.addEventListener("paste", onPaste, cap);
  window.addEventListener("beforeinput", onBeforeInput as EventListener, cap);
  window.addEventListener("input", onInput, cap);
  window.addEventListener("compositionstart", onCompositionStart, cap);
  window.addEventListener("compositionupdate", onCompositionUpdate, cap);
  window.addEventListener("compositionend", onCompositionEnd, cap);
  window.addEventListener("focusin", onFocusIn, cap);

  // ---- overlay UI (plain DOM) --------------------------------------

  const build = (): void => {
    const panel = document.createElement("div");
    panel.style.cssText = [
      "position:fixed",
      "left:8px",
      "bottom:8px",
      "z-index:2147483647",
      "width:440px",
      "max-width:440px",
      "max-height:40vh",
      "display:flex",
      "flex-direction:column",
      "background:rgba(10,12,18,0.92)",
      "color:#d6e2ff",
      "border:1px solid rgba(120,140,200,0.4)",
      "border-radius:6px",
      "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace",
      "font-size:10px",
      "line-height:1.35",
      "box-shadow:0 4px 18px rgba(0,0,0,0.5)",
    ].join(";");

    const header = document.createElement("div");
    header.style.cssText = [
      "display:flex",
      "align-items:center",
      "gap:4px",
      "padding:4px 6px",
      "border-bottom:1px solid rgba(120,140,200,0.3)",
      "flex:0 0 auto",
    ].join(";");

    const title = document.createElement("span");
    title.textContent = "STT debug";
    title.style.cssText = "flex:1;font-weight:bold;opacity:0.8";
    header.appendChild(title);

    const mkBtn = (label: string, onClick: () => void): HTMLButtonElement => {
      const b = document.createElement("button");
      b.textContent = label;
      b.style.cssText = [
        "font:inherit",
        "font-size:10px",
        "padding:1px 6px",
        "background:rgba(60,80,140,0.5)",
        "color:#e6eeff",
        "border:1px solid rgba(120,140,200,0.5)",
        "border-radius:3px",
        "cursor:pointer",
      ].join(";");
      // Never steal focus from the field under test.
      b.addEventListener("mousedown", (ev) => ev.preventDefault());
      b.addEventListener("click", onClick);
      return b;
    };

    const copyBtn = mkBtn("Copy", () => {
      const full = lines.join("\n");
      try {
        void navigator.clipboard.writeText(full);
        copyBtn.textContent = "Copied";
        window.setTimeout(() => (copyBtn.textContent = "Copy"), 1000);
      } catch {
        copyBtn.textContent = "err";
      }
    });
    const clearBtn = mkBtn("Clear", () => {
      lines.length = 0;
      render();
    });

    const pill = document.createElement("div");
    pill.textContent = "STT";
    pill.style.cssText = [
      "position:fixed",
      "left:8px",
      "bottom:8px",
      "z-index:2147483647",
      "padding:3px 8px",
      "background:rgba(10,12,18,0.92)",
      "color:#d6e2ff",
      "border:1px solid rgba(120,140,200,0.4)",
      "border-radius:6px",
      "font-family:ui-monospace,monospace",
      "font-size:10px",
      "cursor:pointer",
      "display:none",
    ].join(";");
    pill.addEventListener("mousedown", (ev) => ev.preventDefault());
    pill.addEventListener("click", () => {
      pill.style.display = "none";
      panel.style.display = "flex";
    });

    const hideBtn = mkBtn("Hide", () => {
      panel.style.display = "none";
      pill.style.display = "block";
    });

    header.appendChild(copyBtn);
    header.appendChild(clearBtn);
    header.appendChild(hideBtn);

    logEl = document.createElement("div");
    logEl.style.cssText = [
      "flex:1 1 auto",
      "overflow-y:auto",
      "white-space:pre-wrap",
      "word-break:break-word",
      "padding:4px 6px",
    ].join(";");
    logEl.addEventListener("scroll", () => {
      if (!logEl) return;
      const atBottom =
        logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 8;
      autoScroll = atBottom;
    });

    panel.appendChild(header);
    panel.appendChild(logEl);
    document.body.appendChild(panel);
    document.body.appendChild(pill);
    render();
  };

  if (document.body) build();
  else window.addEventListener("DOMContentLoaded", build, { once: true });

  log("sttdebug active");
}
