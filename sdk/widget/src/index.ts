/**
 * `<superbased-feedback>`: an end user's thumbs up / down, and an optional
 * comment, on one AI answer (plan W5-6). Framework-agnostic, no runtime
 * dependencies, keyboard and screen-reader accessible, themeable with CSS
 * variables.
 *
 * Security: the browser never holds a superbased SDK key. The widget only
 * dispatches a `superbased-feedback` event and, when `endpoint` is set,
 * POSTs to YOUR backend (same origin by default). Your backend calls the
 * SDK's `feedback()` with the trace and span id it rendered the answer
 * with. See the README for that server half in each SDK.
 *
 * ```html
 * <superbased-feedback trace-id="4bf9..." span-id="00f0..." endpoint="/api/feedback" comment="optional"></superbased-feedback>
 * <script type="module">import { defineFeedbackElement } from "@superbased/feedback-widget"; defineFeedbackElement();</script>
 * ```
 */

/** The custom element's default tag name. */
export const TAG = "superbased-feedback";
/** The event the widget dispatches (bubbles, composed, cancelable: `preventDefault()` skips the POST). */
export const FEEDBACK_EVENT = "superbased-feedback";
/** Dispatched after the POST answered 2xx (`detail`: the payload and the status). */
export const SENT_EVENT = "superbased-feedback-sent";
/** Dispatched when the POST failed (`detail`: the payload, the status (0 = no answer) and the error). */
export const ERROR_EVENT = "superbased-feedback-error";
/** The score name the SDK's `feedback()` uses by default. */
export const DEFAULT_NAME = "user_feedback";

/** The body the widget POSTs, and the `detail` of its event (snake_case, the SDKs' field names). */
export interface FeedbackPayload {
  /** The trace the answer belongs to (32 hex), as your server rendered it. */
  trace_id: string;
  /** The answer's span (16 hex), when your server gave one. */
  span_id?: string;
  /** true = thumbs up, false = thumbs down. */
  value: boolean;
  /** The end user's comment, when they wrote one. */
  comment?: string;
  /** The score name (default `user_feedback`). */
  name: string;
  /** An opaque value your server rendered with the answer (for example an HMAC of the trace id), passed through untouched. */
  token?: string;
}

/** Comment box: `off` (default), `optional` (offered after a vote) or `required` (a thumbs-down needs one). */
export type CommentMode = "off" | "optional" | "required";

/** The texts the widget shows; every one is an attribute (`question`, `label-up`, ...). */
export interface FeedbackTexts {
  question: string;
  labelUp: string;
  labelDown: string;
  commentLabel: string;
  commentPlaceholder: string;
  submit: string;
  skip: string;
  thanks: string;
  error: string;
  commentRequired: string;
  commentTooLong: string;
}

export const DEFAULT_TEXTS: Readonly<FeedbackTexts> = {
  question: "Was this answer helpful?",
  labelUp: "Helpful",
  labelDown: "Not helpful",
  commentLabel: "Tell us more (optional)",
  commentPlaceholder: "",
  submit: "Send",
  skip: "Skip",
  thanks: "Thanks for your feedback.",
  error: "Your feedback could not be sent.",
  commentRequired: "Please add a comment.",
  commentTooLong: "Your comment is too long.",
};

const TEXT_ATTRS: Record<keyof FeedbackTexts, string> = {
  question: "question",
  labelUp: "label-up",
  labelDown: "label-down",
  commentLabel: "comment-label",
  commentPlaceholder: "comment-placeholder",
  submit: "submit-label",
  skip: "skip-label",
  thanks: "thanks",
  error: "error-text",
  commentRequired: "comment-required-text",
  commentTooLong: "comment-too-long-text",
};

const TRACE = /^[0-9a-f]{32}$/;
const SPAN = /^[0-9a-f]{16}$/;
const NAME = /^[a-z0-9_.-]{1,64}$/;
/** The SDKs' comment bound (scores.md: up to 2,000 bytes). */
export const MAX_COMMENT_BYTES = 2000;

/** Why a payload cannot be sent ("" when it can). The same rules the SDKs apply to `feedback()`. */
/** A comment's size in UTF-8 bytes, the unit the SDKs bound it in. */
export function commentBytes(comment: string): number {
  return new TextEncoder().encode(comment).length;
}

export function validatePayload(p: FeedbackPayload): string {
  if (!TRACE.test(p.trace_id) || /^0+$/.test(p.trace_id)) return "trace-id must be 32 lowercase hex characters, not all zero";
  if (p.span_id !== undefined && (!SPAN.test(p.span_id) || /^0+$/.test(p.span_id))) return "span-id must be 16 lowercase hex characters";
  if (typeof p.value !== "boolean") return "value must be true or false";
  if (!NAME.test(p.name)) return "name must be 1-64 chars of a-z 0-9 _ . -";
  if (p.comment !== undefined && commentBytes(p.comment) > MAX_COMMENT_BYTES) return `comment is over ${MAX_COMMENT_BYTES} bytes`;
  return "";
}

/**
 * Whether `endpoint` may be posted to from `origin`: relative and same-origin
 * URLs always; another origin only with `allowCrossOrigin` (the trace id and
 * the comment are the app's data, so they go to the app's own backend by
 * default). Never a non-http(s) scheme.
 */
export function endpointAllowed(endpoint: string, origin: string, allowCrossOrigin = false): boolean {
  let u: URL;
  try {
    u = new URL(endpoint, origin);
  } catch {
    return false;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  return allowCrossOrigin || u.origin === origin;
}

/** The theme variables (set them on the element or any ancestor). */
export const CSS_VARIABLES = [
  "--sb-feedback-font",
  "--sb-feedback-fg",
  "--sb-feedback-muted",
  "--sb-feedback-bg",
  "--sb-feedback-border",
  "--sb-feedback-accent",
  "--sb-feedback-accent-fg",
  "--sb-feedback-radius",
  "--sb-feedback-gap",
  "--sb-feedback-focus",
  "--sb-feedback-error",
] as const;

const STYLE = `
:host { display: inline-block; font: var(--sb-feedback-font, inherit); color: var(--sb-feedback-fg, inherit); }
:host([hidden]) { display: none; }
.root { display: flex; flex-direction: column; gap: var(--sb-feedback-gap, 0.5em); }
.row { display: flex; align-items: center; gap: var(--sb-feedback-gap, 0.5em); flex-wrap: wrap; }
.question { color: var(--sb-feedback-muted, inherit); }
button { font: inherit; color: inherit; cursor: pointer; background: var(--sb-feedback-bg, transparent);
  border: 1px solid var(--sb-feedback-border, currentColor); border-radius: var(--sb-feedback-radius, 0.5em);
  padding: 0.25em 0.6em; min-width: 2.75em; min-height: 2.75em; }
button[aria-pressed="true"], button.primary { background: var(--sb-feedback-accent, #2b6cb0); color: var(--sb-feedback-accent-fg, #fff);
  border-color: var(--sb-feedback-accent, #2b6cb0); }
button:disabled { cursor: default; opacity: 0.6; }
button:focus-visible, textarea:focus-visible { outline: 2px solid var(--sb-feedback-focus, #2b6cb0); outline-offset: 2px; }
textarea { font: inherit; color: inherit; background: var(--sb-feedback-bg, transparent); width: 100%; box-sizing: border-box;
  border: 1px solid var(--sb-feedback-border, currentColor); border-radius: var(--sb-feedback-radius, 0.5em); padding: 0.4em; min-height: 4em; }
.status { min-height: 1.2em; }
.status.error, .hint { color: var(--sb-feedback-error, #c53030); }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
`;

/** One constructed sheet per document (a sheet is adoptable only in the document that built it). */
const sheets = new WeakMap<Document, CSSStyleSheet>();

/**
 * Put the styles on the shadow root without inline CSS where the browser
 * can: a constructed stylesheet (`adoptedStyleSheets`) is not inline style,
 * so a strict `style-src` Content Security Policy allows it. Older browsers
 * get a `<style>` element carrying the element's `nonce` attribute, which a
 * nonce-based policy allows. Returns which one it used.
 */
export function applyStyles(root: ShadowRoot, nonce: string | null): "adopted" | "style" {
  const doc = root.ownerDocument;
  const Sheet = (doc.defaultView as (Window & { CSSStyleSheet?: typeof CSSStyleSheet }) | null)?.CSSStyleSheet;
  const canAdopt = "adoptedStyleSheets" in root && typeof Sheet === "function" && typeof (Sheet.prototype as { replaceSync?: unknown }).replaceSync === "function";
  if (canAdopt) {
    try {
      let sheet = sheets.get(doc);
      if (!sheet) {
        sheet = new Sheet();
        sheet.replaceSync(STYLE);
        sheets.set(doc, sheet);
      }
      const own = sheet;
      root.adoptedStyleSheets = [...root.adoptedStyleSheets.filter((x) => x !== own), own];
      return "adopted";
    } catch {
      // fall through to the element
    }
  }
  const el = root.ownerDocument.createElement("style");
  if (nonce) el.setAttribute("nonce", nonce);
  el.textContent = STYLE;
  root.prepend(el);
  return "style";
}

type FetchLike = (input: string, init: RequestInit) => Promise<{ ok: boolean; status: number }>;

/* A base class that also loads where there is no DOM (server rendering, Node): the element is only defined in a browser. */
const Base: typeof HTMLElement = (typeof HTMLElement !== "undefined" ? HTMLElement : class {}) as typeof HTMLElement;

let seq = 0;

/**
 * The element. Attributes: `trace-id` (required), `span-id`, `endpoint`,
 * `name` (default `user_feedback`), `comment` (`off` | `optional` |
 * `required`), `token`, `cross-origin` (allow an endpoint on another
 * origin), `credentials` (`same-origin` default, `include`, `omit`),
 * `disabled`, `nonce` (for a nonce-based CSP in browsers without
 * constructable stylesheets), and the texts (`question`, `label-up`,
 * `label-down`, `comment-label`, `comment-placeholder`, `submit-label`,
 * `skip-label`, `thanks`, `error-text`, `comment-required-text`,
 * `comment-too-long-text`). Properties: `fetch` (a
 * fetch to use instead of the global one), `value` (the vote, or null),
 * `reset()`.
 */
export class FeedbackElement extends Base {
  static get observedAttributes(): string[] {
    return ["trace-id", "span-id", "comment", "disabled", ...Object.values(TEXT_ATTRS)];
  }

  /** A fetch to use instead of the global one (tests, an app's own client). */
  fetch: FetchLike | null = null;

  private vote: boolean | null = null;
  private stage: "vote" | "comment" | "sending" | "done" | "error" = "vote";
  private lastPayload: FeedbackPayload | null = null;
  private readonly uid = `sbf${++seq}`;
  private built = false;

  /** The end user's vote (true up, false down), or null before one. */
  get value(): boolean | null {
    return this.vote;
  }

  /** Back to the start (for example when the element is reused for another answer). */
  reset(): void {
    this.vote = null;
    this.stage = "vote";
    this.lastPayload = null;
    this.render();
  }

  connectedCallback(): void {
    if (!this.built) this.build();
    this.render();
  }

  attributeChangedCallback(name: string, oldValue: string | null, newValue: string | null): void {
    if (oldValue === newValue || !this.built) return;
    if (name === "trace-id" || name === "span-id") this.vote = null; // a new answer: a new vote
    if (name === "trace-id" || name === "span-id") this.stage = "vote";
    this.render();
  }

  private texts(): FeedbackTexts {
    const out = { ...DEFAULT_TEXTS };
    for (const [k, attr] of Object.entries(TEXT_ATTRS) as [keyof FeedbackTexts, string][]) {
      const v = this.getAttribute(attr);
      if (v !== null) out[k] = v;
    }
    if (this.commentMode() === "required" && this.getAttribute("comment-label") === null) out.commentLabel = "Tell us more";
    return out;
  }

  private commentMode(): CommentMode {
    const m = (this.getAttribute("comment") ?? "off").trim().toLowerCase();
    return m === "optional" || m === "required" ? m : "off";
  }

  private $(sel: string): HTMLElement {
    return this.shadowRoot!.querySelector(sel) as HTMLElement;
  }

  private build(): void {
    const root = this.shadowRoot ?? this.attachShadow({ mode: "open" });
    const id = this.uid;
    root.innerHTML = `<div class="root" part="root">
  <div class="row" role="group" aria-labelledby="${id}-q" part="vote">
    <span class="question" id="${id}-q" part="question"></span>
    <button type="button" class="up" part="button up" aria-pressed="false"><span aria-hidden="true">&#x1F44D;</span><span class="sr up-label"></span></button>
    <button type="button" class="down" part="button down" aria-pressed="false"><span aria-hidden="true">&#x1F44E;</span><span class="sr down-label"></span></button>
  </div>
  <form class="comment" part="comment" hidden novalidate>
    <label for="${id}-c" class="comment-label" part="comment-label"></label>
    <textarea id="${id}-c" part="textarea" maxlength="${MAX_COMMENT_BYTES}" aria-describedby="${id}-h"></textarea>
    <span class="hint" id="${id}-h" part="hint" aria-live="assertive"></span>
    <div class="row">
      <button type="submit" class="primary send" part="button submit"></button>
      <button type="button" class="skip" part="button skip"></button>
    </div>
  </form>
  <div class="status" part="status" role="status" aria-live="polite"></div>
</div>`;
    applyStyles(root, this.getAttribute("nonce"));
    this.$(".up").addEventListener("click", () => this.choose(true));
    this.$(".down").addEventListener("click", () => this.choose(false));
    const form = this.$(".comment") as HTMLFormElement;
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      this.submitComment(false);
    });
    this.$(".skip").addEventListener("click", () => this.submitComment(true));
    const ta = this.$("textarea") as HTMLTextAreaElement;
    // maxlength counts characters; the bound is bytes, so say so as they type.
    ta.addEventListener("input", () => this.checkLength());
    ta.addEventListener("keydown", (e) => {
      const k = e as KeyboardEvent;
      if (k.key === "Escape") {
        k.preventDefault();
        this.submitComment(true);
      } else if (k.key === "Enter" && (k.ctrlKey || k.metaKey)) {
        k.preventDefault();
        this.submitComment(false);
      }
    });
    this.built = true;
  }

  private render(): void {
    if (!this.built) return;
    const t = this.texts();
    const disabled = this.hasAttribute("disabled") || this.stage === "sending" || this.stage === "done";
    this.$(".question").textContent = t.question;
    for (const [cls, label, on] of [
      ["up", t.labelUp, this.vote === true],
      ["down", t.labelDown, this.vote === false],
    ] as const) {
      const b = this.$(`.${cls}`) as HTMLButtonElement;
      b.setAttribute("aria-pressed", String(on));
      b.setAttribute("aria-label", label);
      b.title = label;
      (this.$(`.${cls}-label`) as HTMLElement).textContent = label;
      b.disabled = disabled;
    }
    const form = this.$(".comment") as HTMLFormElement;
    form.hidden = this.stage !== "comment";
    this.$(".comment-label").textContent = t.commentLabel;
    const ta = this.$("textarea") as HTMLTextAreaElement;
    ta.placeholder = t.commentPlaceholder;
    const required = this.commentMode() === "required" && this.vote === false;
    if (required) ta.setAttribute("aria-required", "true");
    else ta.removeAttribute("aria-required");
    this.$(".send").textContent = t.submit;
    const skip = this.$(".skip") as HTMLButtonElement;
    skip.textContent = t.skip;
    skip.hidden = required;
    const status = this.$(".status");
    status.classList.toggle("error", this.stage === "error");
    status.textContent = this.stage === "done" ? t.thanks : this.stage === "error" ? t.error : "";
  }

  private choose(value: boolean): void {
    if (this.hasAttribute("disabled") || this.stage === "sending" || this.stage === "done") return;
    this.vote = value;
    this.$(".hint").textContent = "";
    if (this.commentMode() === "off") {
      void this.send(undefined);
      return;
    }
    this.stage = "comment";
    this.render();
    (this.$("textarea") as HTMLTextAreaElement).focus();
  }

  /** Mark the comment invalid while it is over the byte bound; true when it fits. */
  private checkLength(): boolean {
    const ta = this.$("textarea") as HTMLTextAreaElement;
    const over = commentBytes(ta.value.trim()) > MAX_COMMENT_BYTES;
    if (over) {
      ta.setAttribute("aria-invalid", "true");
      this.$(".hint").textContent = this.texts().commentTooLong;
    } else if (this.$(".hint").textContent === this.texts().commentTooLong) {
      ta.removeAttribute("aria-invalid");
      this.$(".hint").textContent = "";
    }
    return !over;
  }

  private submitComment(skip: boolean): void {
    if (this.stage !== "comment" || this.vote === null) return;
    const ta = this.$("textarea") as HTMLTextAreaElement;
    const text = skip ? "" : ta.value.trim();
    if (!skip && !this.checkLength()) {
      ta.focus();
      return; // the end user shortens it; the vote is kept
    }
    if (!text && this.commentMode() === "required" && this.vote === false) {
      if (skip) return; // a required comment cannot be skipped
      this.$(".hint").textContent = this.texts().commentRequired;
      ta.setAttribute("aria-invalid", "true");
      ta.focus();
      return;
    }
    ta.removeAttribute("aria-invalid");
    void this.send(text || undefined);
  }

  /** Build the payload from the attributes; null (with an error event) when it cannot be sent. */
  private payload(comment: string | undefined): FeedbackPayload | null {
    const p: FeedbackPayload = {
      trace_id: (this.getAttribute("trace-id") ?? "").trim().toLowerCase(),
      value: this.vote as boolean,
      name: (this.getAttribute("name") ?? DEFAULT_NAME).trim().toLowerCase(),
    };
    const span = (this.getAttribute("span-id") ?? "").trim().toLowerCase();
    if (span) p.span_id = span;
    if (comment) p.comment = comment;
    const token = this.getAttribute("token");
    if (token) p.token = token;
    const why = validatePayload(p);
    if (why) {
      this.fail(p, 0, why);
      return null;
    }
    return p;
  }

  private fail(p: FeedbackPayload, status: number, error: string): void {
    this.stage = "error";
    this.render();
    this.dispatchEvent(new CustomEvent(ERROR_EVENT, { bubbles: true, composed: true, detail: { payload: p, status, error } }));
  }

  private async send(comment: string | undefined): Promise<void> {
    const p = this.payload(comment);
    if (!p) return;
    this.lastPayload = p;
    const go = this.dispatchEvent(new CustomEvent(FEEDBACK_EVENT, { bubbles: true, composed: true, cancelable: true, detail: p }));
    const endpoint = this.getAttribute("endpoint");
    if (!go || !endpoint) {
      // The app handles the event itself (or asked the widget not to POST).
      this.stage = "done";
      this.render();
      return;
    }
    const origin = typeof location !== "undefined" ? location.origin : "http://localhost";
    if (!endpointAllowed(endpoint, origin, this.hasAttribute("cross-origin"))) {
      this.fail(p, 0, `endpoint ${endpoint} is not on this page's origin (add the cross-origin attribute to allow it)`);
      return;
    }
    this.stage = "sending";
    this.render();
    const f: FetchLike | null = this.fetch ?? (typeof fetch === "function" ? (i, n) => fetch(i, n) : null);
    if (!f) {
      this.fail(p, 0, "no fetch available");
      return;
    }
    const cred = this.getAttribute("credentials");
    try {
      const resp = await f(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(p),
        credentials: cred === "include" || cred === "omit" ? cred : "same-origin",
        redirect: "error",
      });
      if (!resp.ok) {
        this.fail(p, resp.status, `HTTP ${resp.status}`);
        return;
      }
      this.stage = "done";
      this.render();
      this.dispatchEvent(new CustomEvent(SENT_EVENT, { bubbles: true, composed: true, detail: { payload: p, status: resp.status } }));
    } catch (err) {
      this.fail(p, 0, err instanceof Error ? err.message : String(err));
    }
  }

  /** Send the last vote again after an error (no-op otherwise). */
  retry(): void {
    if (this.stage !== "error" || !this.lastPayload) return;
    this.vote = this.lastPayload.value;
    void this.send(this.lastPayload.comment);
  }
}

/**
 * Register the element (idempotent; a no-op where there is no
 * `customElements`, such as server rendering). Returns the tag name.
 */
export function defineFeedbackElement(tag: string = TAG): string {
  const reg = typeof customElements !== "undefined" ? customElements : null;
  if (reg && !reg.get(tag)) reg.define(tag, tag === TAG ? FeedbackElement : class extends FeedbackElement {});
  return tag;
}
