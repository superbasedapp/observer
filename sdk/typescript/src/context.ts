/**
 * Per-request trace attributes (end user, session, tenant, tags, metadata,
 * release, environment) carried through async work with AsyncLocalStorage
 * (contract sdk-api-surface.md section 2).
 *
 * Every span started while attributes are in scope gets them, whether the
 * SDK, an `instrument()` instrumentation or your own OTel code started it:
 * the SDK's span processor stamps them at span start, never over a value the
 * span already carries. The span active when you call `identify` or
 * `propagateAttributes` gets the values you just set too.
 *
 * Merge rules (inner over outer): scalars, inner wins, `undefined` leaves
 * the outer value and `""` clears it; tags, union (trimmed, de-duplicated,
 * sorted, at most 32 of 128 chars); metadata, per key, inner wins, a `null`
 * value removes the key, non-strings JSON-encoded, at most 32 keys (the
 * lexically smallest kept), key 128 and value 512 chars. These are
 * `otelident.NormalizeTags` / `NormalizeMetadata`.
 */

import { AsyncLocalStorage } from "node:async_hooks";

import { trace, type AttributeValue } from "@opentelemetry/api";

import { K, LIMITS } from "./attrs.js";

/** Per-trace attributes: who and what a request belongs to. */
export interface TraceAttributes {
  /** The app's end user (PII; `sbo.user`). */
  user?: string;
  /** The app's conversation or user session (`session.id`). */
  sessionId?: string;
  /** The app's own customer / tenant (`sbo.tenant`). */
  tenant?: string;
  /** Tags (`sbo.tags`); unioned with tags already in scope. */
  tags?: string[];
  /** Metadata (`sbo.metadata.<key>`); merged over metadata already in scope. */
  metadata?: Record<string, unknown>;
  /** The app's release / build label (`sbo.release`). */
  release?: string;
  /** The app's deployment environment (`sbo.environment`). */
  environment?: string;
}

export interface PropagateOptions extends TraceAttributes {
  /**
   * Also carry the values in W3C baggage, so `inject()` sends them to
   * downstream services, which restore them in `continueTrace()`. Baggage
   * travels in request headers: only use it for values those services may see.
   */
  asBaggage?: boolean;
}

/** Option name -> span attribute, for the scalar options. */
export const SCALAR_KEYS = {
  user: K.user,
  sessionId: K.session,
  tenant: K.tenant,
  release: K.release,
  environment: K.environment,
} as const;
type ScalarName = keyof typeof SCALAR_KEYS;

const clamp = (v: string, n: number): string => {
  const t = v.trim();
  return t.length > n ? t.slice(0, n) : t;
};

/** otelident.NormalizeTags: trimmed, clamped, de-duplicated, sorted, capped. */
export function normalizeTags(...lists: Array<Iterable<unknown> | string | undefined | null>): string[] {
  const seen = new Set<string>();
  for (const l of lists) {
    if (!l) continue;
    const items = typeof l === "string" ? l.split(",") : [...l];
    for (const t of items) {
      const s = clamp(String(t), LIMITS.tagLen);
      if (s) seen.add(s);
    }
  }
  return [...seen].sort().slice(0, LIMITS.tags);
}

function metaValue(v: unknown): string {
  if (typeof v === "string") return v;
  try {
    const s = JSON.stringify(v);
    return s === undefined ? String(v) : s;
  } catch {
    return String(v);
  }
}

/** otelident.NormalizeMetadata, later maps winning; a null value removes the key. */
export function normalizeMetadata(...maps: Array<Record<string, unknown> | undefined | null>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of maps) {
    if (!m) continue;
    for (const [k, v] of Object.entries(m)) {
      const key = clamp(String(k), LIMITS.metadataKeyLen);
      if (!key) continue;
      if (v === null) {
        delete out[key];
        continue;
      }
      if (v === undefined) continue;
      out[key] = clamp(metaValue(v), LIMITS.metadataValueLen);
    }
  }
  const keys = Object.keys(out).sort();
  for (const k of keys.slice(LIMITS.metadataKeys)) delete out[k];
  return out;
}

/** An immutable set of per-request values (one level of nesting). */
export class Scope {
  constructor(
    readonly scalars: Readonly<Record<string, string>> = {},
    readonly tags: readonly string[] = [],
    readonly metadata: Readonly<Record<string, string>> = {},
    readonly baggage = false,
  ) {}

  /** This scope with `opts` on top. */
  merged(opts: PropagateOptions): Scope {
    const scalars: Record<string, string> = { ...this.scalars };
    for (const [name, key] of Object.entries(SCALAR_KEYS)) {
      const v = opts[name as ScalarName];
      if (v === undefined || v === null) continue;
      const s = clamp(String(v), LIMITS.valueLen);
      if (s) scalars[key] = s;
      else delete scalars[key]; // "" clears it for the inner scope
    }
    if (opts.metadata !== undefined && opts.metadata !== null && (typeof opts.metadata !== "object" || Array.isArray(opts.metadata))) {
      throw new TypeError("@superbased/sdk: metadata must be an object");
    }
    return new Scope(
      scalars,
      normalizeTags(this.tags, opts.tags),
      normalizeMetadata(this.metadata, opts.metadata),
      this.baggage || !!opts.asBaggage,
    );
  }

  /** The span attributes this scope writes. */
  attributes(): Record<string, AttributeValue> {
    const out: Record<string, AttributeValue> = { ...this.scalars };
    if (this.tags.length) out[K.tags] = [...this.tags];
    for (const [k, v] of Object.entries(this.metadata)) out[K.metadataPrefix + k] = v;
    return out;
  }

  /** The option-named view (`getCurrentAttributes`). */
  public(): TraceAttributes {
    const out: TraceAttributes = {};
    for (const [name, key] of Object.entries(SCALAR_KEYS)) {
      if (key in this.scalars) (out as Record<string, unknown>)[name] = this.scalars[key];
    }
    if (this.tags.length) out.tags = [...this.tags];
    if (Object.keys(this.metadata).length) out.metadata = { ...this.metadata };
    return out;
  }
}

const EMPTY = new Scope();
const store = new AsyncLocalStorage<Scope>();

export function currentScope(): Scope {
  return store.getStore() ?? EMPTY;
}

/** The span attributes in effect for a span started here. */
export function scopeAttributes(): Record<string, AttributeValue> {
  return currentScope().attributes();
}

/** The per-request values in effect here, by option name. */
export function getCurrentAttributes(): TraceAttributes {
  return currentScope().public();
}

/** Write the values just set onto the active span too (a root entered before the call is tagged). */
function applyToActiveSpan(scope: Scope, opts: TraceAttributes): void {
  try {
    const sp = trace.getActiveSpan();
    if (!sp || !sp.isRecording()) return;
    const attrs = scope.attributes();
    for (const [name, key] of Object.entries(SCALAR_KEYS)) {
      if (opts[name as ScalarName] && key in attrs) sp.setAttribute(key, attrs[key]);
    }
    if (opts.tags?.length && attrs[K.tags]) {
      const existing = ((sp as unknown as { attributes?: Record<string, unknown> }).attributes ?? {})[K.tags];
      sp.setAttribute(K.tags, normalizeTags(Array.isArray(existing) ? existing : [], attrs[K.tags] as string[]));
    }
    for (const k of Object.keys(opts.metadata ?? {})) {
      const key = K.metadataPrefix + clamp(String(k), LIMITS.metadataKeyLen);
      if (key in attrs) sp.setAttribute(key, attrs[key]);
    }
  } catch {
    // tagging must never break the caller
  }
}

/**
 * Run `fn` with `attrs` merged over the attributes already in scope. Every
 * span started inside, at any async depth, carries them. Returns `fn`'s value
 * (sync stays sync; a promise for an async `fn`).
 *
 * ```ts
 * app.post("/chat", (req, res) =>
 *   propagateAttributes({ user: req.user.id, sessionId: req.body.thread }, () => handle(req, res)));
 * ```
 */
export function propagateAttributes<T>(attrs: PropagateOptions, fn: () => T): T {
  const scope = currentScope().merged(attrs);
  return store.run(scope, () => {
    applyToActiveSpan(scope, attrs);
    return fn();
  });
}

/** The handle `identify()` returns. */
export interface AttributeScope {
  /** Undo this identify (restore what was in scope before it). */
  reset(): void;
}

/**
 * Set trace attributes for the rest of the current async context (the
 * remainder of this request handler and everything it awaits or starts),
 * and on the active span. Returns a handle whose `reset()` undoes it. Prefer
 * {@link propagateAttributes} when you can wrap the work in a callback.
 */
export function identify(attrs: TraceAttributes): AttributeScope {
  const before = store.getStore();
  const scope = currentScope().merged(attrs);
  store.enterWith(scope);
  applyToActiveSpan(scope, attrs);
  let done = false;
  return {
    reset() {
      if (done) return;
      done = true;
      store.enterWith(before ?? EMPTY);
    },
  };
}

/** Run `fn` with `scope` in effect (continueTrace). */
export function runWithScope<T>(scope: Scope, fn: () => T): T {
  return store.run(scope, fn);
}

/** Forget scoped attributes (tests only). */
export function _resetContextForTests(): void {
  store.enterWith(EMPTY);
}
