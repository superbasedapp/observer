/**
 * Model client libraries that trace themselves.
 *
 * Some provider SDKs start an OpenTelemetry span for every API call on the
 * global tracer provider (the Anthropic SDKs, `ANTHROPIC_OPEN_TELEMETRY`).
 * `init()` registers that provider, so under a framework instrumentation
 * (LangChain, LlamaIndex, the Vercel AI SDK) or a manual LLM span every call
 * would be recorded twice and counted twice. `instrument(["anthropic"])`
 * records the raw calls on its own.
 *
 * So `init()` turns such a library's own tracing off when the app has not set
 * its switch, and the export policy drops spans from its tracer scope (a
 * client built before `init()` read the switch already). An app that sets the
 * switch to anything other than its "off" value keeps the library's spans.
 */

export type VendorTracing = "off" | "kept";

interface SelfTracing {
  name: string;
  /** The switch the library reads when a client is built. */
  env: string;
  /** The switch value that turns its spans off. */
  off: string;
  /** Its tracer's instrumentation scope. */
  scopePrefix: string;
}

export const SELF_TRACING_LIBRARIES: readonly SelfTracing[] = [
  { name: "anthropic", env: "ANTHROPIC_OPEN_TELEMETRY", off: "false", scopePrefix: "com.anthropic.sdk" },
];

// name -> the app's own value of the switch, captured at the first init()
// (undefined: unset). Later init() calls see the value the SDK wrote.
const appValue = new Map<string, string | undefined>();

function env(): Record<string, string | undefined> {
  return (typeof process !== "undefined" ? process.env : {}) as Record<string, string | undefined>;
}

/** Turn each library's own tracing off unless the app set its switch. */
export function applyVendorTracing(): Record<string, VendorTracing> {
  const e = env();
  const out: Record<string, VendorTracing> = {};
  for (const lib of SELF_TRACING_LIBRARIES) {
    if (!appValue.has(lib.name)) appValue.set(lib.name, e[lib.env]);
    const app = appValue.get(lib.name);
    if (app === undefined) {
      e[lib.env] = lib.off;
      out[lib.name] = "off";
    } else {
      out[lib.name] = app.trim().toLowerCase() === lib.off ? "off" : "kept";
    }
  }
  return out;
}

/** The tracer scopes whose spans the export policy drops. */
export function dropScopePrefixes(state: Record<string, VendorTracing>): string[] {
  return SELF_TRACING_LIBRARIES.filter((l) => state[l.name] === "off").map((l) => l.scopePrefix);
}

/** Restore the switches the SDK wrote (tests only). */
export function resetVendorTracingForTests(): void {
  const e = env();
  for (const lib of SELF_TRACING_LIBRARIES) {
    if (!appValue.has(lib.name)) continue;
    const app = appValue.get(lib.name);
    appValue.delete(lib.name);
    if (app === undefined) delete e[lib.env];
    else e[lib.env] = app;
  }
}
