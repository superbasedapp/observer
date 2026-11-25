/**
 * `@superbased/sdk/register` (plan 3.3): tracing for an ESM app with no code
 * change but the start command.
 *
 * ```sh
 * node --import @superbased/sdk/register server.js
 * ```
 *
 * or, in Next.js, `instrumentation.ts`:
 *
 * ```ts
 * export async function register() {
 *   if (process.env.NEXT_RUNTIME === "nodejs") await import("@superbased/sdk/register");
 * }
 * ```
 *
 * ESM imports are linked before any app code runs, so `init()` inside the app
 * cannot patch a library the app imported statically. This entry runs first:
 * it calls `init()` from the environment (the `instrument` setting is `auto`
 * unless SUPERBASED_INSTRUMENT says otherwise), then registers the
 * `import-in-the-middle` loader hook for exactly the modules of the targets
 * still waiting for their first load, and instruments each as it is
 * evaluated, through the same target rows `instrument()` uses. A CommonJS
 * `require` of a framework is still caught by init()'s own require hook.
 *
 * Nothing is wrapped when nothing is waiting (an app with its own
 * OpenTelemetry provider, `SUPERBASED_INSTRUMENT=off`, or no framework
 * installed). The loader hook is registered once per process.
 */

import { createRequire, register as registerLoader } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

import { diagnostics, init } from "./index.js";
import { esmLoaded, esmMatch, esmWatchList, setEsmHooked } from "./instrument.js";

const require = createRequire(import.meta.url);

/** What the register entry did (also on `registration()`). */
export interface Registration {
  /** The loader hook is in place. */
  hooked: boolean;
  /** The module specifiers it wraps. */
  modules: string[];
  /** Why it is not in place ("" when it is). */
  reason: string;
}

interface Iitm {
  addHook(hook: (name: string, namespace: unknown) => void): void;
}

const GLOBAL_KEY = Symbol.for("superbased.sdk.register");

function start(): Registration {
  const g = globalThis as Record<symbol, Registration | undefined>;
  const prior = g[GLOBAL_KEY];
  if (prior) return prior;
  setEsmHooked(true);
  try {
    init();
  } catch (err) {
    // A bad environment value must not stop the app from starting.
    console.warn(`@superbased/sdk/register: init() failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  const watch = esmWatchList();
  const modules = [...new Set(watch.map((w) => w.spec))];
  let out: Registration;
  if (modules.length === 0) {
    const d = diagnostics();
    out = { hooked: false, modules, reason: d.instrument === "off" ? "instrument is off" : d.notes.find((n) => n.includes("auto-instrumentation skipped")) ?? "nothing is waiting to load" };
  } else if (typeof registerLoader !== "function") {
    out = { hooked: false, modules, reason: "this Node has no module.register (Node 20.6+ needed)" };
  } else {
    try {
      const iitm = require("import-in-the-middle") as Iitm;
      const hookUrl = pathToFileURL(require.resolve("import-in-the-middle/hook.mjs")).href;
      registerLoader(hookUrl, import.meta.url, { data: { include: modules } });
      iitm.addHook((name, namespace) => {
        let path = name;
        if (name.startsWith("file:")) {
          try {
            path = fileURLToPath(name);
          } catch {
            return;
          }
        }
        const w = esmMatch(path, esmWatchList());
        if (w) esmLoaded(w, namespace);
      });
      out = { hooked: true, modules, reason: "" };
    } catch (err) {
      out = { hooked: false, modules, reason: `the loader hook could not be registered: ${err instanceof Error ? err.message : String(err)}` };
      console.warn(`@superbased/sdk/register: ${out.reason}; ESM model libraries are not instrumented`);
    }
  }
  g[GLOBAL_KEY] = out;
  return out;
}

const registration = start();

/** What this entry did: whether the loader hook is in place and for which modules. */
export function registered(): Registration {
  return { ...registration, modules: [...registration.modules] };
}
