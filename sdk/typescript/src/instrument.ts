/**
 * `instrument([...])`: framework auto-instrumentation over the upstream
 * OpenInference JS instrumentations, or OpenLLMetry's (Traceloop) where
 * OpenInference has no JS one (Gemini's `@google/genai`, LlamaIndex.TS)
 * (plan D10: depend on them, own only the wiring and the conformance
 * fixtures; contract sdk-api-surface.md section 10). CrewAI and Pydantic AI
 * are Python-only, so they have no row ({@link PYTHON_ONLY}).
 *
 * Each target is a row of {@link TARGETS}. The instrumentation packages are
 * optional peer dependencies: install the one you need next to the framework
 * (`npm i @arizeai/openinference-instrumentation-openai`). A missing package
 * or framework is reported, never thrown. The spans go through the SDK's
 * provider, so identity, sampling, masking and the destination apply to them
 * like to the SDK's own spans.
 *
 * CommonJS apps: `instrument()` patches the framework module `require`
 * returns, before or after your own `require`. ESM apps import their own
 * copy of the framework, so hand it over: `instrument(["openai"], { modules:
 * { openai: await import("openai") } })`. `vercel-ai` is an AI SDK v7
 * telemetry integration (Node 22+, ESM), registered with `registerTelemetry`;
 * the AI SDK's own spans already use the pinned GenAI semconv, so no
 * OpenInference layer is needed there.
 */

import { existsSync, realpathSync } from "node:fs";
import * as nodeModule from "node:module";
import { createRequire } from "node:module";
import { join, sep } from "node:path";

import { trace, type TracerProvider } from "@opentelemetry/api";

import { req } from "./req.js";
import { runtime } from "./runtime.js";
import { ALIASES, MCP_MODULES, PYTHON_ONLY, TARGET_INFO, packageOf, type InstrumentTarget, type TargetInfo } from "./targets.js";

export { ALIASES, PYTHON_ONLY, type InstrumentTarget } from "./targets.js";

export const INSTRUMENTED = "instrumented";
export const ALREADY = "already";
export const NOT_INSTALLED = "not-installed";
/** Installed; instrumented when the framework first loads (init()'s auto setting). */
export const PENDING = "pending";
/** Installed, but init() instruments it only when named (plan 3.1; sdk-api-surface.md section 14). */
export const AUTO_EXCLUDED = "skipped: auto_excluded";
/** init()'s auto setting with a provider the app registered: nothing is instrumented (row 3). */
export const SKIPPED_HOST_PROVIDER = "skipped: host_provider";
/** init()'s auto setting: the instrumentation package or the framework is not installed. */
export const SKIPPED_NOT_INSTALLED = "skipped: not_installed";

interface Ctx {
  provider: TracerProvider;
  /** The framework module(s) the caller handed over, if any. */
  module: unknown;
  /** The module came through the ESM loader hook, whose namespace can be written to. */
  patchable?: boolean;
}

interface Active {
  undo(): void;
}

/** One instrumentable framework: its data row (targets.ts) and how to install it. */
interface Target extends TargetInfo {
  note: string;
  /** Instrument; throws on failure. `null` = the host already did. */
  install(ctx: Ctx): Active | null;
}

/** The install half of a row; the data half comes from targets.ts by name. */
interface Impl {
  name: InstrumentTarget;
  note: string;
  install(ctx: Ctx): Active | null;
}

type Loaded = Record<string, unknown>;

/**
 * Load an optional peer (an instrumentation package, or a framework not
 * handed over): from this package's location first, then from the app's.
 *
 * The second look matters when the app installed the SDK from a folder
 * (`npm install ./sdk/typescript`): npm links the folder, Node resolves from
 * its real path, and the peers the app installed beside the framework are
 * not on that path. The app is found from its entry script, then the
 * working directory.
 */
function load(spec: string): Loaded {
  try {
    return req(spec) as Loaded;
  } catch (err) {
    if ((err as { code?: string }).code !== "MODULE_NOT_FOUND") throw err;
    for (const app of appRequires()) {
      try {
        return app(spec) as Loaded;
      } catch {
        // not there either; the original error says what is missing
      }
    }
    throw err;
  }
}

/** `require`s anchored at the app: its entry script's folder, then the working directory. */
function appRequires(): NodeJS.Require[] {
  const anchors: string[] = [];
  const entry = typeof process !== "undefined" ? process.argv?.[1] : undefined;
  if (entry) {
    try {
      anchors.push(realpathSync(entry));
    } catch {
      anchors.push(entry);
    }
  }
  if (typeof process !== "undefined" && typeof process.cwd === "function") anchors.push(join(process.cwd(), "noop.js"));
  const out: NodeJS.Require[] = [];
  for (const a of anchors) {
    try {
      out.push(createRequire(a));
    } catch {
      // an anchor that is not a path
    }
  }
  return out;
}

/** An OpenInference class instrumentation patched onto one framework module. */
function oiClass(name: InstrumentTarget, pkg: string, cls: string, library: string, note = ""): Impl {
  return {
    name,
    note,
    install({ provider, module }) {
      const mod = load(pkg);
      if (typeof mod.isPatched === "function" && (mod.isPatched as () => boolean)()) return null;
      const Cls = mod[cls] as new (o: object) => {
        manuallyInstrument(m: unknown): void;
        disable(): void;
        unpatch?(m: unknown): void;
        setTracerProvider?(p: TracerProvider): void;
      };
      const inst = new Cls({ tracerProvider: provider, instrumentationConfig: { enabled: false } });
      inst.setTracerProvider?.(provider);
      const target = module ?? load(library);
      inst.manuallyInstrument(target);
      return {
        undo() {
          inst.disable();
          // Some instrumentations' disable() leaves a manual patch in place (LangChain): unpatch it.
          if (typeof mod.isPatched === "function" && (mod.isPatched as () => boolean)()) inst.unpatch?.(target);
        },
      };
    },
  };
}

/**
 * An ESM module namespace is sealed: an instrumentation that replaces an
 * export (rather than patching a prototype) cannot write to it. Refuse with
 * the fix instead of a TypeError from deep inside the instrumentation.
 */
function writable(mod: unknown, what: string, spread: string): void {
  if (mod && typeof mod === "object" && (Object.prototype.toString.call(mod) === "[object Module]" || !Object.isExtensible(mod))) {
    throw new TypeError(
      `${what} is an ESM module namespace, which cannot be patched; hand over a copy and build the client from it: const m = { ...(await import("${spread}")) }; instrument([...], { modules: { ... m } }); new m.<Client>(...)`,
    );
  }
}

/** Call a method of an instrumentation that its types keep private (the unpatch half of a manual patch). */
function callPrivate(inst: object, method: string, ...args: unknown[]): void {
  const fn = (inst as Record<string, unknown>)[method];
  if (typeof fn === "function") (fn as (...a: unknown[]) => unknown).apply(inst, args);
}

/**
 * An OpenLLMetry (Traceloop) instrumentation: its constructor takes the plain
 * OTel InstrumentationConfig (no `tracerProvider` field), so the provider is
 * set afterwards. `enabled: false` keeps it from installing a require hook of
 * its own; the SDK patches the module it was handed (or `require` returns).
 */
interface Traceloop {
  setTracerProvider(p: TracerProvider): void;
  manuallyInstrument(...m: unknown[]): void;
  disable(): void;
}

function traceloop(pkg: string, cls: string, provider: TracerProvider): Traceloop {
  const Cls = load(pkg)[cls] as new (o: object) => Traceloop;
  const inst = new Cls({ enabled: false });
  inst.setTracerProvider(provider);
  return inst;
}

interface TelemetryHolder {
  AI_SDK_TELEMETRY_INTEGRATIONS?: unknown[];
}

/** The install half of each row, by target. */
const IMPLS: readonly Impl[] = [
  oiClass("openai", "@arizeai/openinference-instrumentation-openai", "OpenAIInstrumentation", "openai"),
  oiClass("anthropic", "@arizeai/openinference-instrumentation-anthropic", "AnthropicInstrumentation", "@anthropic-ai/sdk"),
  oiClass(
    "langchain",
    "@arizeai/openinference-instrumentation-langchain",
    "LangChainInstrumentation",
    "@langchain/core/callbacks/manager",
    "covers LangGraph (its runs are LangChain runs)",
  ),
  {
    name: "mcp",
    note: "carries trace context across MCP client and server transports, so server-side spans join the caller's trace",
    install({ module }) {
      const mod = load("@arizeai/openinference-instrumentation-mcp");
      const Cls = mod.MCPInstrumentation as new (o: object) => { manuallyInstrument(m: object): void; disable(): void };
      const inst = new Cls({ instrumentationConfig: { enabled: false } });
      const given = (module ?? {}) as Record<string, unknown>;
      const mods: Record<string, unknown> = {};
      for (const [k, spec] of Object.entries(MCP_MODULES)) {
        if (given[k]) mods[k] = given[k];
        else if (!module) {
          try {
            mods[k] = load(spec);
          } catch {
            // a transport this SDK version lacks
          }
        }
      }
      inst.manuallyInstrument(mods);
      return { undo: () => inst.disable() };
    },
  },
  {
    name: "vercel-ai",
    note: "AI SDK v7 (Node 22+): registers an @ai-sdk/otel telemetry integration, which emits the pinned GenAI semconv spans Observer reads natively",
    install({ provider, module }) {
      const given = (module ?? {}) as { ai?: Loaded; otel?: Loaded };
      const ai = given.ai ?? load("ai");
      const otel = given.otel ?? load("@ai-sdk/otel");
      const OpenTelemetry = otel.OpenTelemetry as new (o: object) => object;
      const integration = new OpenTelemetry({ tracer: provider.getTracer("ai"), usage: true, embedding: true, toolChoice: true });
      (ai.registerTelemetry as (i: object) => void)(integration);
      return {
        undo() {
          const list = (globalThis as TelemetryHolder).AI_SDK_TELEMETRY_INTEGRATIONS;
          const i = list?.indexOf(integration) ?? -1;
          if (list && i >= 0) list.splice(i, 1);
        },
      };
    },
  },
  {
    name: "gemini",
    note: "Google Gen AI SDK (@google/genai, Node 22+) over OpenLLMetry's instrumentation: generateContent and generateContentStream on clients built after instrument()",
    install({ provider, module, patchable }) {
      const genai = (module ?? load("@google/genai")) as Loaded;
      if (!patchable) writable(genai, "the @google/genai module", "@google/genai");
      const inst = traceloop("@traceloop/instrumentation-google-generativeai", "GenAIInstrumentation", provider);
      inst.manuallyInstrument(genai);
      return {
        undo() {
          callPrivate(inst, "unwrap", genai);
          inst.disable();
        },
      };
    },
  },
  {
    name: "bedrock",
    note: "AWS Bedrock Runtime (@aws-sdk/client-bedrock-runtime): InvokeModel, Converse and their streaming forms, patched on BedrockRuntimeClient.prototype.send",
    install({ provider, module }) {
      const mod = load("@arizeai/openinference-instrumentation-bedrock");
      if (typeof mod.isPatched === "function" && (mod.isPatched as () => boolean)()) return null;
      const Cls = mod.BedrockInstrumentation as new (o: object) => { manuallyInstrument(m: unknown): void; disable(): void; setTracerProvider?(p: TracerProvider): void };
      const inst = new Cls({ tracerProvider: provider, instrumentationConfig: { enabled: false } });
      inst.setTracerProvider?.(provider);
      const target = module ?? load("@aws-sdk/client-bedrock-runtime");
      inst.manuallyInstrument(target);
      return {
        undo() {
          inst.disable();
          if (typeof mod.isPatched === "function" && (mod.isPatched as () => boolean)()) callPrivate(inst, "unpatch", target);
        },
      };
    },
  },
  {
    name: "llama-index",
    note: "LlamaIndex.TS over OpenLLMetry's instrumentation: query and chat engines, retrievers, synthesizers, embeddings and every LLM class the module exports (and @llamaindex/openai's OpenAI when handed over as { llamaindex, openai })",
    install({ provider, module }) {
      const given = module as { llamaindex?: Loaded; openai?: Loaded } | undefined;
      const li = given?.llamaindex ?? (given && !("llamaindex" in given) && !("openai" in given) ? (given as Loaded) : load("llamaindex"));
      let oa = given?.openai;
      if (!oa && !given) {
        try {
          oa = load("@llamaindex/openai");
        } catch {
          // the OpenAI provider package is optional
        }
      }
      const inst = traceloop("@traceloop/instrumentation-llamaindex", "LlamaIndexInstrumentation", provider);
      inst.manuallyInstrument(li, oa);
      return {
        undo() {
          callPrivate(inst, "unpatch", li);
          if (oa) callPrivate(inst, "unpatchOpenAI", oa);
          inst.disable();
        },
      };
    },
  },
  {
    name: "openai-agents",
    note: "OpenAI Agents SDK (@openai/agents): an OpenInference tracing processor added beside the SDK's own processors (agent, generation, function-tool and handoff spans); the app's existing trace processors keep running",
    install({ provider, module }) {
      const mod = load("@arizeai/openinference-instrumentation-openai-agents");
      if (typeof mod.isPatched === "function" && (mod.isPatched as () => boolean)()) return null;
      const Cls = mod.OpenAIAgentsInstrumentation as new (o: object) => {
        manuallyInstrument(m: unknown, o?: object): void;
        uninstrument(): void;
        disable(): void;
      };
      const inst = new Cls({ tracerProvider: provider, exclusiveProcessor: false, instrumentationConfig: { enabled: false } });
      inst.manuallyInstrument(module ?? load("@openai/agents"), { exclusiveProcessor: false });
      return {
        undo() {
          inst.uninstrument();
          inst.disable();
        },
      };
    },
  },
];

/** The table: one row per target (targets.ts's data plus the install), walked in order. */
export const TARGETS: readonly Target[] = TARGET_INFO.map((info) => {
  const impl = IMPLS.find((i) => i.name === info.name);
  if (!impl) throw new Error(`@superbased/sdk: no install for target ${info.name}`);
  return { ...info, note: impl.note, install: impl.install };
});

const byName = new Map(TARGETS.map((t) => [t.name, t]));
const active = new Map<InstrumentTarget, Active>();

function names(targets: readonly string[] | undefined): InstrumentTarget[] {
  if (!targets) return TARGETS.map((t) => t.name);
  const out: InstrumentTarget[] = [];
  for (const raw of targets) {
    const n = String(raw).trim().toLowerCase();
    const name = (ALIASES[n] ?? n) as InstrumentTarget;
    if (PYTHON_ONLY[n]) throw new TypeError(`@superbased/sdk: ${PYTHON_ONLY[n]}`);
    if (!byName.has(name)) {
      const known = [...byName.keys(), ...Object.keys(ALIASES)].sort().join(", ");
      throw new TypeError(`@superbased/sdk: unknown instrument target ${JSON.stringify(raw)}; known: ${known}`);
    }
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

function missing(err: unknown): boolean {
  const code = (err as { code?: string }).code;
  return code === "MODULE_NOT_FOUND" || code === "ERR_MODULE_NOT_FOUND" || code === "ERR_PACKAGE_PATH_NOT_EXPORTED";
}

export interface InstrumentOptions {
  /**
   * The framework modules, for an ESM app (or to patch a specific copy):
   * `openai` (the namespace, `await import("openai")`), `anthropic`
   * (`@anthropic-ai/sdk`), `langchain` (`@langchain/core/callbacks/manager`),
   * `mcp` (`{ clientStreamableHTTPModule, serverStreamableHTTPModule, ... }`),
   * `vercel-ai` (`{ ai, otel }`: the `ai` and `@ai-sdk/otel` modules),
   * `gemini` (a COPY of `@google/genai`: `{ ...(await import("@google/genai")) }`,
   * then build `new copy.GoogleGenAI(...)` from it, because the instrumentation
   * replaces the class export), `bedrock` (`@aws-sdk/client-bedrock-runtime`),
   * `llama-index` (`{ llamaindex, openai }`: the `llamaindex` module and,
   * optionally, `@llamaindex/openai`), `openai-agents` (`@openai/agents`).
   */
  modules?: Partial<Record<InstrumentTarget, unknown>>;
  /** The provider the instrumentations write to (default: the SDK's, else the global one). */
  tracerProvider?: TracerProvider;
}

/** Install one target now; the status it reached. */
function installNow(t: Target, provider: TracerProvider, module: unknown, patchable = false): string {
  if (active.has(t.name)) return ALREADY;
  try {
    const got = t.install({ provider, module, patchable });
    if (got === null) return ALREADY; // the host instrumented it first
    active.set(t.name, got);
    return INSTRUMENTED;
  } catch (err) {
    if (missing(err)) return NOT_INSTALLED;
    const e = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    return `error: ${e}`.slice(0, 300);
  }
}

/**
 * Turn on auto-instrumentation for `targets` (`openai`, `anthropic`,
 * `langchain` (also `langgraph`), `mcp`, `vercel-ai`, `gemini`, `bedrock`,
 * `llama-index`, `openai-agents`); none given
 * instruments every installed one. Returns `{ target: status }`, status one
 * of `instrumented`, `already`, `not-installed` (install the
 * instrumentation package and the framework) or `error: <message>`. An
 * unknown target is a TypeError. Idempotent. `init()` already instruments
 * every installed target when the SDK owns the tracer provider (its
 * `instrument` option); call this to add one, or with `modules` for a copy
 * the app imported itself.
 */
export function instrument(targets?: readonly string[], opts: InstrumentOptions = {}): Record<string, string> {
  const list = names(targets ?? (opts.modules ? (Object.keys(opts.modules) as InstrumentTarget[]) : undefined));
  const provider = opts.tracerProvider ?? runtime.provider ?? trace.getTracerProvider();
  const out: Record<string, string> = {};
  for (const name of list) {
    // An explicit call wins over a wait for the first load.
    dropPending(name);
    out[name] = installNow(byName.get(name)!, provider, opts.modules?.[name]);
    if (name in statuses) statuses[name] = out[name];
  }
  return out;
}

/** Undo `instrument()` for `targets` (none given: every instrumented one), and stop waiting for any not loaded yet. Never throws for one that was not instrumented. */
export function uninstrument(targets?: readonly string[]): void {
  const list = targets ? names(targets) : [...new Set([...active.keys(), ...pending.keys()])];
  for (const name of list) {
    dropPending(name);
    fromInit.delete(name);
    const a = active.get(name);
    active.delete(name);
    try {
      a?.undo();
    } catch {
      // ignore
    }
  }
}

/** The targets instrumented now. */
export function instrumented(): InstrumentTarget[] {
  return [...active.keys()];
}

// --- init()'s instrument setting (plan 3.1) ------------------------------------

/** What `init({ instrument })` / SUPERBASED_INSTRUMENT resolved to. */
export interface InstrumentSetting {
  /** `auto`: every installed target with `auto` set; `off`: none; `list`: exactly `names`. */
  mode: "auto" | "off" | "list";
  names: InstrumentTarget[];
  /** `argument`, `env` or `default`. */
  source: "argument" | "env" | "default";
  /** Names in the environment list that were ignored, and why. */
  warnings: string[];
}

const OFF_WORDS = new Set(["off", "false", "0", "no", "none"]);
const AUTO_WORDS = new Set(["auto", "on", "true", "1", "yes"]);

/**
 * The instrument setting: the `instrument` option, then
 * SUPERBASED_INSTRUMENT, then `auto`. Values: `auto`, `off` (also `false`,
 * `0`), or a list of target names and aliases (an array, or a comma list).
 * An unknown name in the option is a TypeError, as in `instrument()`; in the
 * environment it is ignored with a warning, never fatal.
 */
export function resolveInstrumentSetting(explicit: unknown, env: Record<string, string | undefined>): InstrumentSetting {
  if (explicit !== undefined && explicit !== null) {
    if (explicit === true) return { mode: "auto", names: [], source: "argument", warnings: [] };
    if (explicit === false) return { mode: "off", names: [], source: "argument", warnings: [] };
    if (typeof explicit === "string") {
      const v = explicit.trim().toLowerCase();
      if (AUTO_WORDS.has(v)) return { mode: "auto", names: [], source: "argument", warnings: [] };
      if (OFF_WORDS.has(v)) return { mode: "off", names: [], source: "argument", warnings: [] };
      const list = names(v.split(",").map((x) => x.trim()).filter(Boolean));
      return list.length ? { mode: "list", names: list, source: "argument", warnings: [] } : { mode: "off", names: [], source: "argument", warnings: [] };
    }
    if (Array.isArray(explicit)) {
      const list = names(explicit.map(String));
      return list.length ? { mode: "list", names: list, source: "argument", warnings: [] } : { mode: "off", names: [], source: "argument", warnings: [] };
    }
    throw new TypeError(`@superbased/sdk: instrument must be "auto", "off" or a list of targets, not ${JSON.stringify(explicit)}`);
  }
  const raw = (env.SUPERBASED_INSTRUMENT ?? "").trim();
  const v = raw.toLowerCase();
  if (!v) return { mode: "auto", names: [], source: "default", warnings: [] };
  if (AUTO_WORDS.has(v)) return { mode: "auto", names: [], source: "env", warnings: [] };
  if (OFF_WORDS.has(v)) return { mode: "off", names: [], source: "env", warnings: [] };
  const out: InstrumentTarget[] = [];
  const warnings: string[] = [];
  for (const item of raw.split(",").map((x) => x.trim()).filter(Boolean)) {
    const n = item.toLowerCase();
    const name = (ALIASES[n] ?? n) as InstrumentTarget;
    const known = [...byName.keys(), ...Object.keys(ALIASES)].sort().join(", ");
    if (PYTHON_ONLY[n]) warnings.push(`SUPERBASED_INSTRUMENT names ${JSON.stringify(item)}: ${PYTHON_ONLY[n]}; skipped`);
    else if (!byName.has(name)) warnings.push(`SUPERBASED_INSTRUMENT names an unknown target ${JSON.stringify(item)}; skipped (known: ${known})`);
    else if (!out.includes(name)) out.push(name);
  }
  if (!out.length && !warnings.length) return { mode: "off", names: [], source: "env", warnings };
  return { mode: "list", names: out, source: "env", warnings };
}

/** The note init() logs when auto-instrumentation is skipped for a provider the app registered. */
export const AUTO_SKIPPED_NOTE =
  "auto-instrumentation skipped because the app registered its own OpenTelemetry provider; call instrument([...]) to add model-library spans";

/** A target waiting for its framework's first load. */
interface Pending {
  target: Target;
  provider: TracerProvider;
  /** CommonJS files whose first load fires the install (the library, and each part). */
  files: string[];
  /** Parts already installed through the ESM hook (multi-part targets). */
  partsDone: Set<string>;
}

const pending = new Map<InstrumentTarget, Pending>();
/** Targets init() instrumented (not the app's own instrument() calls): init's `off` undoes them. */
const fromInit = new Set<InstrumentTarget>();
/** Per target, what the last init() reached, kept current as pending ones load. */
let statuses: Record<string, string> = {};
let lastSetting: InstrumentSetting | null = null;
/** An ESM loader hook (`@superbased/sdk/register`) feeds esmLoaded(): named targets wait for their load too. */
let esmHooked = false;

/** Whether an npm package is installed where the SDK or the app would load it from (read from disk, nothing imported). */
export function packageInstalled(name: string): boolean {
  const lookups: string[] = [];
  for (const r of [req, ...appRequires()]) {
    try {
      lookups.push(...(r.resolve.paths(name) ?? []));
    } catch {
      // a require without paths
    }
  }
  return lookups.some((dir) => existsSync(join(dir, ...name.split("/"), "package.json")));
}

let installedCheck: ((t: TargetInfo) => boolean) | null = null;

/** Whether a target's instrumentation package and framework are both installed. */
function installed(t: TargetInfo): boolean {
  if (installedCheck) return installedCheck(t);
  return packageInstalled(t.package) && packageInstalled(packageOf(t.library));
}

/** Tests: decide "installed" by target name instead of the disk (null: the disk again). */
export function _setInstalledForTests(names: readonly string[] | null): void {
  installedCheck = names ? (t) => names.includes(t.name) : null;
}

/** The CommonJS file a module specifier resolves to (from the SDK, then the app), or "". Nothing is loaded. */
function resolveFile(spec: string): string {
  for (const r of [req, ...appRequires()]) {
    try {
      return r.resolve(spec);
    } catch {
      // not resolvable from here (or ESM-only)
    }
  }
  return "";
}

interface CachedModule {
  loaded?: boolean;
  exports?: unknown;
}

function cache(): Record<string, CachedModule | undefined> {
  return (req.cache ?? {}) as Record<string, CachedModule | undefined>;
}

/** The files a pending target watches: its library, and each of its parts. */
function watchFiles(t: Target): string[] {
  const specs = [t.library, ...Object.values(t.parts ?? {})];
  return [...new Set(specs.map(resolveFile).filter(Boolean))];
}

function dropPending(name: InstrumentTarget): void {
  pending.delete(name);
  if (pending.size === 0) unhookRequire();
}

/** Fire every pending target whose CommonJS file has finished loading. */
function checkPending(): void {
  if (pending.size === 0) return;
  const c = cache();
  for (const p of [...pending.values()]) {
    if (!p.files.some((f) => c[f]?.loaded)) continue;
    pending.delete(p.target.name);
    const lib = c[resolveFile(p.target.library)];
    // A multi-part target loads its parts itself; a single module is handed over.
    const module = p.target.parts ? undefined : lib?.loaded ? lib.exports : undefined;
    const st = installNow(p.target, p.provider, module);
    if (st === INSTRUMENTED || st === ALREADY) fromInit.add(p.target.name);
    statuses[p.target.name] = st;
  }
  if (pending.size === 0) unhookRequire();
}

type RequireFn = (this: unknown, id: string) => unknown;
let originalRequire: RequireFn | null = null;
let hookedRequire: RequireFn | null = null;
let firing = false;

function moduleProto(): { require: RequireFn } | null {
  const M = ((nodeModule as unknown as { Module?: unknown }).Module ?? (nodeModule as unknown as { default?: unknown }).default) as
    | { prototype?: { require: RequireFn } }
    | undefined;
  return M?.prototype && typeof M.prototype.require === "function" ? M.prototype : null;
}

/**
 * Watch CommonJS `require` for a pending framework's first load (Node
 * built-ins only: Module.prototype.require is wrapped while something is
 * pending, and put back when nothing is).
 */
function hookRequire(): void {
  if (hookedRequire) return;
  const proto = moduleProto();
  if (!proto) return;
  const orig = proto.require;
  originalRequire = orig;
  hookedRequire = function (this: unknown, id: string): unknown {
    const out = orig.call(this, id);
    if (!firing && pending.size) {
      firing = true;
      try {
        checkPending();
      } catch {
        // never break the app's require
      } finally {
        firing = false;
      }
    }
    return out;
  };
  proto.require = hookedRequire;
}

function unhookRequire(): void {
  const proto = moduleProto();
  if (proto && hookedRequire && proto.require === hookedRequire && originalRequire) proto.require = originalRequire;
  hookedRequire = null;
  originalRequire = null;
}

/** The framework module, when it is already loaded through CommonJS (undefined when not). */
function loadedNow(t: Target): { module: unknown } | undefined {
  const c = cache();
  const files = watchFiles(t);
  if (!files.some((f) => c[f]?.loaded)) return undefined;
  const lib = c[resolveFile(t.library)];
  return { module: t.parts ? undefined : lib?.loaded ? lib.exports : undefined };
}

/** Instrument now when the framework is loaded, else wait for its first load. */
function instrumentOrWait(t: Target, provider: TracerProvider, missing = NOT_INSTALLED): string {
  if (active.has(t.name)) return ALREADY;
  if (!installed(t)) return missing;
  const now = loadedNow(t);
  if (now) {
    const st = installNow(t, provider, now.module);
    if (st === INSTRUMENTED || st === ALREADY) fromInit.add(t.name);
    return st;
  }
  pending.set(t.name, { target: t, provider, files: watchFiles(t), partsDone: new Set() });
  hookRequire();
  return PENDING;
}

/**
 * Apply init()'s instrument setting (the plan 3.1 rule table, walked top
 * down):
 *
 * | # | setting | provider mode | result |
 * | 1 | off     | any           | nothing (what an earlier init() instrumented is undone) |
 * | 2 | a list  | any           | exactly those targets, as `instrument(list)` |
 * | 3 | auto    | attached, standalone | nothing, and the {@link AUTO_SKIPPED_NOTE}; each target reads `skipped: host_provider` |
 * | 4 | auto    | owned         | every installed target with `auto` set, now or on its first load; the others `skipped: auto_excluded` / `skipped: not_installed` |
 *
 * Returns the per-target status and the note ("" when none). Never throws.
 */
export function autoInstrument(setting: InstrumentSetting, mode: string, provider: TracerProvider): { statuses: Record<string, string>; note: string } {
  lastSetting = setting;
  statuses = {};
  let note = "";
  // Waits from an earlier init() are re-decided here.
  for (const name of [...pending.keys()]) dropPending(name);
  if (setting.mode === "off") {
    for (const name of [...fromInit]) uninstrument([name]);
  } else if (setting.mode === "list") {
    for (const name of setting.names) {
      const t = byName.get(name)!;
      // With the ESM hook in place a named target waits for its load too; without it, now.
      const st = esmHooked ? instrumentOrWait(t, provider) : installNow(t, provider, undefined);
      if (st === INSTRUMENTED || st === ALREADY) fromInit.add(name);
      statuses[name] = st;
    }
  } else if (mode !== "owned") {
    note = AUTO_SKIPPED_NOTE;
    for (const t of TARGETS) statuses[t.name] = SKIPPED_HOST_PROVIDER;
  } else {
    for (const t of TARGETS) {
      if (!t.auto) {
        statuses[t.name] = active.has(t.name) ? ALREADY : installed(t) ? AUTO_EXCLUDED : SKIPPED_NOT_INSTALLED;
        continue;
      }
      statuses[t.name] = instrumentOrWait(t, provider, SKIPPED_NOT_INSTALLED);
    }
  }
  return { statuses: { ...statuses }, note };
}

/** What the last init() reached per target, kept current as pending targets load (diagnostics). */
export function instrumentStatus(): Record<string, string> {
  return { ...statuses };
}

/** The setting the last init() applied (null before one). */
export function instrumentSetting(): InstrumentSetting | null {
  return lastSetting;
}

// --- the ESM loader hook's half (register.ts) ------------------------------------

/** One module the ESM hook waits for: the target, and the part it carries ("" = the whole target). */
export interface EsmWatch {
  target: InstrumentTarget;
  spec: string;
  part: string;
}

/** The module specifiers a pending target waits for (each part of a multi-part one). */
export function esmWatchList(): EsmWatch[] {
  const out: EsmWatch[] = [];
  for (const p of pending.values()) {
    const parts = p.target.parts;
    if (parts) {
      for (const [part, spec] of Object.entries(parts)) if (!p.partsDone.has(part)) out.push({ target: p.target.name, spec, part });
    } else {
      out.push({ target: p.target.name, spec: p.target.library, part: "" });
    }
  }
  return out;
}

/** Strip a JavaScript extension. */
function bare(p: string): string {
  return p.replace(/\.(m|c)?js$/, "");
}

/**
 * Which watched module a loaded file is: the package from the path's last
 * `node_modules` segment, then (when one package carries several watched
 * modules) the one whose sub-path the file's path ends with. Null when none.
 * Pure over its inputs.
 */
export function esmMatch(filePath: string, watch: readonly EsmWatch[]): EsmWatch | null {
  const norm = filePath.split(sep).join("/");
  const at = norm.lastIndexOf("/node_modules/");
  if (at < 0) return null;
  const rest = norm.slice(at + "/node_modules/".length).split("/");
  const pkg = rest[0]?.startsWith("@") ? rest.slice(0, 2).join("/") : rest[0];
  const rel = rest.slice(pkg.split("/").length).join("/");
  const same = watch.filter((w) => packageOf(w.spec) === pkg);
  if (same.length <= 1) return same[0] ?? null;
  for (const w of same) {
    const sub = bare(w.spec.slice(pkg.length + 1));
    if (sub && (bare(rel) === sub || bare(rel).endsWith("/" + sub))) return w;
  }
  return null;
}

/** register.ts: the ESM hook is in place, so named targets wait for their load as well. */
export function setEsmHooked(on: boolean): void {
  esmHooked = on;
}

/**
 * register.ts: a watched ESM module was evaluated; `ns` is its namespace as
 * the loader hook hands it over (writable). Installs the target (or the one
 * part) on it. Never throws.
 */
export function esmLoaded(w: EsmWatch, ns: unknown): void {
  const p = pending.get(w.target);
  if (!p) return;
  try {
    if (w.part) {
      if (p.partsDone.has(w.part)) return;
      p.partsDone.add(w.part);
      const got = p.target.install({ provider: p.provider, module: { [w.part]: ns }, patchable: true });
      if (got) {
        const prev = active.get(w.target);
        active.set(w.target, prev ? { undo: () => (prev.undo(), got.undo()) } : got);
      }
      fromInit.add(w.target);
      statuses[w.target] = active.has(w.target) ? INSTRUMENTED : ALREADY;
      if (Object.keys(p.target.parts ?? {}).every((k) => p.partsDone.has(k))) dropPending(w.target);
      return;
    }
    dropPending(w.target);
    const st = installNow(p.target, p.provider, ns, true);
    if (st === INSTRUMENTED || st === ALREADY) fromInit.add(w.target);
    statuses[w.target] = st;
  } catch {
    // never break the app's import
  }
}

/** Forget init()'s instrument state (tests only); instrumented targets stay. */
export function _resetInstrumentForTests(): void {
  installedCheck = null;
  for (const name of [...pending.keys()]) dropPending(name);
  fromInit.clear();
  statuses = {};
  lastSetting = null;
  esmHooked = false;
}
