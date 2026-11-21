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

import { realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

import { trace, type TracerProvider } from "@opentelemetry/api";

import { req } from "./req.js";
import { runtime } from "./runtime.js";

export const INSTRUMENTED = "instrumented";
export const ALREADY = "already";
export const NOT_INSTALLED = "not-installed";

export type InstrumentTarget =
  | "openai"
  | "anthropic"
  | "langchain"
  | "mcp"
  | "vercel-ai"
  | "gemini"
  | "bedrock"
  | "llama-index"
  | "openai-agents";

interface Ctx {
  provider: TracerProvider;
  /** The framework module(s) the caller handed over, if any. */
  module: unknown;
}

interface Active {
  undo(): void;
}

/** One instrumentable framework. */
interface Target {
  name: InstrumentTarget;
  /** The instrumentation package (an optional peer dependency). */
  package: string;
  /** The framework module that must load. */
  library: string;
  note: string;
  /** Instrument; throws on failure. `null` = the host already did. */
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
function oiClass(name: InstrumentTarget, pkg: string, cls: string, library: string, note = ""): Target {
  return {
    name,
    package: pkg,
    library,
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

const MCP_MODULES = {
  clientStdioModule: "@modelcontextprotocol/sdk/client/stdio.js",
  serverStdioModule: "@modelcontextprotocol/sdk/server/stdio.js",
  clientSSEModule: "@modelcontextprotocol/sdk/client/sse.js",
  serverSSEModule: "@modelcontextprotocol/sdk/server/sse.js",
  clientStreamableHTTPModule: "@modelcontextprotocol/sdk/client/streamableHttp.js",
  serverStreamableHTTPModule: "@modelcontextprotocol/sdk/server/streamableHttp.js",
} as const;

interface TelemetryHolder {
  AI_SDK_TELEMETRY_INTEGRATIONS?: unknown[];
}

/** The table: one row per target, walked in order. */
export const TARGETS: readonly Target[] = [
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
    package: "@arizeai/openinference-instrumentation-mcp",
    library: "@modelcontextprotocol/sdk/client/index.js",
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
    package: "@ai-sdk/otel",
    library: "ai",
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
    package: "@traceloop/instrumentation-google-generativeai",
    library: "@google/genai",
    note: "Google Gen AI SDK (@google/genai, Node 22+) over OpenLLMetry's instrumentation: generateContent and generateContentStream on clients built after instrument()",
    install({ provider, module }) {
      const genai = (module ?? load("@google/genai")) as Loaded;
      writable(genai, "the @google/genai module", "@google/genai");
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
    package: "@arizeai/openinference-instrumentation-bedrock",
    library: "@aws-sdk/client-bedrock-runtime",
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
    package: "@traceloop/instrumentation-llamaindex",
    library: "llamaindex",
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
    package: "@arizeai/openinference-instrumentation-openai-agents",
    library: "@openai/agents",
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

/** Other names for a target. */
export const ALIASES: Readonly<Record<string, InstrumentTarget>> = {
  langgraph: "langchain",
  vercel: "vercel-ai",
  ai: "vercel-ai",
  google: "gemini",
  "google-genai": "gemini",
  "aws-bedrock": "bedrock",
  llamaindex: "llama-index",
  llama_index: "llama-index",
  agents: "openai-agents",
  "openai_agents": "openai-agents",
};

/**
 * Frameworks that exist only for Python, so this SDK has no row for them.
 * Asking for one is a TypeError naming the reason (not "unknown target").
 */
export const PYTHON_ONLY: Readonly<Record<string, string>> = {
  crewai: "CrewAI is a Python framework; there is no JavaScript CrewAI to instrument (use the Python SDK, superbased-sdk[crewai])",
  "pydantic-ai": "Pydantic AI is a Python framework; there is no JavaScript Pydantic AI to instrument (use the Python SDK)",
  pydantic_ai: "Pydantic AI is a Python framework; there is no JavaScript Pydantic AI to instrument (use the Python SDK)",
};

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

/**
 * Turn on auto-instrumentation for `targets` (`openai`, `anthropic`,
 * `langchain` (also `langgraph`), `mcp`, `vercel-ai`, `gemini`, `bedrock`,
 * `llama-index`, `openai-agents`); none given
 * instruments every installed one. Returns `{ target: status }`, status one
 * of `instrumented`, `already`, `not-installed` (install the
 * instrumentation package and the framework) or `error: <message>`. An
 * unknown target is a TypeError. Call after `init()`; idempotent.
 */
export function instrument(targets?: readonly string[], opts: InstrumentOptions = {}): Record<string, string> {
  const list = names(targets ?? (opts.modules ? (Object.keys(opts.modules) as InstrumentTarget[]) : undefined));
  const provider = opts.tracerProvider ?? runtime.provider ?? trace.getTracerProvider();
  const out: Record<string, string> = {};
  for (const name of list) {
    if (active.has(name)) {
      out[name] = ALREADY;
      continue;
    }
    const t = byName.get(name)!;
    try {
      const got = t.install({ provider, module: opts.modules?.[name] });
      if (got === null) {
        out[name] = ALREADY; // the host instrumented it first
        continue;
      }
      active.set(name, got);
      out[name] = INSTRUMENTED;
    } catch (err) {
      if (missing(err)) {
        out[name] = NOT_INSTALLED;
        continue;
      }
      const e = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
      out[name] = `error: ${e}`.slice(0, 300);
    }
  }
  return out;
}

/** Undo `instrument()` for `targets` (none given: every instrumented one). Never throws for one that was not instrumented. */
export function uninstrument(targets?: readonly string[]): void {
  const list = targets ? names(targets) : [...active.keys()];
  for (const name of list) {
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
