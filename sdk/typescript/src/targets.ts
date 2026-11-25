/**
 * The instrument targets as plain data: one row per framework, with the
 * packages that mean "this app uses it" and whether `init()` may instrument it
 * on its own. `instrument.ts` adds the install half of each row; `setup`
 * reads the same rows to detect what a project uses (plan 3.5: one owner, so
 * a new framework is one row and both follow it).
 *
 * This module imports nothing, so the setup command can read it without
 * loading OpenTelemetry.
 */

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

/** One instrumentable framework, as data. */
export interface TargetInfo {
  name: InstrumentTarget;
  /** The instrumentation package (an optional peer dependency). */
  package: string;
  /** The framework module that must load. */
  library: string;
  /** npm packages whose presence in a project means the app uses this framework (setup's detection). */
  detect: readonly string[];
  /**
   * Whether `init()` instruments this target on its own (`instrument: "auto"`).
   * `false` = only when named: instrumenting it changes what the app does.
   */
  auto: boolean;
  /**
   * For a framework patched through several modules (MCP's transports): the
   * part name the install takes, mapped to the module that carries it.
   */
  parts?: Readonly<Record<string, string>>;
}

/** MCP's transport modules, by the name the instrumentation takes each under. */
export const MCP_MODULES = {
  clientStdioModule: "@modelcontextprotocol/sdk/client/stdio.js",
  serverStdioModule: "@modelcontextprotocol/sdk/server/stdio.js",
  clientSSEModule: "@modelcontextprotocol/sdk/client/sse.js",
  serverSSEModule: "@modelcontextprotocol/sdk/server/sse.js",
  clientStreamableHTTPModule: "@modelcontextprotocol/sdk/client/streamableHttp.js",
  serverStreamableHTTPModule: "@modelcontextprotocol/sdk/server/streamableHttp.js",
} as const;

/** The table, in the order `instrument()` walks it. */
export const TARGET_INFO: readonly TargetInfo[] = [
  { name: "openai", package: "@arizeai/openinference-instrumentation-openai", library: "openai", detect: ["openai"], auto: true },
  { name: "anthropic", package: "@arizeai/openinference-instrumentation-anthropic", library: "@anthropic-ai/sdk", detect: ["@anthropic-ai/sdk"], auto: true },
  {
    name: "langchain",
    package: "@arizeai/openinference-instrumentation-langchain",
    library: "@langchain/core/callbacks/manager",
    detect: ["@langchain/core"],
    auto: true,
  },
  {
    name: "mcp",
    package: "@arizeai/openinference-instrumentation-mcp",
    library: "@modelcontextprotocol/sdk/client/index.js",
    detect: ["@modelcontextprotocol/sdk"],
    auto: true,
    parts: MCP_MODULES,
  },
  { name: "vercel-ai", package: "@ai-sdk/otel", library: "ai", detect: ["ai"], auto: true },
  { name: "gemini", package: "@traceloop/instrumentation-google-generativeai", library: "@google/genai", detect: ["@google/genai"], auto: true },
  {
    name: "bedrock",
    package: "@arizeai/openinference-instrumentation-bedrock",
    library: "@aws-sdk/client-bedrock-runtime",
    detect: ["@aws-sdk/client-bedrock-runtime"],
    auto: true,
  },
  { name: "llama-index", package: "@traceloop/instrumentation-llamaindex", library: "llamaindex", detect: ["llamaindex"], auto: true },
  // Instrumenting the Agents SDK adds a trace processor to the app's own
  // tracing setup; it happens only when the app names it (plan 3.1).
  {
    name: "openai-agents",
    package: "@arizeai/openinference-instrumentation-openai-agents",
    library: "@openai/agents",
    detect: ["@openai/agents"],
    auto: false,
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
  openai_agents: "openai-agents",
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

/** The npm package a module specifier belongs to (`@scope/name/sub` is `@scope/name`). */
export function packageOf(spec: string): string {
  const parts = spec.split("/");
  return spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

/** A target name or alias, normalised; "" when it names no row. */
export function canonicalTarget(raw: string): InstrumentTarget | "" {
  const n = String(raw).trim().toLowerCase();
  const name = ALIASES[n] ?? n;
  return TARGET_INFO.some((t) => t.name === name) ? (name as InstrumentTarget) : "";
}
