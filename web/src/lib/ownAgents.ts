// Own agents (P-228, docs/own-agents.md): the setup snippets the Sessions
// page's Own agents view prints. A developer points their own agent's
// provider base URL at the node proxy and sends X-Superbased-Agent (and,
// optionally, X-Session-Id); the proxy turns that into a custom-agent
// session. Pure string building so the snippets are testable without React.

export type SnippetLang = "curl" | "python" | "typescript";

export const SNIPPET_LANGS: ReadonlyArray<{ value: SnippetLang; label: string }> = [
  { value: "curl", label: "curl" },
  { value: "python", label: "Python" },
  { value: "typescript", label: "TypeScript" },
];

export type SnippetFacts = {
  /** Proxy root, e.g. http://127.0.0.1:8820 (no trailing slash). */
  baseURL: string;
  agentHeader: string;
  sessionHeader: string;
  /** Example agent name shown in the snippet. */
  agent?: string;
  /** The node wants the proxy client token: the base URL carries
   * /t/<token> (the token itself is never sent to the page). */
  clientAuth?: boolean;
};

/** The placeholder the snippet shows where the client token goes. */
export const CLIENT_TOKEN_PLACEHOLDER = "<token>";

/** The proxy root the snippet uses: the plain root, or the client-token
 * form http://host:port/t/<token> when the node wants client auth. */
export function snippetBase(f: SnippetFacts): string {
  const base = f.baseURL.replace(/\/+$/, "");
  return f.clientAuth ? `${base}/t/${CLIENT_TOKEN_PLACEHOLDER}` : base;
}

const EXAMPLE_AGENT = "my-agent";
const EXAMPLE_SESSION = "run-1";

/** The setup snippet for one language: Anthropic Messages for curl and
 * Python, OpenAI Chat Completions for TypeScript, so both provider shapes
 * appear once. Every snippet sets the base URL and both headers. */
export function ownAgentSnippet(lang: SnippetLang, f: SnippetFacts): string {
  const base = snippetBase(f);
  const agent = f.agent || EXAMPLE_AGENT;
  switch (lang) {
    case "python":
      return [
        "import anthropic",
        "",
        "client = anthropic.Anthropic(",
        `    base_url="${base}",`,
        "    default_headers={",
        `        "${f.agentHeader}": "${agent}",`,
        `        "${f.sessionHeader}": "${EXAMPLE_SESSION}",  # optional`,
        "    },",
        ")",
        "msg = client.messages.create(",
        '    model="claude-sonnet-4-5",',
        "    max_tokens=256,",
        '    messages=[{"role": "user", "content": "hello"}],',
        ")",
      ].join("\n");
    case "typescript":
      return [
        'import OpenAI from "openai";',
        "",
        "const client = new OpenAI({",
        `  baseURL: "${base}/v1",`,
        "  defaultHeaders: {",
        `    "${f.agentHeader}": "${agent}",`,
        `    "${f.sessionHeader}": "${EXAMPLE_SESSION}", // optional`,
        "  },",
        "});",
        "const res = await client.chat.completions.create({",
        '  model: "gpt-4o",',
        '  messages: [{ role: "user", content: "hello" }],',
        "});",
      ].join("\n");
    default:
      return [
        `curl ${base}/v1/messages \\`,
        '  -H "x-api-key: $ANTHROPIC_API_KEY" \\',
        '  -H "anthropic-version: 2023-06-01" \\',
        '  -H "content-type: application/json" \\',
        `  -H "${f.agentHeader}: ${agent}" \\`,
        `  -H "${f.sessionHeader}: ${EXAMPLE_SESSION}" \\`,
        `  -d '{"model":"claude-sonnet-4-5","max_tokens":256,"messages":[{"role":"user","content":"hello"}]}'`,
      ].join("\n");
  }
}

/** The agent name a stored surface_host carries ("agent:<name>"), or "". */
export function agentFromSurfaceHost(host: string | null | undefined): string {
  if (!host || !host.startsWith("agent:")) return "";
  return host.slice("agent:".length);
}

/** The Own agents view's source label: which capture path saw the agent
 * (store.OwnAgentSummary.Via: "proxy", "otlp" or "proxy+otlp"). It is the
 * only thing the view shows differently for span-sourced agents. An
 * unknown or missing value (an older daemon) reads as the proxy, the one
 * path that existed before spans. */
export function viaLabel(via: string | null | undefined): string {
  switch (via) {
    case "otlp":
      return "OTLP spans";
    case "proxy+otlp":
      return "proxy + OTLP spans";
    default:
      return "proxy";
  }
}
