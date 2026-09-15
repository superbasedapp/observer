// Tool registry — color + label + provider class for every AI tool
// the observer can capture. Mirrors `design/tokens.css` --tool-*
// custom properties and the brief's tool-identity-everywhere rule.

export type ToolKey =
  | "claude-code"
  | "codex"
  | "cursor"
  | "cline"
  | "cline-cli"
  | "copilot"
  | "copilot-cli"
  | "cowork"
  | "antigravity"
  | "antigravity-cli"
  | "opencode"
  | "openclaw"
  | "pi"
  | "gemini"
  | "gemini-cli"
  | "hermes"
  | "kilo-code"
  | "kilo-code-cli"
  | "qwen-code"
  | "kiro-cli"
  | "crush"
  | "kimi-code"
  | "grok"
  | "devin"
  | "aider"
  | "qoder"
  | "goose"
  | "droid"
  | "open-interpreter"
  | "command-code"
  | "zcode"
  | "mistral-code"
  | "freebuff"
  // Browser-chatbot rail (Phase 2) — captured by the opt-in MV3 browser
  // extension, NOT coding CLIs. Tokens are ALWAYS estimated.
  | "chatgpt-web"
  | "claude-web"
  | "perplexity-web"
  | "gemini-web"
  | "copilot-web";

export type ToolMeta = {
  key: ToolKey | string;
  label: string;
  // CSS variable reference — components apply this via inline style
  // so theme switches stay automatic.
  colorVar: string;
  provider: "anthropic" | "openai" | "google" | "github" | "agnostic";
  // browser marks a *-web browser-chatbot rail: tokens/cost are ALWAYS
  // estimates (no target UI returns authoritative counts), so the dashboard
  // MUST render an "est." label on its token/cost figures (§9 honesty rule).
  browser?: boolean;
};

const TOOLS: Record<string, ToolMeta> = {
  "claude-code": {
    key: "claude-code",
    label: "Claude Code",
    colorVar: "var(--tool-claude-code)",
    provider: "anthropic",
  },
  codex: {
    key: "codex",
    label: "Codex",
    colorVar: "var(--tool-codex)",
    provider: "openai",
  },
  cursor: {
    key: "cursor",
    label: "Cursor",
    colorVar: "var(--tool-cursor)",
    provider: "anthropic",
  },
  cline: {
    key: "cline",
    label: "Cline",
    colorVar: "var(--tool-cline)",
    provider: "anthropic",
  },
  copilot: {
    key: "copilot",
    label: "Copilot",
    colorVar: "var(--tool-copilot)",
    provider: "github",
  },
  "copilot-cli": {
    key: "copilot-cli",
    label: "Copilot CLI",
    colorVar: "var(--tool-copilot-cli)",
    provider: "github",
  },
  cowork: {
    key: "cowork",
    label: "Cowork",
    colorVar: "var(--tool-cowork)",
    provider: "anthropic",
  },
  antigravity: {
    key: "antigravity",
    label: "Antigravity",
    colorVar: "var(--tool-antigravity)",
    provider: "google",
  },
  opencode: {
    key: "opencode",
    label: "OpenCode",
    colorVar: "var(--tool-opencode)",
    provider: "agnostic",
  },
  openclaw: {
    key: "openclaw",
    label: "OpenClaw",
    colorVar: "var(--tool-openclaw)",
    provider: "anthropic",
  },
  pi: {
    key: "pi",
    label: "Pi",
    colorVar: "var(--tool-pi)",
    provider: "anthropic",
  },
  gemini: {
    key: "gemini",
    label: "Gemini",
    colorVar: "var(--tool-gemini)",
    provider: "google",
  },
  "gemini-cli": {
    key: "gemini-cli",
    label: "Gemini CLI",
    colorVar: "var(--tool-gemini)",
    provider: "google",
  },
  "cline-cli": {
    key: "cline-cli",
    label: "Cline CLI",
    colorVar: "var(--tool-cline-cli)",
    provider: "anthropic",
  },
  "antigravity-cli": {
    key: "antigravity-cli",
    label: "Antigravity CLI",
    // Same vendor + product family — shares antigravity's identity
    // color (the gemini/gemini-cli precedent).
    colorVar: "var(--tool-antigravity)",
    provider: "google",
  },
  hermes: {
    key: "hermes",
    label: "Hermes",
    colorVar: "var(--tool-hermes)",
    provider: "agnostic",
  },
  "kilo-code": {
    key: "kilo-code",
    label: "Kilo Code",
    colorVar: "var(--tool-kilo-code)",
    provider: "agnostic",
  },
  "kilo-code-cli": {
    key: "kilo-code-cli",
    label: "Kilo CLI",
    // One product family, one identity color (gemini-cli precedent).
    colorVar: "var(--tool-kilo-code)",
    provider: "agnostic",
  },
  // 2026-07 adapter wave. Per-turn providers are operator-configured
  // (openai-compat multi-backend observed live), so provider stays
  // "agnostic" where no single backend is true.
  "qwen-code": {
    key: "qwen-code",
    label: "Qwen Code",
    colorVar: "var(--tool-qwen-code)",
    provider: "agnostic",
  },
  "kiro-cli": {
    key: "kiro-cli",
    label: "Kiro CLI",
    colorVar: "var(--tool-kiro-cli)",
    provider: "agnostic",
  },
  crush: {
    key: "crush",
    label: "Crush",
    colorVar: "var(--tool-crush)",
    provider: "agnostic",
  },
  "kimi-code": {
    key: "kimi-code",
    label: "Kimi Code",
    colorVar: "var(--tool-kimi-code)",
    provider: "agnostic",
  },
  grok: {
    key: "grok",
    label: "Grok",
    // Deliberately neutral — xAI's brand is black/white; identity is
    // never color-alone (labels/legends everywhere).
    colorVar: "var(--tool-grok)",
    provider: "agnostic",
  },
  devin: {
    key: "devin",
    label: "Devin",
    colorVar: "var(--tool-devin)",
    provider: "agnostic",
  },
  aider: {
    key: "aider",
    label: "Aider",
    colorVar: "var(--tool-aider)",
    provider: "agnostic",
  },
  qoder: {
    key: "qoder",
    label: "Qoder",
    colorVar: "var(--tool-qoder)",
    provider: "agnostic",
  },
  goose: {
    key: "goose",
    label: "goose",
    colorVar: "var(--tool-goose)",
    provider: "agnostic",
  },
  // 2026-07-29 wave. All three are BYOK/multi-backend or closed-gateway
  // products with no single true upstream vendor, so provider stays
  // "agnostic" — the honest value (see the wave-2 note above).
  droid: {
    key: "droid",
    label: "droid",
    colorVar: "var(--tool-droid)",
    provider: "agnostic",
  },
  "open-interpreter": {
    key: "open-interpreter",
    label: "Open Interpreter",
    colorVar: "var(--tool-open-interpreter)",
    provider: "agnostic",
  },
  "command-code": {
    key: "command-code",
    label: "Command Code",
    colorVar: "var(--tool-command-code)",
    provider: "agnostic",
  },
  // 2026-08 wave. zcode (Z.AI's OpenCode fork) and mistral-code (Mistral's
  // `vibe` CLI) each authenticate to their own vendor's backend, but
  // neither Z.AI nor Mistral has a slot in the provider union above, so
  // both stay "agnostic" (the devin/kimi-code precedent — a single true
  // vendor whose name isn't one of the five modeled providers). freebuff
  // (CodebuffAI) is the same shape.
  zcode: {
    key: "zcode",
    label: "zcode",
    colorVar: "var(--tool-zcode)",
    provider: "agnostic",
  },
  "mistral-code": {
    key: "mistral-code",
    label: "Mistral Code",
    colorVar: "var(--tool-mistral-code)",
    provider: "agnostic",
  },
  freebuff: {
    key: "freebuff",
    label: "Freebuff",
    colorVar: "var(--tool-freebuff)",
    provider: "agnostic",
  },
  // Browser-chatbot rail (Phase 2). provider names the vendor whose web app
  // the extension observes; browser:true forces the mandatory "est." label
  // on every token/cost figure (§9).
  "chatgpt-web": {
    key: "chatgpt-web",
    label: "ChatGPT (web)",
    colorVar: "var(--tool-chatgpt-web)",
    provider: "openai",
    browser: true,
  },
  "claude-web": {
    key: "claude-web",
    label: "Claude (web)",
    colorVar: "var(--tool-claude-web)",
    provider: "anthropic",
    browser: true,
  },
  "perplexity-web": {
    key: "perplexity-web",
    label: "Perplexity (web)",
    colorVar: "var(--tool-perplexity-web)",
    provider: "agnostic",
    browser: true,
  },
  "gemini-web": {
    key: "gemini-web",
    label: "Gemini (web)",
    colorVar: "var(--tool-gemini-web)",
    provider: "google",
    browser: true,
  },
  "copilot-web": {
    key: "copilot-web",
    label: "Copilot (web)",
    colorVar: "var(--tool-copilot-web)",
    provider: "github",
    browser: true,
  },
};

// BROWSER_TOOLS is the *-web rail set — the "Browser chatbots" dashboard
// grouping. Ordered for stable rendering.
export const BROWSER_TOOLS: string[] = [
  "chatgpt-web",
  "claude-web",
  "perplexity-web",
  "gemini-web",
  "copilot-web",
];

// isBrowserTool reports whether a tool key is a browser-chatbot rail (so the
// caller renders the mandatory estimated-token "est." label). Registry-driven
// off the browser flag, never a name substring test.
export function isBrowserTool(key: string | null | undefined): boolean {
  if (!key) return false;
  return TOOLS[key]?.browser === true;
}

const FALLBACK: ToolMeta = {
  key: "other",
  label: "Other",
  colorVar: "var(--tool-other)",
  provider: "agnostic",
};

export function toolMeta(key: string | null | undefined): ToolMeta {
  if (!key) return FALLBACK;
  return TOOLS[key] ?? { ...FALLBACK, key, label: key };
}
