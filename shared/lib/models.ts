// Model registry — provider classification + color inference from the model
// identifier string, both derived from modelFamily(). Used by ModelId /
// ModelMark / ModelDot and any surface that wants a family-tinted swatch next
// to a model name (Cost ModelTable, Analysis Daily-spend legend).

import { modelFamily, type ModelFamilyId } from "./modelFamilies";

export type ModelProvider =
  | "anthropic"
  | "openai"
  | "google"
  | "synthetic"
  | "other";

// One family table is the single source of model colour (2026-09-28): the
// ordered modelFamily() matcher (./modelFamilies.ts, generated) resolves the
// family, and these two rows map a family to its provider class and colour.
// A family with no row here (and an unmatched id) is "other" / --tool-other:
// unknown stays unknown, never a guessed vendor.
const FAMILY_PROVIDER: Partial<Record<ModelFamilyId, ModelProvider>> = {
  synthetic: "synthetic",
  claude: "anthropic",
  openai: "openai",
  "gpt-oss": "openai",
  gemini: "google",
  gemma: "google",
};

// Family -> colour. Reuses the --tool-* token of the vendor's own coding tool
// where there is one, so a model and its maker's tool read as one hue.
const FAMILY_COLOR: Partial<Record<ModelFamilyId, string>> = {
  synthetic: "var(--fg-4)",
  claude: "var(--tool-claude-code)",
  openai: "var(--tool-codex)",
  "gpt-oss": "var(--tool-codex)",
  gemini: "var(--tool-gemini)",
  gemma: "var(--tool-gemini)",
  grok: "var(--tool-grok)",
  "meta-ai": "var(--tool-muse)",
  llama: "var(--tool-muse)",
  mistral: "var(--tool-mistral-code)",
  deepseek: "var(--tool-deepseek)",
  qwen: "var(--tool-qwen-code)",
  kimi: "var(--tool-kimi-code)",
  glm: "var(--tool-zcode)",
  sonar: "var(--tool-perplexity-web)",
  poolside: "var(--tool-poolside)",
  cursor: "var(--tool-cursor)",
  windsurf: "var(--tool-devin)",
  microsoft: "var(--tool-copilot)",
  auto: "var(--fg-3)",
};

// modelProvider — the provider class of a model id, derived from its family.
// "synthetic" covers the proxy-injected placeholder used for JSONL-only rows.
export function modelProvider(id: string | null | undefined): ModelProvider {
  const fam = modelFamily(id);
  return (fam && FAMILY_PROVIDER[fam.id]) || "other";
}

// modelColorVar — CSS variable reference for the model's family colour.
export function modelColorVar(id: string | null | undefined): string {
  const fam = modelFamily(id);
  return (fam && FAMILY_COLOR[fam.id]) || "var(--tool-other)";
}

// modelSeriesColors — chart colours for a list of model ids (in display
// order). Each model takes its FAMILY colour; the 2nd, 3rd, ... model of the
// same family is a lighter / darker mix of it, so a chart with three Claude
// models reads as three shades of the Claude hue instead of three unrelated
// rank colours. Pure: same input order, same colours.
const SHADE_STEPS = ["", "var(--fg-0) 28%", "var(--bg-0) 32%", "var(--fg-0) 50%", "var(--bg-0) 55%"];
export function modelSeriesColors(ids: ReadonlyArray<string>): string[] {
  const seen = new Map<string, number>();
  return ids.map((id) => {
    const base = modelColorVar(id);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    const step = SHADE_STEPS[n % SHADE_STEPS.length];
    return step ? `color-mix(in srgb, ${base}, ${step})` : base;
  });
}

// shortModel — trim provider/vendor prefix that the proxy stores
// verbatim ("anthropic/claude-opus-4-7" → "claude-opus-4-7") so
// model strings fit common column widths.
export function shortModel(id: string | null | undefined): string {
  if (!id) return "";
  const i = id.lastIndexOf("/");
  return i >= 0 ? id.slice(i + 1) : id;
}

// formatModelId — shared model-id display hygiene (V14/WS1.2; moved from
// web2/src/lib/models.ts). A raw model id from the wire can be a leading-`~`
// provisional resolution, or one of a few placeholder strings meaning "we
// don't actually know the model"; this normalizes both into an honest,
// consistent shape instead of leaking the raw string into every
// dropdown/table.
export interface FormattedModelId {
  // Display label: the placeholder copy when !known, the (tilde-stripped)
  // model id otherwise.
  label: string;
  // True when the id came in with a leading "~" (resolved from partial data).
  provisional: boolean;
  // False for empty/placeholder ids: render label muted, no model chrome.
  known: boolean;
}

const PLACEHOLDER_MODEL_IDS = new Set(["", "(none)", "(unknown)", "none", "unknown", "null", "-"]);

export function formatModelId(raw: string | null | undefined): FormattedModelId {
  const trimmed = (raw ?? "").trim();
  if (!trimmed || PLACEHOLDER_MODEL_IDS.has(trimmed.toLowerCase())) {
    return { label: "No model reported", provisional: false, known: false };
  }
  if (trimmed.startsWith("~") && trimmed.length > 1) {
    return { label: trimmed.slice(1), provisional: true, known: true };
  }
  return { label: trimmed, provisional: false, known: true };
}
