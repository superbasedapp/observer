// Model registry — provider classification + color inference from
// the model identifier string. Used by the Sessions Models column +
// any other surface that wants a provider-tinted swatch next to a
// model name (Cost ModelTable, Analysis Daily-spend legend).

export type ModelProvider =
  | "anthropic"
  | "openai"
  | "google"
  | "synthetic"
  | "other";

// modelProvider — infer the provider from a model id. The proxy
// stores identifiers verbatim, so we normalize: strip a leading
// vendor segment (e.g. `anthropic/claude-opus-4-7` → `claude-opus-4-7`)
// then match on family substrings. "synthetic" covers the
// proxy-injected placeholder used for JSONL-only rows.
export function modelProvider(id: string | null | undefined): ModelProvider {
  if (!id) return "other";
  const s = id.toLowerCase();
  const i = s.lastIndexOf("/");
  const tail = i >= 0 ? s.slice(i + 1) : s;
  if (tail.startsWith("<synthetic")) return "synthetic";
  if (
    tail.includes("claude") ||
    tail.includes("opus") ||
    tail.includes("sonnet") ||
    tail.includes("haiku")
  ) {
    return "anthropic";
  }
  if (
    tail.startsWith("gpt") ||
    tail.startsWith("o1") ||
    tail.startsWith("o3") ||
    tail.startsWith("o4") ||
    tail.includes("codex")
  ) {
    return "openai";
  }
  if (tail.startsWith("gemini")) return "google";
  return "other";
}

// modelColorVar — CSS variable reference for the inferred provider's
// brand color. Mirrors the tool-* color tokens.
export function modelColorVar(id: string | null | undefined): string {
  switch (modelProvider(id)) {
    case "anthropic":
      return "var(--tool-claude-code)";
    case "openai":
      return "var(--tool-codex)";
    case "google":
      return "var(--tool-gemini)";
    case "synthetic":
      return "var(--fg-4)";
    default:
      return "var(--tool-other)";
  }
}

// shortModel — trim provider/vendor prefix that the proxy stores
// verbatim ("anthropic/claude-opus-4-7" → "claude-opus-4-7") so
// model strings fit common column widths.
export function shortModel(id: string | null | undefined): string {
  if (!id) return "";
  const i = id.lastIndexOf("/");
  return i >= 0 ? id.slice(i + 1) : id;
}
